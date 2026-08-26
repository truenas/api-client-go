// SPDX-License-Identifier: LGPL-3.0-or-later

package truenas

import (
	"context"
	"strings"
	"sync"
	"time"
)

// EventCallback is called for every event delivered to a subscription. mtype
// is the upper-cased update type ("ADDED", "CHANGED", "REMOVED", ...).
type EventCallback func(mtype string, params *CollectionUpdateParams)

// SubscribeOptions configures a subscription.
type SubscribeOptions struct {
	// Sync runs the callback on the client's reader goroutine, blocking
	// message processing until it returns. By default each callback
	// invocation runs in its own goroutine.
	Sync bool
}

// Subscription is an active event subscription.
type Subscription struct {
	// ID is the identifier assigned by core.subscribe.
	ID string

	name     string
	callback EventCallback
	sync     bool

	mu   sync.Mutex
	err  error
	done chan struct{}
}

// Done is closed when the server terminates the subscription
// (notify_unsubscribed) or the connection is lost.
func (s *Subscription) Done() <-chan struct{} {
	return s.done
}

// Err reports why the subscription ended, or nil if it ended cleanly or is
// still active.
func (s *Subscription) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Subscription) finish(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

// Subscribe subscribes to an event via core.subscribe and calls cb for every
// received event. name may be "*" to receive all collection updates. opts may
// be nil for defaults.
func (c *Client) Subscribe(name string, cb EventCallback, opts *SubscribeOptions) (*Subscription, error) {
	sync := opts != nil && opts.Sync
	return c.subscribe(context.Background(), name, cb, sync)
}

func (c *Client) subscribe(ctx context.Context, name string, cb EventCallback, sync bool) (*Subscription, error) {
	sub := &Subscription{
		name:     name,
		callback: cb,
		sync:     sync,
		done:     make(chan struct{}),
	}

	// Register before calling core.subscribe so events racing with the
	// subscribe response are not lost (same order as the Python client).
	c.mu.Lock()
	c.subscriptions[name] = append(c.subscriptions[name], sub)
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result, err := c.callRaw(ctx, "core.subscribe", []any{name})
	if err != nil {
		c.removeSubscription(sub)
		return nil, err
	}
	var id string
	if err := unmarshalTo(result, &id); err != nil {
		c.removeSubscription(sub)
		return nil, err
	}
	sub.ID = id
	return sub, nil
}

// Unsubscribe calls core.unsubscribe and removes the subscription.
func (c *Client) Unsubscribe(sub *Subscription) error {
	if _, err := c.Call("core.unsubscribe", sub.ID); err != nil {
		return err
	}
	c.removeSubscription(sub)
	return nil
}

func (c *Client) removeSubscription(sub *Subscription) {
	c.mu.Lock()
	defer c.mu.Unlock()
	subs := c.subscriptions[sub.name]
	for i, s := range subs {
		if s == sub {
			c.subscriptions[sub.name] = append(subs[:i:i], subs[i+1:]...)
			break
		}
	}
	if len(c.subscriptions[sub.name]) == 0 {
		delete(c.subscriptions, sub.name)
	}
}

// dispatchEvent delivers a collection_update to matching subscriptions.
func (c *Client) dispatchEvent(params *CollectionUpdateParams) {
	mtype := strings.ToUpper(params.Msg)

	c.mu.Lock()
	var targets []*Subscription
	targets = append(targets, c.subscriptions["*"]...)
	if params.Collection != "*" {
		targets = append(targets, c.subscriptions[params.Collection]...)
	}
	c.mu.Unlock()

	for _, sub := range targets {
		if sub.callback == nil {
			continue
		}
		if sub.sync {
			sub.callback(mtype, params)
		} else {
			go sub.callback(mtype, params)
		}
	}
}

// handleUnsubscribed marks all subscriptions of a collection as terminated.
func (c *Client) handleUnsubscribed(params *NotifyUnsubscribedParams) {
	c.mu.Lock()
	subs := append([]*Subscription(nil), c.subscriptions[params.Collection]...)
	c.mu.Unlock()

	var err error
	if params.Error != nil {
		if params.Error.Reason != "" {
			err = &ClientError{Reason: params.Error.Reason, Errno: params.Error.Error,
				Trace: params.Error.Trace, Extra: params.Error.Extra}
		} else {
			err = &ClientError{Reason: params.Error.Errname, Errno: params.Error.Error}
		}
	}
	for _, sub := range subs {
		sub.finish(err)
	}
}
