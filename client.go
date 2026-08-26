// SPDX-License-Identifier: LGPL-3.0-or-later

package truenas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/truenas/api-client-go/ejson"
)

// DefaultCallTimeout is the default number of seconds to allow an API call
// before timing out, overridable with the CALL_TIMEOUT environment variable
// (like the Python client).
var DefaultCallTimeout = defaultCallTimeout()

func defaultCallTimeout() time.Duration {
	if v := os.Getenv("CALL_TIMEOUT"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	return 60 * time.Second
}

// Options configures a Client. The zero value is a valid default
// configuration.
type Options struct {
	// ReservedPorts binds the connection to a local port in the privileged
	// 600-1024 range (requires root; ws:// URIs only).
	ReservedPorts bool
	// PrivateMethods allows calling private API methods.
	PrivateMethods bool
	// CallTimeout is the default time allowed per API call before
	// CallTimeoutError. Zero means DefaultCallTimeout.
	CallTimeout time.Duration
	// InsecureSkipVerify disables SSL certificate verification for wss://
	// connections.
	InsecureSkipVerify bool
	// Logger receives client diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
}

// call tracks a single in-flight request-response pair (ports Call from the
// Python client).
type call struct {
	id       string
	method   string
	returned chan struct{}
	result   json.RawMessage
	err      error
}

// Client interfaces with the TrueNAS middleware API over a JSON-RPC 2.0
// websocket connection (ports JSONRPCClient; the pre-25.04 legacy protocol is
// not supported).
type Client struct {
	conn *websocket.Conn
	url  string
	opts Options
	log  *slog.Logger

	writeMu sync.Mutex // gorilla/websocket allows one concurrent writer

	mu             sync.Mutex
	calls          map[string]*call
	jobs           map[int64]*jobState
	jobsWatching   bool
	newStyleJobs   bool
	subscriptions  map[string][]*Subscription
	setOptionsCall *call
	closeErr       *ClientError // set once the connection is gone

	connected chan struct{} // closed when the core.set_options handshake completes
	closed    chan struct{} // closed when the reader goroutine exits
}

// Connect establishes a connection to the TrueNAS middleware API.
//
// uri may be a websocket URL such as "ws://example.com/api/current" or
// "wss://example.com/api/current", a "ws+unix://" path, or empty to connect
// to the local middlewared UNIX socket. opts may be nil for defaults.
func Connect(uri string, opts *Options) (*Client, error) {
	return ConnectContext(context.Background(), uri, opts)
}

// ConnectContext is Connect with a caller-supplied context bounding the
// connection attempt.
func ConnectContext(ctx context.Context, uri string, opts *Options) (*Client, error) {
	if uri == "" {
		uri = UnixSocketPrefix + MiddlewareRunDir + "/middlewared.sock"
	}

	var o Options
	if opts != nil {
		o = *opts
	}
	if o.CallTimeout == 0 {
		o.CallTimeout = DefaultCallTimeout
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}

	conn, err := dialWebsocket(ctx, uri, o.ReservedPorts, !o.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}

	c := &Client{
		conn:          conn,
		url:           uri,
		opts:          o,
		log:           o.Logger,
		calls:         make(map[string]*call),
		jobs:          make(map[int64]*jobState),
		subscriptions: make(map[string][]*Subscription),
		connected:     make(chan struct{}),
		closed:        make(chan struct{}),
	}

	// Configure how middlewared sends its responses. The response to this
	// call completes the connection handshake (ports on_open).
	setOptions := c.newCall("core.set_options")
	c.mu.Lock()
	c.setOptionsCall = setOptions
	c.mu.Unlock()
	if err := c.send(setOptions, []any{map[string]any{
		"legacy_jobs":     false,
		"private_methods": o.PrivateMethods,
	}}); err != nil {
		conn.Close()
		return nil, err
	}

	go c.readLoop()

	select {
	case <-c.connected:
	case <-time.After(30 * time.Second):
		conn.Close()
		return nil, &ClientError{Reason: "Failed connection handshake"}
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}

	c.mu.Lock()
	closeErr := c.closeErr
	c.mu.Unlock()
	if closeErr != nil {
		conn.Close()
		return nil, closeErr
	}
	return c, nil
}

// Close cleanly closes the connection to the server.
func (c *Client) Close() error {
	c.writeMu.Lock()
	c.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	c.writeMu.Unlock()
	err := c.conn.Close()
	// Wait for the reader goroutine to finish broadcasting.
	select {
	case <-c.closed:
	case <-time.After(time.Second):
	}
	return err
}

func (c *Client) newCall(method string) *call {
	return &call{
		id:       uuid.NewString(),
		method:   method,
		returned: make(chan struct{}),
	}
}

// send serializes and writes one JSON-RPC request.
func (c *Client) send(call *call, params []any) error {
	if params == nil {
		params = []any{}
	}
	data, err := ejson.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  call.method,
		"id":      call.id,
		"params":  params,
	})
	if err != nil {
		return fmt.Errorf("truenas: encoding %s params: %w", call.method, err)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		// Happens when the other node on HA is rebooted, for example, while
		// there are calls in flight.
		return &ClientError{Reason: "Unexpected closure of remote connection", Errno: errnoECONNABORTED}
	}
	return nil
}

// Call sends an API call and waits for its result, decoded via ejson.
// The default call timeout applies.
func (c *Client) Call(method string, params ...any) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.opts.CallTimeout)
	defer cancel()
	return c.CallContext(ctx, method, params...)
}

// CallContext sends an API call and waits for its result, decoded via ejson.
// The context bounds the wait; use CallRawContext for an undecoded result.
func (c *Client) CallContext(ctx context.Context, method string, params ...any) (any, error) {
	raw, err := c.CallRawContext(ctx, method, params...)
	if err != nil {
		return nil, err
	}
	return decodeResult(raw)
}

// CallRawContext sends an API call and returns the raw JSON result.
func (c *Client) CallRawContext(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	c.maybeWatchJobs()
	return c.callRaw(ctx, method, params)
}

func (c *Client) callRaw(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	call := c.newCall(method)
	c.registerCall(call)
	defer c.unregisterCall(call)

	if err := c.send(call, params); err != nil {
		return nil, err
	}
	return c.wait(ctx, call)
}

func (c *Client) wait(ctx context.Context, call *call) (json.RawMessage, error) {
	select {
	case <-call.returned:
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &CallTimeoutError{}
		}
		return nil, ctx.Err()
	}
	if call.err != nil {
		return nil, call.err
	}
	return call.result, nil
}

// Ping calls core.ping to verify the connection to the server.
func (c *Client) Ping() (string, error) {
	return c.PingContext(context.Background())
}

// PingContext is Ping bounded by ctx (default limit: 10 seconds, matching
// the Python client).
func (c *Client) PingContext(ctx context.Context) (string, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	res, err := c.CallContext(ctx, "core.ping")
	if err != nil {
		return "", err
	}
	s, _ := res.(string)
	return s, nil
}

func decodeResult(raw json.RawMessage) (any, error) {
	if raw == nil {
		return nil, nil
	}
	return ejson.Unmarshal(raw)
}

func (c *Client) registerCall(call *call) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeErr != nil {
		// The connection is already gone; fail the call immediately instead
		// of waiting for a response that cannot arrive.
		call.err = c.closeErr
		close(call.returned)
		return
	}
	c.calls[call.id] = call
}

func (c *Client) unregisterCall(call *call) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.calls, call.id)
}

// readLoop receives and dispatches messages until the connection closes
// (ports WSClient callbacks plus JSONRPCClient._recv).
func (c *Client) readLoop() {
	var closeReason string
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			closeReason = err.Error()
			break
		}
		var msg message
		if err := json.Unmarshal(data, &msg); err != nil {
			c.log.Error("truenas: received invalid JSON-RPC message", "error", err)
			continue
		}
		c.dispatch(&msg)
	}
	c.onClose(closeReason)
}

func (c *Client) dispatch(msg *message) {
	switch {
	case msg.Method != "":
		c.dispatchNotification(msg)
	case msg.ID != nil || msg.Result != nil || msg.Error != nil:
		c.dispatchResponse(msg)
	default:
		c.log.Error("truenas: received unknown message")
	}
}

func (c *Client) dispatchNotification(msg *message) {
	switch msg.Method {
	case "collection_update":
		var params CollectionUpdateParams
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			c.log.Error("truenas: invalid collection_update params", "error", err)
			return
		}
		c.handleCollectionUpdate(&params)
	case "notify_unsubscribed":
		var params NotifyUnsubscribedParams
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			c.log.Error("truenas: invalid notify_unsubscribed params", "error", err)
			return
		}
		c.handleUnsubscribed(&params)
	default:
		c.log.Error("truenas: received unknown notification", "method", msg.Method)
	}
}

func (c *Client) handleCollectionUpdate(params *CollectionUpdateParams) {
	c.mu.Lock()
	newStyleJobs := c.newStyleJobs
	c.mu.Unlock()

	if newStyleJobs && params.Collection == "core.get_jobs" &&
		(params.Msg == "added" || params.Msg == "changed") {
		// With new-style jobs, the method return value is not sent until the
		// job completes; the job ID arrives immediately via this update, so
		// resolve the originating call with the job ID as its result.
		var fields struct {
			MessageIDs []string `json:"message_ids"`
		}
		if err := json.Unmarshal(params.Fields, &fields); err == nil {
			for _, messageID := range fields.MessageIDs {
				c.mu.Lock()
				call := c.calls[messageID]
				if call != nil {
					delete(c.calls, call.id)
				}
				c.mu.Unlock()
				if call != nil {
					call.result = params.ID
					close(call.returned)
				}
			}
		}
	}

	c.dispatchEvent(params)
}

func (c *Client) dispatchResponse(msg *message) {
	if msg.ID == nil {
		if msg.Error != nil {
			err, _ := c.parseError(msg.Error)
			c.log.Error("truenas: received a global connection error", "error", err)
			c.broadcastError(&ClientError{Reason: err.Error(), Errno: errnoECONNABORTED})
		}
		return
	}

	c.mu.Lock()
	setOptions := c.setOptionsCall
	c.mu.Unlock()

	if setOptions != nil && *msg.ID == setOptions.id {
		c.finishHandshake(msg)
		return
	}

	c.mu.Lock()
	call := c.calls[*msg.ID]
	if call != nil {
		delete(c.calls, call.id)
	}
	newStyleJobs := c.newStyleJobs
	c.mu.Unlock()

	if call != nil {
		if msg.Error != nil {
			call.err, _ = c.parseError(msg.Error)
		} else {
			call.result = msg.Result
		}
		close(call.returned)
		return
	}

	// With new-style jobs the real response of a job call arrives after the
	// call was already resolved with the job ID; silently ignore it.
	if !newStyleJobs {
		if msg.Error != nil {
			err, _ := c.parseError(msg.Error)
			c.log.Error("truenas: error response for non-registered method call",
				"id", *msg.ID, "error", err)
		} else {
			c.log.Error("truenas: response for non-registered method call", "id", *msg.ID)
		}
	}
}

// finishHandshake processes the core.set_options response that completes the
// connection handshake.
func (c *Client) finishHandshake(msg *message) {
	if msg.Result != nil {
		var result struct {
			LegacyJobs *bool `json:"legacy_jobs"`
		}
		if err := json.Unmarshal(msg.Result, &result); err == nil && result.LegacyJobs != nil {
			c.mu.Lock()
			c.newStyleJobs = !*result.LegacyJobs
			c.mu.Unlock()
		}
	}
	if msg.Error != nil {
		err, _ := c.parseError(msg.Error)
		c.log.Error("truenas: error setting client options", "error", err)
	}
	c.mu.Lock()
	c.setOptionsCall = nil
	c.mu.Unlock()
	close(c.connected)
}

// parseError converts a JSON-RPC error object into a Go error (ports
// _parse_error_and_unpickle_exception, minus pickle support). The second
// return value is the parsed TrueNAS error data, if any.
func (c *Client) parseError(obj *errorObj) (error, *TruenasError) {
	code := JSONRPCErrorCode(obj.Code)
	switch code {
	case InvalidParams:
		var data TruenasError
		if err := json.Unmarshal(obj.Data, &data); err == nil {
			return &ValidationErrors{Errors: data.Extra}, &data
		}
	case TruenasCallError:
		var data TruenasError
		if err := json.Unmarshal(obj.Data, &data); err == nil {
			return &ClientError{
				Reason: data.Reason,
				Errno:  data.Error,
				Trace:  data.Trace,
				Extra:  data.Extra,
			}, &data
		}
	case MethodNotFound:
		msg := obj.Message
		if msg == "" {
			msg = code.String()
		}
		return &ClientError{Reason: msg, Errno: ENoMethod}, nil
	}
	msg := obj.Message
	if msg == "" {
		msg = code.String()
	}
	return &ClientError{Reason: msg}, nil
}

// onClose ends all unanswered calls and unreturned jobs with an error after
// the connection is gone (ports on_close plus _broadcast_error).
func (c *Client) onClose(reason string) {
	err := &ClientError{
		Reason: fmt.Sprintf("WebSocket connection closed: %s", reason),
		Errno:  errnoECONNABORTED,
	}
	c.broadcastError(err)
	close(c.closed)
}

func (c *Client) broadcastError(err *ClientError) {
	c.mu.Lock()
	if c.closeErr == nil {
		c.closeErr = err
	}
	pending := make([]*call, 0, len(c.calls))
	for id, call := range c.calls {
		pending = append(pending, call)
		delete(c.calls, id)
	}
	setOptions := c.setOptionsCall
	c.setOptionsCall = nil
	jobs := make([]*jobState, 0, len(c.jobs))
	for _, job := range c.jobs {
		jobs = append(jobs, job)
	}
	c.mu.Unlock()

	for _, call := range pending {
		call.err = err
		close(call.returned)
	}
	if setOptions != nil {
		select {
		case <-c.connected:
		default:
			close(c.connected)
		}
	}
	for _, job := range jobs {
		job.fail(err)
	}
}
