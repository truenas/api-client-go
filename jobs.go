// SPDX-License-Identifier: LGPL-3.0-or-later

package truenas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// JobCallback is called with the job's latest state every time an update is
// received.
type JobCallback func(fields *JobFields)

// jobState tracks server-side updates for one job (ports _JobDict).
type jobState struct {
	id int64

	mu       sync.Mutex
	fields   JobFields
	haveInfo bool
	callback JobCallback
	failure  error // connection-level failure, if any

	ready     chan struct{}
	readyOnce sync.Once
}

func (j *jobState) update(fields *JobFields, mtype string) {
	j.mu.Lock()
	j.fields = *fields
	j.haveInfo = true
	callback := j.callback
	j.mu.Unlock()

	if callback != nil {
		go callback(fields)
	}
	if mtype == "CHANGED" {
		switch fields.State {
		case "SUCCESS", "FAILED", "ABORTED":
			j.readyOnce.Do(func() { close(j.ready) })
		}
	}
}

func (j *jobState) fail(err error) {
	j.mu.Lock()
	j.failure = err
	j.mu.Unlock()
	j.readyOnce.Do(func() { close(j.ready) })
}

// Job is a long-running background process on the server initiated by an API
// call.
type Job struct {
	client *Client
	state  *jobState
}

// ID returns the server-assigned job identifier.
func (j *Job) ID() int64 {
	return j.state.id
}

// OnUpdate registers cb to be called (in its own goroutine) with the job's
// state every time an update is received. Call it before Result to observe
// progress. If updates already arrived before registration, cb is immediately
// called once with the latest state.
func (j *Job) OnUpdate(cb JobCallback) {
	j.state.mu.Lock()
	j.state.callback = cb
	replay := j.state.haveInfo
	fields := j.state.fields
	j.state.mu.Unlock()
	if replay {
		go cb(&fields)
	}
}

// Result waits for the job to finish and returns its result decoded via
// ejson (ports Job.result).
func (j *Job) Result(ctx context.Context) (any, error) {
	select {
	case <-j.state.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	c := j.client
	c.mu.Lock()
	delete(c.jobs, j.state.id)
	c.mu.Unlock()

	j.state.mu.Lock()
	defer j.state.mu.Unlock()

	if !j.state.haveInfo {
		if j.state.failure != nil {
			return nil, j.state.failure
		}
		return nil, &ClientError{Reason: "No job event was received."}
	}
	fields := &j.state.fields

	if fields.State == "SUCCESS" {
		return decodeResult(fields.Result)
	}

	if fields.ExcInfo != nil {
		if fields.ExcInfo.Type == "VALIDATION" {
			return nil, &ValidationErrors{Errors: fields.ExcInfo.Extra}
		}
		repr := fields.ExcInfo.Repr
		if repr == "" {
			lines := strings.Split(strings.TrimRight(fields.Exception, "\n"), "\n")
			repr = lines[len(lines)-1]
		}
		return nil, &ClientError{
			Reason: fields.Error,
			Trace: &Traceback{
				Class:     fields.ExcInfo.Type,
				Frames:    []map[string]any{},
				Formatted: fields.Exception,
				Repr:      repr,
			},
			Extra: fields.ExcInfo.Extra,
		}
	}

	if j.state.failure != nil {
		return nil, j.state.failure
	}
	// Aborted or interrupted jobs have no exc_info to build a trace from.
	if fields.Error != "" {
		return nil, &ClientError{Reason: fields.Error}
	}
	return nil, &ClientError{
		Reason: fmt.Sprintf("Job %d did not succeed (state=%q)", j.state.id, fields.State),
	}
}

// StartJob calls a job method and returns a Job handle for tracking progress
// and awaiting the result (ports call(job='RETURN')). ctx bounds only the
// initial call, not the job itself.
func (c *Client) StartJob(ctx context.Context, method string, params ...any) (*Job, error) {
	c.mu.Lock()
	newStyle := c.newStyleJobs
	c.mu.Unlock()
	// With new-style jobs an authentication failure subscribing is not fatal:
	// results still arrive through the normal JSON-RPC protocol.
	if err := c.watchJobs(ctx, newStyle); err != nil {
		return nil, err
	}
	raw, err := c.callRaw(ctx, method, params)
	if err != nil {
		return nil, err
	}
	var jobID int64
	if err := unmarshalTo(raw, &jobID); err != nil {
		return nil, &ClientError{Reason: fmt.Sprintf("%s did not return a job ID: %v", method, err)}
	}
	return &Job{client: c, state: c.jobState(jobID)}, nil
}

// CallJob calls a job method and waits for the job to complete, returning its
// result (ports call(job=True)). ctx bounds the entire wait.
func (c *Client) CallJob(ctx context.Context, method string, params ...any) (any, error) {
	job, err := c.StartJob(ctx, method, params...)
	if err != nil {
		return nil, err
	}
	return job.Result(ctx)
}

// jobState returns the tracked state for jobID, creating a stub if no event
// has been received yet (mirrors the Python defaultdict + Event dance that
// avoids racing job events against Job creation).
func (c *Client) jobState(jobID int64) *jobState {
	c.mu.Lock()
	defer c.mu.Unlock()
	job := c.jobs[jobID]
	if job == nil {
		job = &jobState{id: jobID, ready: make(chan struct{})}
		c.jobs[jobID] = job
	}
	return job
}

// jobsEvent processes a core.get_jobs collection update (ports
// _jobs_callback).
func (c *Client) jobsEvent(mtype string, params *CollectionUpdateParams) {
	var fields JobFields
	if err := json.Unmarshal(params.Fields, &fields); err != nil {
		c.log.Error("truenas: invalid core.get_jobs fields", "error", err)
		return
	}
	jobID, err := fields.ID.Int64()
	if err != nil {
		return
	}
	c.jobState(jobID).update(&fields, mtype)
}

// maybeWatchJobs subscribes to core.get_jobs before a plain call when
// new-style jobs are active: any method call can be a job then, and a failed
// silent subscribe is not an error.
func (c *Client) maybeWatchJobs() {
	c.mu.Lock()
	watching, newStyle := c.jobsWatching, c.newStyleJobs
	c.mu.Unlock()
	if watching || !newStyle {
		return
	}
	if err := c.watchJobs(context.Background(), true); err != nil {
		c.log.Error("truenas: failed to subscribe to core.get_jobs", "error", err)
	}
}

// watchJobs ensures the client is subscribed to job updates (ports
// _jobs_subscribe). When silent, an ENOTAUTHENTICATED failure is swallowed
// (core.subscribe before authentication triggers it).
func (c *Client) watchJobs(ctx context.Context, silent bool) error {
	c.mu.Lock()
	if c.jobsWatching {
		c.mu.Unlock()
		return nil
	}
	c.jobsWatching = true
	c.mu.Unlock()

	if _, err := c.subscribe(ctx, "core.get_jobs", c.jobsEvent, true); err != nil {
		c.mu.Lock()
		c.jobsWatching = false
		c.mu.Unlock()

		var clientErr *ClientError
		if silent && errors.As(err, &clientErr) && clientErr.Errno == ENotAuthenticated {
			return nil
		}
		return err
	}
	return nil
}

func unmarshalTo(raw json.RawMessage, v any) error {
	return json.Unmarshal(raw, v)
}
