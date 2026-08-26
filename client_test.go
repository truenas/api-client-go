// SPDX-License-Identifier: LGPL-3.0-or-later

package truenas

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// serverConn is one fake middleware connection; helpers may be called from
// the handler (on the read loop) or other goroutines.
type serverConn struct {
	t  *testing.T
	mu sync.Mutex
	ws *websocket.Conn
}

func (s *serverConn) write(v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ws.WriteJSON(v); err != nil {
		s.t.Logf("server write: %v", err)
	}
}

func (s *serverConn) respond(id string, result any) {
	s.write(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (s *serverConn) respondError(id string, code int, message string, data any) {
	errObj := map[string]any{"code": code, "message": message}
	if data != nil {
		errObj["data"] = data
	}
	s.write(map[string]any{"jsonrpc": "2.0", "id": id, "error": errObj})
}

func (s *serverConn) notify(method string, params any) {
	s.write(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

type methodHandler func(s *serverConn, id string, params []any)

// newTestClient starts a fake middleware server and returns a connected
// client. core.set_options is answered automatically with legacyJobs.
func newTestClient(t *testing.T, legacyJobs bool, handlers map[string]methodHandler) (*Client, *serverConn) {
	t.Helper()
	connCh := make(chan *serverConn, 1)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		sc := &serverConn{t: t, ws: ws}
		connCh <- sc
		for {
			var msg struct {
				Method string `json:"method"`
				ID     string `json:"id"`
				Params []any  `json:"params"`
			}
			if err := ws.ReadJSON(&msg); err != nil {
				return
			}
			switch {
			case msg.Method == "core.set_options":
				sc.respond(msg.ID, map[string]any{"legacy_jobs": legacyJobs})
			case handlers[msg.Method] != nil:
				handlers[msg.Method](sc, msg.ID, msg.Params)
			default:
				sc.respondError(msg.ID, int(MethodNotFound), "Method does not exist", nil)
			}
		}
	}))
	t.Cleanup(srv.Close)

	uri := "ws" + strings.TrimPrefix(srv.URL, "http")
	c, err := Connect(uri, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c, <-connCh
}

func subscribeHandler(s *serverConn, id string, params []any) {
	s.respond(id, uuid.NewString())
}

func TestPing(t *testing.T) {
	c, _ := newTestClient(t, true, map[string]methodHandler{
		"core.ping": func(s *serverConn, id string, params []any) {
			s.respond(id, "pong")
		},
	})
	got, err := c.Ping()
	if err != nil {
		t.Fatal(err)
	}
	if got != "pong" {
		t.Errorf("got %q", got)
	}
}

func TestCallDecodesEJSON(t *testing.T) {
	c, _ := newTestClient(t, true, map[string]methodHandler{
		"test.echo_date": func(s *serverConn, id string, params []any) {
			s.respond(id, map[string]any{"created": map[string]any{"$date": 2000}})
		},
	})
	res, err := c.Call("test.echo_date")
	if err != nil {
		t.Fatal(err)
	}
	created := res.(map[string]any)["created"].(time.Time)
	if created != time.Date(1970, 1, 1, 0, 0, 2, 0, time.UTC) {
		t.Errorf("got %v", created)
	}
}

func TestCallSendsParams(t *testing.T) {
	var gotParams []any
	done := make(chan struct{})
	c, _ := newTestClient(t, true, map[string]methodHandler{
		"user.create": func(s *serverConn, id string, params []any) {
			gotParams = params
			close(done)
			s.respond(id, float64(70))
		},
	})
	res, err := c.Call("user.create", map[string]any{"username": "user"}, true)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if res.(int64) != 70 {
		t.Errorf("result: got %v", res)
	}
	if len(gotParams) != 2 || gotParams[1] != true {
		t.Errorf("params: got %v", gotParams)
	}
	if m, ok := gotParams[0].(map[string]any); !ok || m["username"] != "user" {
		t.Errorf("params[0]: got %v", gotParams[0])
	}
}

func TestCallError(t *testing.T) {
	c, _ := newTestClient(t, true, map[string]methodHandler{
		"test.fail": func(s *serverConn, id string, params []any) {
			s.respondError(id, int(TruenasCallError), "Call error", map[string]any{
				"error":   22,
				"errname": "EINVAL",
				"reason":  "it broke",
				"trace":   map[string]any{"class": "CallError", "formatted": "tb", "repr": "CallError(...)"},
				"extra":   []any{},
			})
		},
	})
	_, err := c.Call("test.fail")
	var clientErr *ClientError
	if !errors.As(err, &clientErr) {
		t.Fatalf("got %T: %v", err, err)
	}
	if clientErr.Reason != "it broke" || clientErr.Errno != 22 {
		t.Errorf("got %+v", clientErr)
	}
	if clientErr.Trace == nil || clientErr.Trace.Class != "CallError" {
		t.Errorf("trace: got %+v", clientErr.Trace)
	}
}

func TestCallValidationErrors(t *testing.T) {
	c, _ := newTestClient(t, true, map[string]methodHandler{
		"test.validate": func(s *serverConn, id string, params []any) {
			s.respondError(id, int(InvalidParams), "Invalid params", map[string]any{
				"error":   22,
				"errname": "EINVAL",
				"reason":  "validation",
				"trace":   nil,
				"extra":   []any{[]any{"user.name", "already exists", 17}},
			})
		},
	})
	_, err := c.Call("test.validate")
	var vErr *ValidationErrors
	if !errors.As(err, &vErr) {
		t.Fatalf("got %T: %v", err, err)
	}
	if len(vErr.Errors) != 1 || vErr.Errors[0].Attribute != "user.name" {
		t.Errorf("got %+v", vErr.Errors)
	}
	if want := "[EEXIST] user.name: already exists"; vErr.Error() != want {
		t.Errorf("message: got %q", vErr.Error())
	}
}

func TestCallMethodNotFound(t *testing.T) {
	c, _ := newTestClient(t, true, nil)
	_, err := c.Call("no.such_method")
	var clientErr *ClientError
	if !errors.As(err, &clientErr) {
		t.Fatalf("got %T: %v", err, err)
	}
	if clientErr.Errno != ENoMethod || clientErr.Reason != "Method does not exist" {
		t.Errorf("got %+v", clientErr)
	}
}

func TestCallTimeout(t *testing.T) {
	c, _ := newTestClient(t, true, map[string]methodHandler{
		"test.slow": func(s *serverConn, id string, params []any) {
			// never respond
		},
	})
	c.opts.CallTimeout = 100 * time.Millisecond
	_, err := c.Call("test.slow")
	var timeout *CallTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("got %T: %v", err, err)
	}
}

func TestConnectionClosedFailsPendingCalls(t *testing.T) {
	c, sc := newTestClient(t, true, map[string]methodHandler{
		"test.slow": func(s *serverConn, id string, params []any) {
			// drop the connection mid-call
			s.ws.Close()
		},
	})
	_ = sc
	_, err := c.Call("test.slow")
	var clientErr *ClientError
	if !errors.As(err, &clientErr) {
		t.Fatalf("got %T: %v", err, err)
	}
	if clientErr.Errno != errnoECONNABORTED {
		t.Errorf("got %+v", clientErr)
	}
	// Subsequent calls fail immediately.
	if _, err := c.Call("core.ping"); err == nil {
		t.Error("expected error after close")
	}
}

// New-style job: the call resolves with the job ID from the core.get_jobs
// collection update, and the job result arrives via a CHANGED event.
func TestCallJobNewStyle(t *testing.T) {
	c, _ := newTestClient(t, false, map[string]methodHandler{
		"core.subscribe": subscribeHandler,
		"pool.import": func(s *serverConn, id string, params []any) {
			fields := func(state string, percent float64, result any) map[string]any {
				return map[string]any{
					"id": 123, "state": state, "result": result,
					"progress":    map[string]any{"percent": percent, "description": "working"},
					"message_ids": []string{id},
				}
			}
			s.notify("collection_update", map[string]any{
				"msg": "added", "collection": "core.get_jobs", "id": 123,
				"fields": fields("RUNNING", 10, nil),
			})
			s.notify("collection_update", map[string]any{
				"msg": "changed", "collection": "core.get_jobs", "id": 123,
				"fields": fields("SUCCESS", 100, "imported"),
			})
			// The real response arrives after the job completes and must be
			// ignored (the call was already resolved with the job ID).
			s.respond(id, "imported")
		},
	})

	job, err := c.StartJob(t.Context(), "pool.import")
	if err != nil {
		t.Fatal(err)
	}
	if job.ID() != 123 {
		t.Errorf("job id: got %d", job.ID())
	}
	res, err := job.Result(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if res != "imported" {
		t.Errorf("result: got %v", res)
	}
}

func TestCallJobProgressCallback(t *testing.T) {
	updates := make(chan *JobFields, 8)
	c, _ := newTestClient(t, false, map[string]methodHandler{
		"core.subscribe": subscribeHandler,
		"test.job": func(s *serverConn, id string, params []any) {
			for i, state := range []string{"RUNNING", "SUCCESS"} {
				s.notify("collection_update", map[string]any{
					"msg":        map[bool]string{true: "added", false: "changed"}[i == 0],
					"collection": "core.get_jobs", "id": 7,
					"fields": map[string]any{
						"id": 7, "state": state, "result": nil,
						"progress":    map[string]any{"percent": float64(50 * (i + 1)), "description": "step"},
						"message_ids": []string{id},
					},
				})
			}
		},
	})

	job, err := c.StartJob(t.Context(), "test.job")
	if err != nil {
		t.Fatal(err)
	}
	job.OnUpdate(func(fields *JobFields) { updates <- fields })
	if _, err := job.Result(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case u := <-updates:
		if u.Progress.Description != "step" {
			t.Errorf("got %+v", u.Progress)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no progress update received")
	}
}

func TestJobValidationFailure(t *testing.T) {
	c, _ := newTestClient(t, false, map[string]methodHandler{
		"core.subscribe": subscribeHandler,
		"test.job": func(s *serverConn, id string, params []any) {
			s.notify("collection_update", map[string]any{
				"msg": "changed", "collection": "core.get_jobs", "id": 9,
				"fields": map[string]any{
					"id": 9, "state": "FAILED", "error": "validation failed",
					"exception": "Traceback...\nValidationErrors",
					"exc_info": map[string]any{
						"type":  "VALIDATION",
						"extra": []any{[]any{"pool.name", "invalid name", 22}},
					},
					"progress":    map[string]any{"percent": 0, "description": ""},
					"message_ids": []string{id},
				},
			})
		},
	})

	_, err := c.CallJob(t.Context(), "test.job")
	var vErr *ValidationErrors
	if !errors.As(err, &vErr) {
		t.Fatalf("got %T: %v", err, err)
	}
	if len(vErr.Errors) != 1 || vErr.Errors[0].Attribute != "pool.name" {
		t.Errorf("got %+v", vErr.Errors)
	}
}

func TestJobFailureWithTrace(t *testing.T) {
	c, _ := newTestClient(t, false, map[string]methodHandler{
		"core.subscribe": subscribeHandler,
		"test.job": func(s *serverConn, id string, params []any) {
			s.notify("collection_update", map[string]any{
				"msg": "changed", "collection": "core.get_jobs", "id": 9,
				"fields": map[string]any{
					"id": 9, "state": "FAILED", "error": "boom",
					"exception":   "Traceback (most recent call last):\nCallError: boom",
					"exc_info":    map[string]any{"type": "CallError", "extra": nil},
					"progress":    map[string]any{"percent": 0, "description": ""},
					"message_ids": []string{id},
				},
			})
		},
	})

	_, err := c.CallJob(t.Context(), "test.job")
	var clientErr *ClientError
	if !errors.As(err, &clientErr) {
		t.Fatalf("got %T: %v", err, err)
	}
	if clientErr.Reason != "boom" || clientErr.Trace == nil || clientErr.Trace.Class != "CallError" {
		t.Errorf("got %+v trace %+v", clientErr, clientErr.Trace)
	}
	if clientErr.Trace.Repr != "CallError: boom" {
		t.Errorf("repr: got %q", clientErr.Trace.Repr)
	}
}

func TestSubscribe(t *testing.T) {
	c, sc := newTestClient(t, true, map[string]methodHandler{
		"core.subscribe":   subscribeHandler,
		"core.unsubscribe": func(s *serverConn, id string, params []any) { s.respond(id, nil) },
	})

	events := make(chan string, 8)
	sub, err := c.Subscribe("alert.list", func(mtype string, params *CollectionUpdateParams) {
		events <- mtype
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sub.ID == "" {
		t.Error("no subscription id")
	}

	sc.notify("collection_update", map[string]any{
		"msg": "added", "collection": "alert.list", "fields": map[string]any{},
	})
	select {
	case mtype := <-events:
		if mtype != "ADDED" {
			t.Errorf("got %q", mtype)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event received")
	}

	if err := c.Unsubscribe(sub); err != nil {
		t.Fatal(err)
	}
	sc.notify("collection_update", map[string]any{
		"msg": "added", "collection": "alert.list", "fields": map[string]any{},
	})
	select {
	case <-events:
		t.Error("received event after unsubscribe")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestNotifyUnsubscribed(t *testing.T) {
	c, sc := newTestClient(t, true, map[string]methodHandler{
		"core.subscribe": subscribeHandler,
	})
	sub, err := c.Subscribe("alert.list", func(string, *CollectionUpdateParams) {}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sc.notify("notify_unsubscribed", map[string]any{
		"collection": "alert.list",
		"error":      map[string]any{"error": 1, "errname": "EPERM", "reason": "not allowed"},
	})
	select {
	case <-sub.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("subscription not terminated")
	}
	if sub.Err() == nil || sub.Err().Error() != "not allowed" {
		t.Errorf("err: got %v", sub.Err())
	}
}

func TestWildcardSubscription(t *testing.T) {
	c, sc := newTestClient(t, true, map[string]methodHandler{
		"core.subscribe": subscribeHandler,
	})
	events := make(chan string, 8)
	_, err := c.Subscribe("*", func(mtype string, params *CollectionUpdateParams) {
		events <- params.Collection
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sc.notify("collection_update", map[string]any{
		"msg": "changed", "collection": "disk.query", "fields": map[string]any{},
	})
	select {
	case collection := <-events:
		if collection != "disk.query" {
			t.Errorf("got %q", collection)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event received")
	}
}

func TestConnectFailsOnRefusedConnection(t *testing.T) {
	_, err := Connect("ws://127.0.0.1:1/api/current", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestConnectHandshakeError(t *testing.T) {
	// A server that closes immediately after upgrade never answers
	// core.set_options: Connect must fail, not hang.
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ws.Close()
	}))
	defer srv.Close()

	uri := "ws" + strings.TrimPrefix(srv.URL, "http")
	if _, err := Connect(uri, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestReservedPortsRequiresWSScheme(t *testing.T) {
	_, err := Connect("wss://example.com/api/current", &Options{ReservedPorts: true})
	var clientErr *ClientError
	if !errors.As(err, &clientErr) {
		t.Fatalf("got %T: %v", err, err)
	}
	if !strings.Contains(clientErr.Reason, "reserved_ports connections require a ws:// URI") {
		t.Errorf("got %q", clientErr.Reason)
	}
}

func TestGlobalErrorBroadcast(t *testing.T) {
	c, sc := newTestClient(t, true, map[string]methodHandler{
		"test.slow": func(s *serverConn, id string, params []any) {},
	})
	errCh := make(chan error, 1)
	go func() {
		_, err := c.Call("test.slow")
		errCh <- err
	}()
	// Give the call time to register, then send a global (id: null) error.
	time.Sleep(100 * time.Millisecond)
	sc.write(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{
		"code": int(TruenasTooManyConcurrentCalls), "message": "too many calls",
	}})
	select {
	case err := <-errCh:
		var clientErr *ClientError
		if !errors.As(err, &clientErr) {
			t.Fatalf("got %T: %v", err, err)
		}
		if !strings.Contains(clientErr.Reason, "too many calls") {
			t.Errorf("got %q", clientErr.Reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("call not failed by global error")
	}
}
