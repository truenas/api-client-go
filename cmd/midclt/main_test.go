// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// startFakeServer runs a minimal middleware endpoint answering
// core.set_options, core.ping and test.echo.
func startFakeServer(t *testing.T) string {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		for {
			var msg struct {
				Method string `json:"method"`
				ID     string `json:"id"`
				Params []any  `json:"params"`
			}
			if err := ws.ReadJSON(&msg); err != nil {
				return
			}
			respond := func(result any) {
				ws.WriteJSON(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": result})
			}
			switch msg.Method {
			case "core.set_options":
				respond(map[string]any{"legacy_jobs": true})
			case "core.ping":
				respond("pong")
			case "test.echo":
				respond(msg.Params)
			default:
				ws.WriteJSON(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "error": map[string]any{
					"code": -32601, "message": "Method does not exist",
				}})
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

// captureStdout runs fn while capturing what it writes to stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	out := make([]byte, 64*1024)
	n, _ := r.Read(out)
	return string(out[:n])
}

func TestRunPing(t *testing.T) {
	uri := startFakeServer(t)
	out := captureStdout(t, func() {
		if code := runPing(&globalOptions{uri: uri}); code != 0 {
			t.Errorf("exit code %d", code)
		}
	})
	if strings.TrimSpace(out) != "pong" {
		t.Errorf("got %q", out)
	}
}

func TestRunCallParsesJSONArgs(t *testing.T) {
	uri := startFakeServer(t)
	out := captureStdout(t, func() {
		code := runCall(&globalOptions{uri: uri}, []string{
			"test.echo", `{"a": 1}`, "plain-string", "42", "true",
		})
		if code != 0 {
			t.Errorf("exit code %d", code)
		}
	})
	want := `[{"a":1},"plain-string",42,true]`
	if strings.TrimSpace(out) != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestRunCallMethodNotFound(t *testing.T) {
	uri := startFakeServer(t)
	if code := runCall(&globalOptions{uri: uri}, []string{"-q", "no.such"}); code != 1 {
		t.Errorf("exit code %d", code)
	}
}

func TestParseParams(t *testing.T) {
	params, err := parseParams([]string{`[1, 2]`, "root", `{"x": null}`})
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 3 {
		t.Fatalf("got %d params", len(params))
	}
	if _, ok := params[0].([]any); !ok {
		t.Errorf("params[0]: got %T", params[0])
	}
	if params[1] != "root" {
		t.Errorf("params[1]: got %v", params[1])
	}
}
