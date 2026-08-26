// SPDX-License-Identifier: LGPL-3.0-or-later

//go:build smoke

// Smoke tests against a real TrueNAS machine. They are excluded from normal
// unit-test runs by the "smoke" build tag and configured via environment
// variables:
//
//	TRUENAS_SMOKE_URI       websocket URI, e.g. wss://nas.example/api/current
//	                        (required; tests skip without it)
//	TRUENAS_SMOKE_USERNAME  account username
//	TRUENAS_SMOKE_PASSWORD  account password (password login)
//	TRUENAS_SMOKE_API_KEY   API key material or key file path (API-key login;
//	                        used with TRUENAS_SMOKE_USERNAME)
//	TRUENAS_SMOKE_INSECURE  "1" to disable SSL certificate verification
//	TRUENAS_SMOKE_NO_CB     "1" to disable SCRAM channel binding (required
//	                        for plain ws:// or servers without binding support)
//	TRUENAS_SMOKE_PLAIN     "1" to use PLAIN API-key auth instead of SCRAM
//	TRUENAS_SMOKE_JOB       "1" to also run the job smoke test, which calls
//	                        the private core.job_test method
//
// Example:
//
//	TRUENAS_SMOKE_URI=wss://nas.example/api/current \
//	TRUENAS_SMOKE_USERNAME=admin \
//	TRUENAS_SMOKE_API_KEY=1-abcd... \
//	go test -tags smoke -v -run Smoke .
//
// All tests are read-only against the target machine except TestSmokeJob,
// which runs the middleware's built-in test job.
package truenas

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func smokeURI(t *testing.T) string {
	t.Helper()
	uri := os.Getenv("TRUENAS_SMOKE_URI")
	if uri == "" {
		t.Skip("TRUENAS_SMOKE_URI not set; skipping smoke test")
	}
	return uri
}

func smokeOptions() *Options {
	return &Options{
		InsecureSkipVerify: os.Getenv("TRUENAS_SMOKE_INSECURE") == "1",
	}
}

func smokeConnect(t *testing.T) *Client {
	t.Helper()
	c, err := Connect(smokeURI(t), smokeOptions())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// smokeLogin authenticates with whichever credentials the environment
// provides, skipping the test if there are none.
func smokeLogin(t *testing.T, c *Client) {
	t.Helper()
	username := os.Getenv("TRUENAS_SMOKE_USERNAME")
	password := os.Getenv("TRUENAS_SMOKE_PASSWORD")
	apiKey := os.Getenv("TRUENAS_SMOKE_API_KEY")

	switch {
	case apiKey != "":
		mech := AuthMechSCRAM
		if os.Getenv("TRUENAS_SMOKE_PLAIN") == "1" {
			mech = AuthMechPlain
		}
		err := c.LoginWithAPIKey(username, apiKey, &APIKeyOptions{
			Mechanism:             mech,
			DisableChannelBinding: os.Getenv("TRUENAS_SMOKE_NO_CB") == "1",
		})
		if err != nil {
			t.Fatalf("LoginWithAPIKey: %v", err)
		}
	case username != "" && password != "":
		if err := c.LoginWithPassword(username, password, ""); err != nil {
			t.Fatalf("LoginWithPassword: %v", err)
		}
	default:
		t.Skip("no smoke credentials set (TRUENAS_SMOKE_API_KEY or " +
			"TRUENAS_SMOKE_USERNAME+TRUENAS_SMOKE_PASSWORD); skipping")
	}
}

func TestSmokeConnectAndPing(t *testing.T) {
	c := smokeConnect(t)
	pong, err := c.Ping()
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if pong != "pong" {
		t.Errorf("Ping: got %q, want \"pong\"", pong)
	}
}

func TestSmokeLoginAndSystemInfo(t *testing.T) {
	c := smokeConnect(t)
	smokeLogin(t, c)

	result, err := c.Call("system.info")
	if err != nil {
		t.Fatalf("system.info: %v", err)
	}
	info, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("system.info: got %T, want object", result)
	}
	version, _ := info["version"].(string)
	if version == "" {
		t.Errorf("system.info: missing version in %v", info)
	}
	t.Logf("connected to TrueNAS %s (%v)", version, info["hostname"])

	// The ejson decoder should have produced a real time.Time for the
	// server's $date-encoded datetime field.
	if dt, ok := info["datetime"]; ok {
		if _, isTime := dt.(time.Time); !isTime {
			t.Errorf("system.info datetime: got %T, want time.Time", dt)
		}
	}
}

func TestSmokeCallWithParams(t *testing.T) {
	c := smokeConnect(t)
	smokeLogin(t, c)

	result, err := c.Call("user.query", []any{[]any{"username", "=", "root"}})
	if err != nil {
		t.Fatalf("user.query: %v", err)
	}
	users, ok := result.([]any)
	if !ok || len(users) != 1 {
		t.Fatalf("user.query: got %T len %d, want 1 root user", result, len(users))
	}
}

func TestSmokeMethodNotFound(t *testing.T) {
	c := smokeConnect(t)
	_, err := c.Call("no.such_method_smoke_test")
	var clientErr *ClientError
	if !errors.As(err, &clientErr) || clientErr.Errno != ENoMethod {
		t.Fatalf("got %v, want ClientError with ENoMethod", err)
	}
}

func TestSmokeSubscribe(t *testing.T) {
	c := smokeConnect(t)
	smokeLogin(t, c)

	sub, err := c.Subscribe("core.get_jobs", func(mtype string, params *CollectionUpdateParams) {}, nil)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if sub.ID == "" {
		t.Error("Subscribe: empty subscription id")
	}
	if err := c.Unsubscribe(sub); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
}

// TestSmokeJob runs the middleware's built-in test job (core.job_test, a
// private method) and tracks it to completion. Opt in with
// TRUENAS_SMOKE_JOB=1.
func TestSmokeJob(t *testing.T) {
	if os.Getenv("TRUENAS_SMOKE_JOB") != "1" {
		t.Skip("TRUENAS_SMOKE_JOB not set; skipping job smoke test")
	}
	uri := smokeURI(t)
	opts := smokeOptions()
	opts.PrivateMethods = true
	c, err := Connect(uri, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()
	smokeLogin(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	job, err := c.StartJob(ctx, "core.job_test", map[string]any{"sleep": 1})
	if err != nil {
		t.Fatalf("core.job_test: %v", err)
	}
	t.Logf("started job %d", job.ID())

	updates := 0
	job.OnUpdate(func(fields *JobFields) { updates++ })
	if _, err := job.Result(ctx); err != nil {
		t.Fatalf("job result: %v", err)
	}
	t.Logf("job finished after %d update(s)", updates)
}
