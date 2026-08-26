// SPDX-License-Identifier: LGPL-3.0-or-later

package truenas

import (
	"encoding/json"
	"testing"
)

func TestValidationErrorsMessage(t *testing.T) {
	err := &ValidationErrors{Errors: []ErrorExtra{
		{Attribute: "user.name", Errmsg: "already exists", Errcode: 17},
		{Attribute: "", Errmsg: "bad input", Errcode: 22},
		{Attribute: "x", Errmsg: "mystery", Errcode: 9999},
	}}
	want := "[EEXIST] user.name: already exists\n" +
		"[EINVAL] ALL: bad input\n" +
		"[EUNKNOWN] x: mystery"
	if got := err.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestErrnoNameCustomCodes(t *testing.T) {
	if got := errnoName(ENoMethod); got != "ENOMETHOD" {
		t.Errorf("got %q", got)
	}
	if got := errnoName(ENotAuthenticated); got != "ENOTAUTHENTICATED" {
		t.Errorf("got %q", got)
	}
}

func TestErrorExtraJSONRoundTrip(t *testing.T) {
	// On the wire an ErrorExtra is [attribute, errmsg, errcode].
	var e ErrorExtra
	if err := json.Unmarshal([]byte(`["user.name", "invalid", 22]`), &e); err != nil {
		t.Fatal(err)
	}
	if e.Attribute != "user.name" || e.Errmsg != "invalid" || e.Errcode != 22 {
		t.Errorf("got %+v", e)
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `["user.name","invalid",22]` {
		t.Errorf("got %s", data)
	}
}

func TestErrorExtraRejectsWrongLength(t *testing.T) {
	var e ErrorExtra
	if err := json.Unmarshal([]byte(`["a", "b"]`), &e); err == nil {
		t.Error("expected error for 2-element array")
	}
}

func TestMessageParsing(t *testing.T) {
	var m message
	data := `{"jsonrpc": "2.0", "id": "abc", "error": {"code": -32001, "message": "err",
		"data": {"error": 22, "errname": "EINVAL", "reason": "bad", "trace": null, "extra": []}}}`
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		t.Fatal(err)
	}
	if m.ID == nil || *m.ID != "abc" {
		t.Errorf("id: got %v", m.ID)
	}
	if m.Error == nil || JSONRPCErrorCode(m.Error.Code) != TruenasCallError {
		t.Errorf("error: got %+v", m.Error)
	}
	var te TruenasError
	if err := json.Unmarshal(m.Error.Data, &te); err != nil {
		t.Fatal(err)
	}
	if te.Reason != "bad" || te.Errname != "EINVAL" {
		t.Errorf("data: got %+v", te)
	}
}
