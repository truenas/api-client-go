// SPDX-License-Identifier: LGPL-3.0-or-later

package truenas

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/truenas/api-client-go/scram"
)

const (
	testRawAPIKey  = "1-uz8DhKHFhRIUQIvjzabPYtpy5wf1DJ3ZBLlDgNVhRAFT7Y6pJGUlm0n3apwxWEU4"
	testKeySecret  = "uz8DhKHFhRIUQIvjzabPYtpy5wf1DJ3ZBLlDgNVhRAFT7Y6pJGUlm0n3apwxWEU4"
	testIterations = 50000
)

// scramServer implements the server side of the SCRAM-SHA-512 exchange with
// an independent stdlib-crypto implementation, so the tests exercise real
// interop rather than the client verifying itself.
type scramServer struct {
	t          *testing.T
	salt       []byte
	storedKey  []byte
	serverKey  []byte
	binding    []byte // expected cbind-data, nil for an unbound exchange
	mechanisms []any

	clientFirstBare string
	gs2Header       string
	serverFirstStr  string
}

func newScramServer(t *testing.T, secret string, binding []byte) *scramServer {
	salt := []byte("fixed-salt-16byt")
	salted, err := pbkdf2.Key(sha512.New, secret, salt, testIterations, sha512.Size)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyMAC := hmac.New(sha512.New, salted)
	clientKeyMAC.Write([]byte("Client Key"))
	clientKey := clientKeyMAC.Sum(nil)
	stored := sha512.Sum512(clientKey)
	serverKeyMAC := hmac.New(sha512.New, salted)
	serverKeyMAC.Write([]byte("Server Key"))
	return &scramServer{
		t:          t,
		salt:       salt,
		storedKey:  stored[:],
		serverKey:  serverKeyMAC.Sum(nil),
		binding:    binding,
		mechanisms: []any{"SCRAM", "API_KEY_PLAIN"},
	}
}

func scramAttrs(rfcStr string) map[string]string {
	attrs := map[string]string{}
	for _, part := range strings.Split(rfcStr, ",") {
		if key, value, found := strings.Cut(part, "="); found {
			attrs[key] = value
		}
	}
	return attrs
}

func (s *scramServer) handleLoginEx(sc *serverConn, id string, params []any) {
	req := params[0].(map[string]any)
	switch req["mechanism"] {
	case "SCRAM":
		s.handleSCRAM(sc, id, req)
	default:
		sc.respond(id, map[string]any{"response_type": "AUTH_ERR"})
	}
}

func (s *scramServer) handleSCRAM(sc *serverConn, id string, req map[string]any) {
	rfcStr, _ := req["rfc_str"].(string)
	switch req["scram_type"] {
	case "CLIENT_FIRST_MESSAGE":
		gs2Header, bare, found := strings.Cut(rfcStr, ",,")
		if !found {
			sc.respond(id, map[string]any{"response_type": "AUTH_ERR"})
			return
		}
		s.gs2Header = gs2Header
		s.clientFirstBare = bare
		clientNonce, err := base64.StdEncoding.DecodeString(scramAttrs(bare)["r"])
		if err != nil {
			s.t.Errorf("server: bad client nonce: %v", err)
			sc.respond(id, map[string]any{"response_type": "AUTH_ERR"})
			return
		}
		serverNonce := make([]byte, 32)
		rand.Read(serverNonce)
		combined := append(clientNonce, serverNonce...)
		s.serverFirstStr = "r=" + base64.StdEncoding.EncodeToString(combined) +
			",s=" + base64.StdEncoding.EncodeToString(s.salt) +
			",i=50000"
		sc.respond(id, map[string]any{
			"response_type": "SCRAM_RESPONSE",
			"scram_type":    "SERVER_FIRST_RESPONSE",
			"rfc_str":       s.serverFirstStr,
		})

	case "CLIENT_FINAL_MESSAGE":
		attrs := scramAttrs(rfcStr)

		// Validate the channel-binding c= value byte-for-byte.
		wantCB := base64.StdEncoding.EncodeToString(append([]byte(s.gs2Header+",,"), s.binding...))
		if attrs["c"] != wantCB {
			s.t.Errorf("server: c= mismatch: got %q, want %q", attrs["c"], wantCB)
			sc.respond(id, map[string]any{"response_type": "AUTH_ERR"})
			return
		}

		withoutProof := "c=" + attrs["c"] + ",r=" + attrs["r"]
		authMessage := s.clientFirstBare + "," + s.serverFirstStr + "," + withoutProof

		proof, err := base64.StdEncoding.DecodeString(attrs["p"])
		if err != nil {
			sc.respond(id, map[string]any{"response_type": "AUTH_ERR"})
			return
		}
		sigMAC := hmac.New(sha512.New, s.storedKey)
		sigMAC.Write([]byte(authMessage))
		clientSignature := sigMAC.Sum(nil)
		recoveredKey := make([]byte, len(proof))
		for i := range proof {
			recoveredKey[i] = proof[i] ^ clientSignature[i]
		}
		recoveredStored := sha512.Sum512(recoveredKey)
		if !hmac.Equal(recoveredStored[:], s.storedKey) {
			sc.respond(id, map[string]any{"response_type": "AUTH_ERR"})
			return
		}

		serverSigMAC := hmac.New(sha512.New, s.serverKey)
		serverSigMAC.Write([]byte(authMessage))
		sc.respond(id, map[string]any{
			"response_type": "SCRAM_RESPONSE",
			"scram_type":    "SERVER_FINAL_RESPONSE",
			"rfc_str":       "v=" + base64.StdEncoding.EncodeToString(serverSigMAC.Sum(nil)),
		})

	default:
		sc.respond(id, map[string]any{"response_type": "AUTH_ERR"})
	}
}

func (s *scramServer) handlers() map[string]methodHandler {
	return map[string]methodHandler{
		"auth.mechanism_choices": func(sc *serverConn, id string, params []any) {
			sc.respond(id, s.mechanisms)
		},
		"auth.login_ex": s.handleLoginEx,
	}
}

func TestLoginWithAPIKeySCRAM(t *testing.T) {
	server := newScramServer(t, testKeySecret, nil)
	c, _ := newTestClient(t, true, server.handlers())
	err := c.LoginWithAPIKey("admin", testRawAPIKey, &APIKeyOptions{DisableChannelBinding: true})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoginWithAPIKeySCRAMPrecomputedKeys(t *testing.T) {
	server := newScramServer(t, testKeySecret, nil)
	c, _ := newTestClient(t, true, server.handlers())

	// Precompute the client-side keys with the scram package, as the TrueNAS
	// server would hand them out.
	salted, err := scram.Hi([]byte(testKeySecret), server.salt, testIterations)
	if err != nil {
		t.Fatal(err)
	}
	auth := scram.GenerateAuthData(salted)
	key := `{
		"client_key": "` + base64.StdEncoding.EncodeToString(auth.ClientKey) + `",
		"stored_key": "` + base64.StdEncoding.EncodeToString(auth.StoredKey) + `",
		"server_key": "` + base64.StdEncoding.EncodeToString(auth.ServerKey) + `",
		"api_key_id": 1
	}`
	if err := c.LoginWithAPIKey("admin", key, &APIKeyOptions{DisableChannelBinding: true}); err != nil {
		t.Fatal(err)
	}
}

func TestLoginWithAPIKeySCRAMWrongKey(t *testing.T) {
	server := newScramServer(t, "some-other-secret", nil)
	c, _ := newTestClient(t, true, server.handlers())
	err := c.LoginWithAPIKey("admin", testRawAPIKey, &APIKeyOptions{DisableChannelBinding: true})
	if err == nil || err.Error() != "Failed to authenticate with API key" {
		t.Fatalf("got %v", err)
	}
}

func TestLoginWithAPIKeySCRAMChannelBindingRequiredOverPlainWS(t *testing.T) {
	server := newScramServer(t, testKeySecret, nil)
	c, _ := newTestClient(t, true, server.handlers())
	err := c.LoginWithAPIKey("admin", testRawAPIKey, nil)
	if err == nil || !strings.Contains(err.Error(), "channel binding is required but the connection is not TLS") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginWithAPIKeySCRAMChannelBindingOverTLS(t *testing.T) {
	// The server computes the expected tls-server-end-point binding from its
	// own certificate and rejects a client-final whose c= does not carry it.
	upgrader := websocket.Upgrader{}
	var server *scramServer
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		sc := &serverConn{t: t, ws: ws}
		handlers := server.handlers()
		for {
			var msg struct {
				Method string `json:"method"`
				ID     string `json:"id"`
				Params []any  `json:"params"`
			}
			if err := ws.ReadJSON(&msg); err != nil {
				return
			}
			if msg.Method == "core.set_options" {
				sc.respond(msg.ID, map[string]any{"legacy_jobs": true})
			} else if h := handlers[msg.Method]; h != nil {
				h(sc, msg.ID, msg.Params)
			} else {
				sc.respondError(msg.ID, int(MethodNotFound), "Method does not exist", nil)
			}
		}
	}))
	defer srv.Close()

	binding, err := scram.ComputeTLSServerEndPoint(srv.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	server = newScramServer(t, testKeySecret, binding)

	uri := "wss" + strings.TrimPrefix(srv.URL, "https")
	c, err := Connect(uri, &Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := c.LoginWithAPIKey("admin", testRawAPIKey, nil); err != nil {
		t.Fatal(err)
	}
}

func TestLoginWithAPIKeySCRAMNotSupported(t *testing.T) {
	server := newScramServer(t, testKeySecret, nil)
	server.mechanisms = []any{"API_KEY_PLAIN"}
	c, _ := newTestClient(t, true, server.handlers())
	err := c.LoginWithAPIKey("admin", testRawAPIKey, &APIKeyOptions{DisableChannelBinding: true})
	if err == nil || !strings.Contains(err.Error(), "SCRAM authentication is not supported") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginWithAPIKeyPlain(t *testing.T) {
	var gotKey, gotUser string
	c, _ := newTestClient(t, true, map[string]methodHandler{
		"auth.mechanism_choices": func(sc *serverConn, id string, params []any) {
			sc.respond(id, []any{"API_KEY_PLAIN"})
		},
		"auth.login_ex": func(sc *serverConn, id string, params []any) {
			req := params[0].(map[string]any)
			if req["mechanism"] != "API_KEY_PLAIN" {
				t.Errorf("mechanism: got %v", req["mechanism"])
			}
			gotKey, _ = req["api_key"].(string)
			gotUser, _ = req["username"].(string)
			sc.respond(id, map[string]any{"response_type": "SUCCESS"})
		},
	})
	if err := c.LoginWithAPIKey("admin", testRawAPIKey, &APIKeyOptions{Mechanism: AuthMechPlain}); err != nil {
		t.Fatal(err)
	}
	if gotKey != testRawAPIKey || gotUser != "admin" {
		t.Errorf("got key %q user %q", gotKey, gotUser)
	}
}

func TestLoginWithAPIKeySCRAMRequiresUsername(t *testing.T) {
	server := newScramServer(t, testKeySecret, nil)
	c, _ := newTestClient(t, true, server.handlers())
	err := c.LoginWithAPIKey("", testRawAPIKey, &APIKeyOptions{DisableChannelBinding: true})
	if err == nil || !strings.Contains(err.Error(), "username is required") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginWithPassword(t *testing.T) {
	c, _ := newTestClient(t, true, map[string]methodHandler{
		"auth.login_ex": func(sc *serverConn, id string, params []any) {
			req := params[0].(map[string]any)
			if req["mechanism"] != "PASSWORD_PLAIN" || req["username"] != "root" || req["password"] != "pw" {
				sc.respond(id, map[string]any{"response_type": "AUTH_ERR"})
				return
			}
			sc.respond(id, map[string]any{"response_type": "SUCCESS"})
		},
	})
	if err := c.LoginWithPassword("root", "pw", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.LoginWithPassword("root", "wrong", ""); err == nil ||
		err.Error() != "Invalid username or password" {
		t.Fatalf("got %v", err)
	}
}

func TestLoginWithPasswordOTP(t *testing.T) {
	c, _ := newTestClient(t, true, map[string]methodHandler{
		"auth.login_ex": func(sc *serverConn, id string, params []any) {
			sc.respond(id, map[string]any{"response_type": "OTP_REQUIRED"})
		},
		"auth.login_ex_continue": func(sc *serverConn, id string, params []any) {
			req := params[0].(map[string]any)
			if req["mechanism"] != "OTP_TOKEN" || req["otp_token"] != "123456" {
				sc.respond(id, map[string]any{"response_type": "AUTH_ERR"})
				return
			}
			sc.respond(id, map[string]any{"response_type": "SUCCESS"})
		},
	})
	if err := c.LoginWithPassword("root", "pw", "123456"); err != nil {
		t.Fatal(err)
	}
	if err := c.LoginWithPassword("root", "pw", ""); err == nil ||
		!strings.Contains(err.Error(), "Two-factor authentication is required") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginWithPasswordLegacyFallback(t *testing.T) {
	// Pre-25.04 server: auth.login_ex does not exist; auth.login returns a
	// bool.
	c, _ := newTestClient(t, true, map[string]methodHandler{
		"auth.login": func(sc *serverConn, id string, params []any) {
			sc.respond(id, params[0] == "root" && params[1] == "pw")
		},
	})
	if err := c.LoginWithPassword("root", "pw", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.LoginWithPassword("root", "wrong", ""); err == nil ||
		err.Error() != "Invalid username or password" {
		t.Fatalf("got %v", err)
	}
}

func TestGetKeyMaterialRaw(t *testing.T) {
	m, err := getKeyMaterial(testRawAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	if m.raw != testRawAPIKey || m.rawSecret != testKeySecret || m.apiKeyID != 1 {
		t.Errorf("got %+v", m)
	}
}

func TestGetKeyMaterialJSONRawKey(t *testing.T) {
	m, err := getKeyMaterial(`{"raw_key": "` + testRawAPIKey + `"}`)
	if err != nil {
		t.Fatal(err)
	}
	if m.raw != testRawAPIKey || m.apiKeyID != 1 {
		t.Errorf("got %+v", m)
	}
}

func TestGetKeyMaterialJSONPrecomputed(t *testing.T) {
	keyB64 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	m, err := getKeyMaterial(`{"client_key": "` + keyB64 + `", "stored_key": "` + keyB64 +
		`", "server_key": "` + keyB64 + `", "api_key_id": 5}`)
	if err != nil {
		t.Fatal(err)
	}
	if m.apiKeyID != 5 || string(m.clientKey) != "0123456789abcdef" {
		t.Errorf("got %+v", m)
	}
	// A missing field errors.
	if _, err := getKeyMaterial(`{"client_key": "` + keyB64 + `", "stored_key": "` + keyB64 + `"}`); err == nil {
		t.Error("expected error for missing fields")
	}
}

func TestGetKeyMaterialINI(t *testing.T) {
	keyB64 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	ini := "[TRUENAS_API_KEY]\n" +
		"client_key = " + keyB64 + "\n" +
		"stored_key = " + keyB64 + "\n" +
		"server_key = " + keyB64 + "\n" +
		"api_key_id = 3\n"
	m, err := getKeyMaterial(ini)
	if err != nil {
		t.Fatal(err)
	}
	if m.apiKeyID != 3 || string(m.serverKey) != "0123456789abcdef" {
		t.Errorf("got %+v", m)
	}
}

func TestGetKeyMaterialINIRawKey(t *testing.T) {
	m, err := getKeyMaterial("[DEFAULT]\nraw_key = " + testRawAPIKey + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if m.raw != testRawAPIKey {
		t.Errorf("got %+v", m)
	}
}

func TestGetKeyMaterialFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apikey")
	if err := os.WriteFile(path, []byte(testRawAPIKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := getKeyMaterial(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.raw != testRawAPIKey {
		t.Errorf("got %+v", m)
	}
	if _, err := getKeyMaterial(filepath.Join(t.TempDir(), "missing")); err == nil ||
		!strings.Contains(err.Error(), "Key file not found") {
		t.Errorf("got %v", err)
	}
}

func TestGetKeyMaterialGarbage(t *testing.T) {
	_, err := getKeyMaterial("not a key at all !!!")
	if err == nil || !strings.Contains(err.Error(), "Key material must be either a raw API key") {
		t.Errorf("got %v", err)
	}
}
