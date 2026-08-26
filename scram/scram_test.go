// SPDX-License-Identifier: LGPL-3.0-or-later

package scram

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fakeServer implements the server side of the exchange using the same
// primitives, so a full round trip exercises proof computation and mutual
// verification (mirrors tests/scram/test_scram_client.py's approach).
type fakeServer struct {
	salt       []byte
	iterations int
	auth       *AuthData
}

func newFakeServer(t *testing.T, password string) *fakeServer {
	t.Helper()
	salt := make([]byte, 16)
	rand.Read(salt)
	salted, err := Hi([]byte(password), salt, MinIters)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeServer{salt: salt, iterations: MinIters, auth: GenerateAuthData(salted)}
}

// firstResponse builds "r=,s=,i=" combining the client nonce with a server nonce.
func (s *fakeServer) firstResponse(t *testing.T, clientFirst *ClientFirst) *ServerFirst {
	t.Helper()
	serverNonce := make([]byte, NonceSize)
	rand.Read(serverNonce)
	combined := append(append([]byte{}, clientFirst.nonce...), serverNonce...)
	rfc := fmt.Sprintf("r=%s,s=%s,i=%d",
		base64.StdEncoding.EncodeToString(combined),
		base64.StdEncoding.EncodeToString(s.salt),
		s.iterations)
	parsed, err := ParseServerFirst(rfc)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// verifyProofAndSign checks the client proof (RFC 5802 server side) and
// returns the server-final message.
func (s *fakeServer) verifyProofAndSign(t *testing.T, clientFirst *ClientFirst,
	serverFirst *ServerFirst, clientFinal *ClientFinal) *ServerFinal {
	t.Helper()

	cbB64 := encodeChannelBinding(clientFirst.gs2Header, clientFinal.channelBinding)
	msg := authMessage(clientFirst, serverFirst, cbB64, clientFinal.nonce)

	clientSignature := hmacSHA512(s.auth.StoredKey, []byte(msg))
	recoveredKey, err := xorBytes(clientFinal.proof, clientSignature)
	if err != nil {
		t.Fatal(err)
	}
	if !constantTimeEqual(h(recoveredKey), s.auth.StoredKey) {
		t.Fatal("server: client proof verification failed")
	}

	signature := hmacSHA512(s.auth.ServerKey, []byte(msg))
	parsed, err := ParseServerFinal("v=" + base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func runExchange(t *testing.T, username, password string, apiKeyID int, cbType string, cbData []byte) {
	t.Helper()
	server := newFakeServer(t, password)

	clientFirst, err := NewClientFirst(username, apiKeyID, cbType)
	if err != nil {
		t.Fatal(err)
	}
	serverFirst := server.firstResponse(t, clientFirst)

	salted, err := Hi([]byte(password), serverFirst.Salt, serverFirst.Iterations)
	if err != nil {
		t.Fatal(err)
	}
	auth := GenerateAuthData(salted)

	clientFinal, err := NewClientFinal(clientFirst, serverFirst, auth.ClientKey, auth.StoredKey, cbData)
	if err != nil {
		t.Fatal(err)
	}

	serverFinal := server.verifyProofAndSign(t, clientFirst, serverFirst, clientFinal)

	if err := VerifyServerSignature(clientFirst, serverFirst, clientFinal, serverFinal, auth.ServerKey); err != nil {
		t.Fatal(err)
	}
}

func TestFullExchange(t *testing.T) {
	runExchange(t, "admin", "hunter2-api-key-material", 7, "", nil)
}

func TestFullExchangeWithChannelBinding(t *testing.T) {
	cbData := make([]byte, 32)
	rand.Read(cbData)
	runExchange(t, "admin", "hunter2-api-key-material", 7, CBTLSServerEndPoint, cbData)
}

func TestFullExchangePasswordAuth(t *testing.T) {
	// api_key_id of zero: plain user credential, no ":id" suffix.
	runExchange(t, "root", "secret-password", 0, "", nil)
}

func TestClientFirstFormat(t *testing.T) {
	m, err := NewClientFirst("user", 3, "")
	if err != nil {
		t.Fatal(err)
	}
	s := m.String()
	if !strings.HasPrefix(s, "n,,n=user:3,r=") {
		t.Errorf("got %q", s)
	}
	if m.bare() != strings.TrimPrefix(s, "n,,") {
		t.Errorf("bare: got %q", m.bare())
	}
}

func TestClientFirstChannelBindingHeader(t *testing.T) {
	m, err := NewClientFirst("user", 3, CBTLSServerEndPoint)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.String(), "p=tls-server-end-point,,n=user:3,r=") {
		t.Errorf("got %q", m.String())
	}
}

func TestClientFirstRejectsBadUsernames(t *testing.T) {
	for _, name := range []string{"", "with,comma", "with=equals"} {
		if _, err := NewClientFirst(name, 0, ""); err == nil {
			t.Errorf("NewClientFirst(%q): expected error", name)
		}
	}
}

func TestChannelBindingConsistency(t *testing.T) {
	server := newFakeServer(t, "pw")
	clientFirst, err := NewClientFirst("user", 1, CBTLSServerEndPoint)
	if err != nil {
		t.Fatal(err)
	}
	serverFirst := server.firstResponse(t, clientFirst)
	salted, _ := Hi([]byte("pw"), serverFirst.Salt, serverFirst.Iterations)
	auth := GenerateAuthData(salted)

	// 'p' flag without binding data must fail.
	if _, err := NewClientFinal(clientFirst, serverFirst, auth.ClientKey, auth.StoredKey, nil); err == nil {
		t.Error("expected error for p flag without binding data")
	}

	// Binding data without 'p' flag must fail.
	unbound, err := NewClientFirst("user", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	serverFirst2 := server.firstResponse(t, unbound)
	if _, err := NewClientFinal(unbound, serverFirst2, auth.ClientKey, auth.StoredKey, []byte{1, 2}); err == nil {
		t.Error("expected error for binding data without p flag")
	}
}

func TestParseServerFirstValidation(t *testing.T) {
	nonce := base64.StdEncoding.EncodeToString(make([]byte, NonceSize*2))
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	for _, bad := range []string{
		"",
		"r=abc",
		fmt.Sprintf("r=%s,s=%s,i=notanumber", nonce, salt),
		fmt.Sprintf("r=%s,s=%s,i=100", nonce, salt),      // iterations below minimum
		fmt.Sprintf("r=%s,s=%s,i=99999999", nonce, salt), // iterations above maximum
		fmt.Sprintf("r=%s,s=%s,i=50000", base64.StdEncoding.EncodeToString([]byte("short")), salt), // bad nonce size
		fmt.Sprintf("r=%s,s=%s,x=50000", nonce, salt), // unknown key
	} {
		if _, err := ParseServerFirst(bad); err == nil {
			t.Errorf("ParseServerFirst(%q): expected error", bad)
		}
	}
	good := fmt.Sprintf("r=%s,s=%s,i=50000", nonce, salt)
	m, err := ParseServerFirst(good)
	if err != nil {
		t.Fatal(err)
	}
	if m.Iterations != 50000 || len(m.Nonce) != NonceSize*2 {
		t.Errorf("got %+v", m)
	}
}

func TestParseServerFinalValidation(t *testing.T) {
	for _, bad := range []string{"", "x=abc", "v=abc,extra=1", "v=!!!"} {
		if _, err := ParseServerFinal(bad); err == nil {
			t.Errorf("ParseServerFinal(%q): expected error", bad)
		}
	}
}

func TestVerifyServerSignatureRejectsWrongKey(t *testing.T) {
	server := newFakeServer(t, "pw")
	clientFirst, _ := NewClientFirst("user", 1, "")
	serverFirst := server.firstResponse(t, clientFirst)
	salted, _ := Hi([]byte("pw"), serverFirst.Salt, serverFirst.Iterations)
	auth := GenerateAuthData(salted)
	clientFinal, err := NewClientFinal(clientFirst, serverFirst, auth.ClientKey, auth.StoredKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverFinal := server.verifyProofAndSign(t, clientFirst, serverFirst, clientFinal)

	wrongKey := make([]byte, DigestSize)
	if err := VerifyServerSignature(clientFirst, serverFirst, clientFinal, serverFinal, wrongKey); err == nil {
		t.Error("expected verification failure with wrong server key")
	}
}

// Channel-binding parity vectors exported from the Python client's
// tests/scram/_cb_test_vectors.py: signature algorithms beyond the default
// RSA-PKCS1/SHA-256, including RSASSA-PSS (digest in signature parameters)
// and SHA-1 promotion per RFC 5929 4.1.
func TestComputeTLSServerEndPointVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/cb_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name        string `json:"name"`
		CertDERB64  string `json:"cert_der_b64"`
		ExpectedHex string `json:"expected_hex"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			certDER, err := base64.StdEncoding.DecodeString(v.CertDERB64)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ComputeTLSServerEndPoint(certDER)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != v.ExpectedHex {
				t.Errorf("got %x, want %s", got, v.ExpectedHex)
			}
		})
	}
}
