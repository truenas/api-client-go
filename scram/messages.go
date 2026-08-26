// SPDX-License-Identifier: LGPL-3.0-or-later

package scram

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/xdg-go/stringprep"
)

var b64 = base64.StdEncoding

// ClientFirst is the first message of the client-server exchange (ports
// ClientFirstMessage). We slightly depart from the RFC in that the API key id
// is passed to the server alongside the username, letting the server select
// the correct key material since users may have more than one API key.
type ClientFirst struct {
	nonce     []byte
	username  string
	apiKeyID  int
	gs2Header string // "" means the default "n" (no channel binding)
	rfcStr    string
}

// NewClientFirst builds a client-first message. channelBindingType, when
// non-empty, requires channel binding: the gs2 cbind flag becomes
// "p=<cb-name>". An apiKeyID of zero means authentication with an actual user
// credential rather than an API key.
func NewClientFirst(username string, apiKeyID int, channelBindingType string) (*ClientFirst, error) {
	if username == "" {
		return nil, fmt.Errorf("scram: must specify username")
	}
	// SCRAM messages are comma-separated and use '=' for the "=2C"/"=3D"
	// username escapes (RFC 5802 5.1) that this library does not emit.
	// Reject both characters up front, matching the C library.
	if strings.ContainsAny(username, ",=") {
		return nil, fmt.Errorf("scram: username must not contain ',' or '='")
	}

	// RFC 5802, Section 5.1: prepare the username with the SASLprep profile
	// of stringprep before sending it to the server.
	prepared, err := stringprep.SASLprep.Prepare(username)
	if err != nil {
		return nil, fmt.Errorf("scram: invalid username: %w", err)
	}

	var gs2Header string
	if channelBindingType != "" {
		gs2Header = "p=" + channelBindingType
	}

	m := &ClientFirst{
		nonce:     generateNonce(),
		username:  prepared,
		apiKeyID:  apiKeyID,
		gs2Header: gs2Header,
	}

	name := m.username
	if m.apiKeyID != 0 {
		name += ":" + strconv.Itoa(m.apiKeyID)
	}
	hdr := m.gs2Header
	if hdr == "" {
		hdr = "n"
	}
	m.rfcStr = fmt.Sprintf("%s%sn=%s,r=%s", hdr, gs2Separator, name, b64.EncodeToString(m.nonce))
	return m, nil
}

// String returns the RFC 5802 wire form of the message.
func (m *ClientFirst) String() string { return m.rfcStr }

// bare returns client-first-message-bare: the message without its GS2 header
// and separator.
func (m *ClientFirst) bare() string {
	if idx := strings.Index(m.rfcStr, gs2Separator); idx >= 0 {
		return m.rfcStr[idx+len(gs2Separator):]
	}
	return m.rfcStr
}

// ServerFirst is the server's reply to the client-first message (ports
// ServerFirstMessage).
type ServerFirst struct {
	Nonce      []byte // combined client+server nonce
	Salt       []byte
	Iterations int
	rfcStr     string
}

// ParseServerFirst parses "r=<nonce>,s=<salt>,i=<iterations>".
func ParseServerFirst(rfcStr string) (*ServerFirst, error) {
	parts := strings.Split(rfcStr, ",")
	if len(parts) != 3 {
		return nil, fmt.Errorf("scram: invalid server first message format")
	}

	var nonceB64, saltB64 string
	iterations := -1
	for _, part := range parts {
		key, value, err := splitAttr(part)
		if err != nil {
			return nil, fmt.Errorf("scram: invalid server first message format")
		}
		switch key {
		case "r":
			nonceB64 = value
		case "s":
			saltB64 = value
		case "i":
			iterations, err = strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("scram: invalid iteration count in server first message")
			}
		default:
			return nil, fmt.Errorf("scram: unknown key in server first message: %s", key)
		}
	}
	if nonceB64 == "" || saltB64 == "" || iterations == -1 {
		return nil, fmt.Errorf("scram: missing required fields in server first message")
	}

	if iterations < MinIters || iterations > MaxIters {
		return nil, fmt.Errorf("scram: %d: iteration count outside [%d, %d]", iterations, MinIters, MaxIters)
	}

	nonce, err := b64.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("scram: invalid base64 encoding in server first message: %w", err)
	}
	salt, err := b64.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("scram: invalid base64 encoding in server first message: %w", err)
	}

	// The C parser accepts only a 32- or 64-byte nonce and caps the salt
	// length; match both.
	if len(nonce) != NonceSize && len(nonce) != NonceSize*2 {
		return nil, fmt.Errorf("scram: %d: unexpected nonce size", len(nonce))
	}
	if len(salt) > MaxSaltSize {
		return nil, fmt.Errorf("scram: %d: salt exceeds maximum of %d", len(salt), MaxSaltSize)
	}

	return &ServerFirst{Nonce: nonce, Salt: salt, Iterations: iterations, rfcStr: rfcStr}, nil
}

// String returns the RFC 5802 wire form of the message.
func (m *ServerFirst) String() string { return m.rfcStr }

// ClientFinal is the final client message carrying the proof (ports
// ClientFinalMessage).
type ClientFinal struct {
	nonce          []byte
	channelBinding []byte
	proof          []byte
	rfcStr         string
}

// NewClientFinal computes the client proof per RFC 5802 Section 3:
//
//	AuthMessage     := client-first-message-bare + "," +
//	                   server-first-message + "," +
//	                   client-final-message-without-proof
//	ClientSignature := HMAC(StoredKey, AuthMessage)
//	ClientProof     := ClientKey XOR ClientSignature
//
// channelBinding is the raw cbind-data (e.g. the tls-server-end-point hash),
// or nil for an unbound exchange.
func NewClientFinal(clientFirst *ClientFirst, serverFirst *ServerFirst,
	clientKey, storedKey, channelBinding []byte) (*ClientFinal, error) {
	// Validate the gs2 flag / channel-binding combination (RFC 5802 6): a
	// 'p' flag requires binding data, and any other flag must not carry any.
	gs2Flag := byte('n')
	if clientFirst.gs2Header != "" {
		gs2Flag = clientFirst.gs2Header[0]
	}
	if gs2Flag == 'p' && len(channelBinding) == 0 {
		return nil, fmt.Errorf("scram: gs2 channel-binding flag 'p' requires channel binding data")
	}
	if gs2Flag != 'p' && len(channelBinding) > 0 {
		return nil, fmt.Errorf("scram: channel binding data provided but gs2 flag is not 'p'")
	}

	// c= is base64(cbind-input) where cbind-input = gs2-header + ",," +
	// [cbind-data] (RFC 5802 7); the gs2-header defaults to "n".
	channelBindingB64 := encodeChannelBinding(clientFirst.gs2Header, channelBinding)

	// Use the combined client+server nonce from server-first.
	m := &ClientFinal{
		nonce:          serverFirst.Nonce,
		channelBinding: channelBinding,
	}

	authMessage := authMessage(clientFirst, serverFirst, channelBindingB64, m.nonce)
	clientSignature := hmacSHA512(storedKey, []byte(authMessage))
	proof, err := xorBytes(clientKey, clientSignature)
	if err != nil {
		return nil, err
	}
	m.proof = proof
	m.rfcStr = fmt.Sprintf("c=%s,r=%s,p=%s",
		channelBindingB64, b64.EncodeToString(m.nonce), b64.EncodeToString(proof))
	return m, nil
}

// String returns the RFC 5802 wire form of the message.
func (m *ClientFinal) String() string { return m.rfcStr }

// ServerFinal is the server's final message carrying its signature (ports
// ServerFinalMessage).
type ServerFinal struct {
	Signature []byte
	rfcStr    string
}

// ParseServerFinal parses "v=<signature>".
func ParseServerFinal(rfcStr string) (*ServerFinal, error) {
	if !strings.HasPrefix(rfcStr, "v=") {
		return nil, fmt.Errorf("scram: invalid server final message format: must start with \"v=\"")
	}
	signatureB64 := rfcStr[2:]
	if strings.Contains(signatureB64, ",") {
		return nil, fmt.Errorf("scram: invalid server final message format: unexpected additional attributes")
	}
	signature, err := b64.DecodeString(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("scram: invalid base64 encoding in server final message: %w", err)
	}
	return &ServerFinal{Signature: signature, rfcStr: rfcStr}, nil
}

// VerifyServerSignature checks that the server had access to ServerKey (RFC
// 5802 Section 3: ServerSignature := HMAC(ServerKey, AuthMessage)), providing
// mutual authentication. Returns nil on success.
func VerifyServerSignature(clientFirst *ClientFirst, serverFirst *ServerFirst,
	clientFinal *ClientFinal, serverFinal *ServerFinal, serverKey []byte) error {
	if len(serverFinal.Signature) == 0 {
		return fmt.Errorf("scram: server response lacks signature")
	}
	channelBindingB64 := encodeChannelBinding(clientFirst.gs2Header, clientFinal.channelBinding)
	message := authMessage(clientFirst, serverFirst, channelBindingB64, clientFinal.nonce)
	expected := hmacSHA512(serverKey, []byte(message))
	if !constantTimeEqual(expected, serverFinal.Signature) {
		return fmt.Errorf("scram: server signature verification failed")
	}
	return nil
}

// encodeChannelBinding builds the c= attribute: base64(gs2-header + ",," +
// [cbind-data]). Without binding data and with the default header this is
// base64("n,,") == "biws".
func encodeChannelBinding(gs2Header string, channelBinding []byte) string {
	if gs2Header == "" && len(channelBinding) == 0 {
		return gs2NoChannelBinding
	}
	hdr := gs2Header
	if hdr == "" {
		hdr = "n"
	}
	data := append([]byte(hdr+gs2Separator), channelBinding...)
	return b64.EncodeToString(data)
}

// authMessage builds the RFC 5802 AuthMessage.
func authMessage(clientFirst *ClientFirst, serverFirst *ServerFirst,
	channelBindingB64 string, nonce []byte) string {
	clientFinalNoProof := fmt.Sprintf("c=%s,r=%s", channelBindingB64, b64.EncodeToString(nonce))
	return clientFirst.bare() + "," + serverFirst.String() + "," + clientFinalNoProof
}

func splitAttr(part string) (key, value string, err error) {
	if part == "" {
		return "", "", fmt.Errorf("empty attribute")
	}
	key, value, found := strings.Cut(part, "=")
	if !found || value == "" {
		return "", "", fmt.Errorf("malformed attribute %q", part)
	}
	return key, value, nil
}
