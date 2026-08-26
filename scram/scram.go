// SPDX-License-Identifier: LGPL-3.0-or-later

// Package scram implements the client side of the SCRAM-SHA-512 (RFC 5802)
// authentication exchange used by TrueNAS servers, including the RFC 5929
// tls-server-end-point channel binding.
//
// This is a Go port of the client-side subset of truenas_api_client's
// py_scram package (itself a pure-Python mirror of the truenas_scram C
// library).
package scram

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
)

// Constants from truenas_scram.h.
const (
	MaxIters    = 5000000
	MinIters    = 50000
	NonceSize   = 32
	MaxSaltSize = 1024 // salt length cap enforced by the C parser
	DigestSize  = sha512.Size

	gs2Separator = ",,"
	// base64 of "n,,": the c= value of an exchange without channel binding.
	gs2NoChannelBinding = "biws"
)

// CBTLSServerEndPoint is the RFC 5929 channel-binding type name (the
// "cb-name" in a "p=" gs2 flag).
const CBTLSServerEndPoint = "tls-server-end-point"

// AuthData holds the client-side keys derived from a salted password
// (ports ScramAuthData).
type AuthData struct {
	SaltedPassword []byte
	ClientKey      []byte
	StoredKey      []byte
	ServerKey      []byte
}

func generateNonce() []byte {
	nonce := make([]byte, NonceSize)
	rand.Read(nonce) // crypto/rand.Read never fails as of Go 1.24
	return nonce
}

// Hi implements Hi(str, salt, i) from RFC 5802 Section 2.2:
// PBKDF2-HMAC-SHA-512 key derivation.
func Hi(key, salt []byte, iterations int) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("scram: empty key")
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("scram: empty salt")
	}
	if iterations < MinIters || iterations > MaxIters {
		return nil, fmt.Errorf("scram: iterations must be between %d and %d", MinIters, MaxIters)
	}
	return pbkdf2.Key(sha512.New, string(key), salt, iterations, DigestSize)
}

// h implements H(str) from RFC 5802 Section 2.2 (SHA-512).
func h(data []byte) []byte {
	digest := sha512.Sum512(data)
	return digest[:]
}

func hmacSHA512(key, data []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("scram: byte array sizes do not match")
	}
	out := make([]byte, len(a))
	subtle.XORBytes(out, a, b)
	return out, nil
}

func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// GenerateAuthData derives the SCRAM keys from a salted password (ports
// generate_scram_auth_data):
//
//	ClientKey := HMAC(SaltedPassword, "Client Key")
//	StoredKey := H(ClientKey)
//	ServerKey := HMAC(SaltedPassword, "Server Key")
func GenerateAuthData(saltedPassword []byte) *AuthData {
	clientKey := hmacSHA512(saltedPassword, []byte("Client Key"))
	return &AuthData{
		SaltedPassword: saltedPassword,
		ClientKey:      clientKey,
		StoredKey:      h(clientKey),
		ServerKey:      hmacSHA512(saltedPassword, []byte("Server Key")),
	}
}
