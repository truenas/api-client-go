// SPDX-License-Identifier: LGPL-3.0-or-later

package truenas

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/truenas/api-client-go/scram"
)

// APIKeyAuthMech selects the API-key authentication mechanism.
type APIKeyAuthMech string

const (
	// AuthMechSCRAM is SCRAM-SHA-512 (default); never transmits the API key
	// in plaintext.
	AuthMechSCRAM APIKeyAuthMech = "SCRAM"
	// AuthMechPlain is an explicit opt-in that transmits the raw API key
	// (only TLS protects it).
	AuthMechPlain APIKeyAuthMech = "PLAIN"
)

// Authentication mechanism / response type wire constants.
const (
	mechanismSCRAM       = "SCRAM"
	mechanismAPIKeyPlain = "API_KEY_PLAIN"
	responseTypeSCRAM    = "SCRAM_RESPONSE"
	responseTypeAuthErr  = "AUTH_ERR"
)

// APIKeyOptions configures LoginWithAPIKey. The zero value selects SCRAM with
// channel binding, the most secure configuration.
type APIKeyOptions struct {
	// Mechanism is AuthMechSCRAM (default) or AuthMechPlain. SCRAM (TrueNAS
	// 26+) never transmits the key over the wire. PLAIN sends the raw API
	// key (protected only by TLS) and must be selected explicitly -- it is
	// required to reach a server that does not support SCRAM (before
	// TrueNAS 26). The client never auto-downgrades to PLAIN: choosing it
	// from the server's unauthenticated advertised mechanisms would let a
	// man-in-the-middle strip SCRAM and harvest the cleartext key.
	Mechanism APIKeyAuthMech
	// DisableChannelBinding authenticates with SCRAM but without binding
	// the exchange to the server's TLS certificate. By default SCRAM binds
	// the exchange (SCRAM-PLUS, RFC 5929 tls-server-end-point) and fails if
	// binding cannot be negotiated -- i.e. on a non-TLS network transport,
	// or against a SCRAM backend too old to compute the binding. The local
	// UNIX socket is exempt. Required over a plain ws:// connection or
	// against a server that supports SCRAM but not channel binding. Ignored
	// for PLAIN authentication.
	DisableChannelBinding bool
}

// LoginWithAPIKey authenticates via API key (ports login_with_api_key /
// api_key_authenticate).
//
// username is the name of the user the API key is associated with (required
// for SCRAM). key is either the key material or an absolute path to the file
// where it is stored. opts may be nil for the defaults (SCRAM with channel
// binding).
func (c *Client) LoginWithAPIKey(username, key string, opts *APIKeyOptions) error {
	var o APIKeyOptions
	if opts != nil {
		o = *opts
	}
	if o.Mechanism == "" {
		o.Mechanism = AuthMechSCRAM
	}
	if key == "" {
		return errors.New("API key is required")
	}

	keyData, err := getKeyMaterial(key)
	if err != nil {
		return err
	}

	availableMechanisms, err := c.mechanismChoices()
	if err != nil {
		return err
	}

	switch o.Mechanism {
	case AuthMechPlain:
		if keyData.raw == "" {
			return errors.New("Raw API key is required in order to do legacy API key authentication")
		}
		if username == "" {
			return errors.New("username is required for plain API key authentication")
		}
		resp, err := c.Call("auth.login_ex", map[string]any{
			"mechanism": mechanismAPIKeyPlain,
			"username":  username,
			"api_key":   keyData.raw,
		})
		if err != nil {
			return err
		}
		return checkAPIKeyResponse(asMap(resp))

	case AuthMechSCRAM:
		// SCRAM is the default and never transmits the key in plaintext. We
		// deliberately do NOT auto-fall-back to PLAIN when the server omits
		// SCRAM: auth.mechanism_choices is unauthenticated, so a MITM that
		// strips SCRAM from it could otherwise force a silent downgrade and
		// harvest the cleartext key.
		if !contains(availableMechanisms, mechanismSCRAM) {
			return errors.New("SCRAM authentication is not supported on the remote server; " +
				"select AuthMechPlain to authenticate with a plaintext API key")
		}
		if username == "" {
			return errors.New("username is required for SCRAM authentication")
		}
		return c.scramAuthenticate(username, keyData, !o.DisableChannelBinding)

	default:
		return fmt.Errorf("%s: unknown authentication mechanism", o.Mechanism)
	}
}

// mechanismChoices fetches the server's advertised authentication mechanisms,
// tolerating servers that predate auth.mechanism_choices (or carry the
// 25.04.2-25.10.2 backend bug that breaks the unauthenticated call): both
// mean SCRAM is unsupported, so API-key auth falls back to PLAIN-only.
func (c *Client) mechanismChoices() ([]string, error) {
	resp, err := c.Call("auth.mechanism_choices")
	if err != nil {
		var clientErr *ClientError
		if errors.As(err, &clientErr) {
			if clientErr.Reason == "Method does not exist" ||
				strings.Contains(clientErr.Reason, "'NoneType' object has no attribute 'may_create_auth_token'") {
				return []string{mechanismAPIKeyPlain}, nil
			}
		}
		return nil, err
	}
	items, _ := resp.([]any)
	mechanisms := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			mechanisms = append(mechanisms, s)
		}
	}
	return mechanisms, nil
}

// scramAuthenticate runs the SCRAM-SHA-512 exchange over auth.login_ex.
func (c *Client) scramAuthenticate(username string, keyData *keyMaterial, channelBinding bool) error {
	binding, err := c.resolveChannelBinding(channelBinding)
	if err != nil {
		return err
	}
	cbType := ""
	if binding != nil {
		cbType = scram.CBTLSServerEndPoint
	}

	clientFirst, err := scram.NewClientFirst(username, keyData.apiKeyID, cbType)
	if err != nil {
		return err
	}

	// Send our first client SCRAM message: client nonce plus the key
	// identifier being used server-side.
	resp, err := c.Call("auth.login_ex", map[string]any{
		"mechanism":  mechanismSCRAM,
		"scram_type": "CLIENT_FIRST_MESSAGE",
		"rfc_str":    clientFirst.String(),
	})
	if err != nil {
		return err
	}
	rfcStr, err := scramResponse(asMap(resp), "SERVER_FIRST_RESPONSE", "Invalid API key")
	if err != nil {
		return err
	}
	serverFirst, err := scram.ParseServerFirst(rfcStr)
	if err != nil {
		return err
	}

	clientKey, storedKey, serverKey := keyData.clientKey, keyData.storedKey, keyData.serverKey
	if keyData.raw != "" {
		// Compute the salted password (expensive PBKDF2) and derive keys;
		// precomputed key material skips this.
		salted, err := scram.Hi([]byte(keyData.rawSecret), serverFirst.Salt, serverFirst.Iterations)
		if err != nil {
			return err
		}
		auth := scram.GenerateAuthData(salted)
		clientKey, storedKey = auth.ClientKey, auth.StoredKey
		if serverKey == nil {
			serverKey = auth.ServerKey
		}
	}

	clientFinal, err := scram.NewClientFinal(clientFirst, serverFirst, clientKey, storedKey, binding)
	if err != nil {
		return err
	}

	// Send our client SCRAM final message with the client proof.
	resp, err = c.Call("auth.login_ex", map[string]any{
		"mechanism":  mechanismSCRAM,
		"scram_type": "CLIENT_FINAL_MESSAGE",
		"rfc_str":    clientFinal.String(),
	})
	if err != nil {
		return err
	}
	rfcStr, err = scramResponse(asMap(resp), "SERVER_FINAL_RESPONSE", "Failed to authenticate with API key")
	if err != nil {
		return err
	}
	serverFinal, err := scram.ParseServerFinal(rfcStr)
	if err != nil {
		return err
	}

	// Validate the server final message: mutual authentication.
	if err := scram.VerifyServerSignature(clientFirst, serverFirst, clientFinal, serverFinal, serverKey); err != nil {
		// Attempt to logout, but don't mask the original verification error.
		c.Call("auth.logout") //nolint:errcheck
		return fmt.Errorf("Remote server validation failed! %w", err)
	}
	return nil
}

// scramResponse validates a SCRAM auth.login_ex response and returns its
// rfc_str.
func scramResponse(resp map[string]any, wantScramType, authErrMsg string) (string, error) {
	respType, _ := resp["response_type"].(string)
	switch respType {
	case responseTypeAuthErr:
		return "", errors.New(authErrMsg)
	case responseTypeSCRAM:
	default:
		return "", fmt.Errorf("%s: unexpected server response", respType)
	}
	scramType, _ := resp["scram_type"].(string)
	if scramType != wantScramType {
		return "", fmt.Errorf("%s: unexpected response type", scramType)
	}
	rfcStr, _ := resp["rfc_str"].(string)
	return rfcStr, nil
}

// resolveChannelBinding resolves the SCRAM channel binding for the current
// connection (ports _resolve_channel_binding): the RFC 5929
// tls-server-end-point binding for a TLS (wss://) connection, or nil for an
// unbound exchange. The local UNIX socket is exempt from the required=true
// policy, since channel binding is meaningless for local IPC; any other
// non-TLS transport cannot satisfy the requirement and errors.
func (c *Client) resolveChannelBinding(required bool) ([]byte, error) {
	if !required {
		return nil, nil
	}
	if certDER := peerCertificateDER(c.conn); certDER != nil {
		return scram.ComputeTLSServerEndPoint(certDER)
	}
	if strings.HasPrefix(c.url, UnixSocketPrefix) {
		return nil, nil
	}
	return nil, errors.New("channel binding is required but the connection is not TLS (wss://); " +
		"set DisableChannelBinding to authenticate without it")
}

// checkAPIKeyResponse maps non-SUCCESS API_KEY_PLAIN responses to errors
// (ports _raise_for_api_key_response).
func checkAPIKeyResponse(resp map[string]any) error {
	respType, _ := resp["response_type"].(string)
	switch respType {
	case "SUCCESS":
		return nil
	case "AUTH_ERR":
		return errors.New("Invalid API key")
	case "EXPIRED":
		return errors.New("API key has expired")
	case "DENIED":
		return errors.New("Account does not have API access")
	case "REDIRECT":
		return fmt.Errorf("Authentication must be performed on active storage controller. "+
			"Redirect URLs: %s", redirectURLs(resp))
	default:
		return fmt.Errorf("%s: unexpected server response", respType)
	}
}

// LoginWithPassword authenticates via username and password (ports
// login_with_password). Uses auth.login_ex with the PASSWORD_PLAIN mechanism,
// falling back to auth.login for pre-25.04 TrueNAS servers. otpToken is the
// one-time password for two-factor authentication ("" if not used).
func (c *Client) LoginWithPassword(username, password, otpToken string) error {
	resp, err := c.Call("auth.login_ex", map[string]any{
		"mechanism": "PASSWORD_PLAIN",
		"username":  username,
		"password":  password,
	})
	if err != nil {
		var clientErr *ClientError
		if errors.As(err, &clientErr) && clientErr.Reason == "Method does not exist" {
			// Pre-25.04 server.
			var otp any
			if otpToken != "" {
				otp = otpToken
			}
			result, err := c.Call("auth.login", username, password, otp)
			if err != nil {
				return err
			}
			if ok, _ := result.(bool); !ok {
				return errors.New("Invalid username or password")
			}
			return nil
		}
		return err
	}
	return c.handleLoginExResponse(asMap(resp), otpToken)
}

func (c *Client) handleLoginExResponse(resp map[string]any, otpToken string) error {
	respType, _ := resp["response_type"].(string)
	switch respType {
	case "SUCCESS":
		return nil
	case "OTP_REQUIRED":
		if otpToken == "" {
			return errors.New("Two-factor authentication is required for this account. " +
				"Call LoginWithPassword again with otpToken specified.")
		}
		otpResp, err := c.Call("auth.login_ex_continue", map[string]any{
			"mechanism": "OTP_TOKEN",
			"otp_token": otpToken,
		})
		if err != nil {
			return err
		}
		return c.handleLoginExResponse(asMap(otpResp), "")
	case "REDIRECT":
		return fmt.Errorf("Authentication must be performed on active storage controller. "+
			"Redirect URLs: %s", redirectURLs(resp))
	case "EXPIRED":
		return errors.New("Account credentials have expired")
	case "DENIED":
		return errors.New("Account does not have API access")
	default:
		return errors.New("Invalid username or password")
	}
}

func redirectURLs(resp map[string]any) string {
	items, _ := resp["urls"].([]any)
	urls := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			urls = append(urls, s)
		}
	}
	return strings.Join(urls, ", ")
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// decodeBase64Key decodes a base64 key field from precomputed key material.
func decodeBase64Key(field, value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in %s: %w", field, err)
	}
	return decoded, nil
}
