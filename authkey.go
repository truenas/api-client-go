// SPDX-License-Identifier: LGPL-3.0-or-later

package truenas

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Raw API keys have the format {api_key_id}-{raw_key_material},
// e.g. "1-uz8DhKHFhRIUQIvjzabPYtpy5wf1DJ3ZBLlDgNVhRAFT7Y6pJGUlm0n3apwxWEU4".
var rawKeyPattern = regexp.MustCompile(`^\d+-[a-zA-Z0-9]+$`)

// keyMaterial is the parsed API-key material (ports KeyData /
// RawKeyData / PrecomputedKeyData).
type keyMaterial struct {
	// raw is the full "<id>-<key>" string when raw key material was
	// provided, empty for precomputed keys.
	raw string
	// rawSecret is the key material after the id prefix (used as the SCRAM
	// password).
	rawSecret string
	// apiKeyID identifies which of the user's API keys is used.
	apiKeyID int
	// Precomputed SCRAM keys, avoiding the expensive PBKDF2 computation
	// client-side. serverKey enables mutual authentication.
	clientKey []byte
	storedKey []byte
	serverKey []byte
}

// getKeyMaterial parses the user-provided key: either a string containing key
// info or an absolute path to a key file assumed to be JSON- or INI-formatted
// (ports get_key_material).
func getKeyMaterial(key string) (*keyMaterial, error) {
	if filepath.IsAbs(key) {
		content, err := os.ReadFile(key)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("Key file not found: %s", key)
			}
			if errors.Is(err, os.ErrPermission) {
				return nil, fmt.Errorf("Permission denied reading key file: %s", key)
			}
			return nil, fmt.Errorf("Error reading key file %s: %w", key, err)
		}
		key = strings.TrimSpace(string(content))
	} else {
		key = strings.TrimSpace(key)
	}

	if rawKeyPattern.MatchString(key) {
		return newRawKeyMaterial(key)
	}

	// Try parsing as structured data (JSON or INI format).
	data := map[string]any{}
	if jsonErr := json.Unmarshal([]byte(key), &data); jsonErr != nil {
		var iniErr error
		data, iniErr = parseINIKeyConfig(key)
		if iniErr != nil {
			return nil, fmt.Errorf("Key material must be either a raw API key (format: <id>-<key>), "+
				"valid JSON, or valid INI format. JSON error: %v. INI error: %v", jsonErr, iniErr)
		}
	}

	if rawValue, ok := data["raw_key"]; ok {
		rawKey, ok := rawValue.(string)
		if !ok {
			return nil, fmt.Errorf("raw_key must be a string, got %T", rawValue)
		}
		return newRawKeyMaterial(rawKey)
	}

	// Precomputed key material: all four fields are required.
	clientKey, err := requiredKeyString(data, "client_key")
	if err != nil {
		return nil, err
	}
	storedKey, err := requiredKeyString(data, "stored_key")
	if err != nil {
		return nil, err
	}
	serverKey, err := requiredKeyString(data, "server_key")
	if err != nil {
		return nil, err
	}
	apiKeyID, err := requiredKeyInt(data, "api_key_id")
	if err != nil {
		return nil, err
	}

	material := &keyMaterial{apiKeyID: apiKeyID}
	if material.clientKey, err = decodeBase64Key("client_key", clientKey); err != nil {
		return nil, err
	}
	if material.storedKey, err = decodeBase64Key("stored_key", storedKey); err != nil {
		return nil, err
	}
	if material.serverKey, err = decodeBase64Key("server_key", serverKey); err != nil {
		return nil, err
	}
	return material, nil
}

func newRawKeyMaterial(rawKey string) (*keyMaterial, error) {
	idStr, secret, found := strings.Cut(rawKey, "-")
	if !found {
		return nil, fmt.Errorf("invalid raw API key format (expected <id>-<key>)")
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return nil, fmt.Errorf("invalid API key id %q: %w", idStr, err)
	}
	return &keyMaterial{raw: rawKey, rawSecret: secret, apiKeyID: id}, nil
}

func requiredKeyString(data map[string]any, field string) (string, error) {
	value, ok := data[field]
	if !ok {
		return "", fmt.Errorf("Missing required field in key data: %q", field)
	}
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string, got %T", field, value)
	}
	return s, nil
}

func requiredKeyInt(data map[string]any, field string) (int, error) {
	value, ok := data[field]
	if !ok {
		return 0, fmt.Errorf("Missing required field in key data: %q", field)
	}
	switch v := value.(type) {
	case int:
		return v, nil
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("%s must be an int, got %v", field, v)
		}
		return int(v), nil
	default:
		return 0, fmt.Errorf("%s must be an int, got %T", field, value)
	}
}

// parseINIKeyConfig parses INI-formatted key data (ports _parse_ini_config,
// which uses Python's ConfigParser): section headers are required, keys are
// lower-cased, the [TRUENAS_API_KEY] section wins, a [DEFAULT] section or a
// single named section is accepted, and api_key_id is converted to an int.
func parseINIKeyConfig(content string) (map[string]any, error) {
	sections := map[string]map[string]string{}
	var order []string
	var current map[string]string

	for lineNo, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			if name == "" {
				return nil, fmt.Errorf("line %d: empty section name", lineNo+1)
			}
			if sections[name] == nil {
				sections[name] = map[string]string{}
				if name != "DEFAULT" {
					order = append(order, name)
				}
			}
			current = sections[name]
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			key, value, found = strings.Cut(line, ":")
		}
		if !found {
			return nil, fmt.Errorf("line %d: not a key/value pair: %q", lineNo+1, line)
		}
		if current == nil {
			return nil, fmt.Errorf("line %d: key/value pair before any section header", lineNo+1)
		}
		current[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}

	var selected map[string]string
	switch {
	case len(order) == 0:
		if sections["DEFAULT"] == nil {
			return nil, fmt.Errorf("no sections found")
		}
		selected = sections["DEFAULT"]
	case sections["TRUENAS_API_KEY"] != nil:
		selected = sections["TRUENAS_API_KEY"]
	case len(order) == 1:
		selected = sections[order[0]]
	default:
		return nil, fmt.Errorf("Multiple sections found but [TRUENAS_API_KEY] not present. "+
			"Available sections: %v", order)
	}

	result := make(map[string]any, len(selected))
	for k, v := range selected {
		result[k] = v
	}
	if idStr, ok := result["api_key_id"].(string); ok {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return nil, fmt.Errorf("invalid api_key_id %q: %w", idStr, err)
		}
		result["api_key_id"] = id
	}
	return result, nil
}
