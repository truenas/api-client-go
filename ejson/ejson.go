// SPDX-License-Identifier: LGPL-3.0-or-later

// Package ejson implements the extended JSON encoding used by the TrueNAS
// middleware API.
//
// In addition to the standard JSON types, the following values are supported:
//
//	Go                JSON
//	----------------  -------------------------------------------------
//	time.Time         {"$date": <milliseconds since epoch>}
//	ejson.Date        {"$type": "date", "$value": "YYYY-MM-DD"}
//	ejson.Time        {"$time": "HH:MM:SS[.ffffff][+HH:MM]"}
//	ejson.Set         {"$set": [items...]}
//	netip.Prefix      {"$ipv4_interface": "a.b.c.d/n"} or
//	                  {"$ipv6_interface": "x::y/n"}
//
// This mirrors truenas_api_client/ejson.py. Note that the $date encoding is
// second-granular: sub-second precision is dropped on encode, matching the
// Python client.
package ejson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

// DecodeError is returned when a $-prefixed extended value cannot be parsed.
type DecodeError struct {
	Key string
	Err error
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("ejson: error parsing %s: %v", e.Key, e.Err)
}

func (e *DecodeError) Unwrap() error { return e.Err }

// Marshal encodes v as extended JSON. Values of type time.Time, Date, Time,
// Set and netip.Prefix are converted to their $-prefixed representations,
// including when nested inside maps and slices. Other values are encoded with
// encoding/json as usual.
func Marshal(v any) ([]byte, error) {
	return json.Marshal(transform(v))
}

// transform recursively replaces extended types with json.Marshaler wrappers.
func transform(v any) any {
	switch val := v.(type) {
	case time.Time:
		return DateTime(val)
	case *time.Time:
		if val == nil {
			return nil
		}
		return DateTime(*val)
	case netip.Prefix:
		return prefixValue(val)
	case Set:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = transform(item)
		}
		return map[string]any{"$set": out}
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			out[k] = transform(item)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = transform(item)
		}
		return out
	default:
		return v
	}
}

// Unmarshal decodes extended JSON into Go values: objects become
// map[string]any, arrays []any, numbers int64 or float64, and the $-prefixed
// extended representations become time.Time, Date, Time, Set and netip.Prefix
// respectively.
func Unmarshal(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	// Reject trailing garbage after the first JSON value.
	if dec.More() {
		return nil, fmt.Errorf("ejson: unexpected data after JSON value")
	}
	return revive(raw)
}

func revive(v any) (any, error) {
	switch val := v.(type) {
	case json.Number:
		if i, err := val.Int64(); err == nil {
			return i, nil
		}
		f, err := val.Float64()
		if err != nil {
			return nil, fmt.Errorf("ejson: invalid number %q", val.String())
		}
		return f, nil
	case []any:
		for i, item := range val {
			revived, err := revive(item)
			if err != nil {
				return nil, err
			}
			val[i] = revived
		}
		return val, nil
	case map[string]any:
		return reviveObject(val)
	default:
		return v, nil
	}
}

func reviveObject(obj map[string]any) (any, error) {
	if len(obj) == 1 {
		for key, raw := range obj {
			switch key {
			case "$date":
				return reviveDate(key, raw)
			case "$time":
				return reviveTime(key, raw)
			case "$set":
				return reviveSet(raw)
			case "$ipv4_interface", "$ipv6_interface":
				return revivePrefix(key, raw)
			}
		}
	}
	if len(obj) == 2 {
		if typ, ok := obj["$type"].(string); ok && typ == "date" {
			if value, ok := obj["$value"]; ok {
				s, ok := value.(string)
				if !ok {
					return nil, &DecodeError{Key: "date", Err: fmt.Errorf("$value is not a string")}
				}
				d, err := ParseDate(s)
				if err != nil {
					return nil, &DecodeError{Key: "date", Err: err}
				}
				return d, nil
			}
		}
	}
	for k, item := range obj {
		revived, err := revive(item)
		if err != nil {
			return nil, err
		}
		obj[k] = revived
	}
	return obj, nil
}

func reviveDate(key string, raw any) (any, error) {
	num, ok := raw.(json.Number)
	if !ok {
		return nil, &DecodeError{Key: key, Err: fmt.Errorf("value is not a number")}
	}
	ms, err := num.Int64()
	if err != nil {
		return nil, &DecodeError{Key: key, Err: err}
	}
	// Floor-divide for whole seconds; the remainder is added as milliseconds
	// (matches the Python decoder, including for pre-epoch values).
	sec, rem := ms/1000, ms%1000
	if rem < 0 {
		sec--
		rem += 1000
	}
	return time.Unix(sec, rem*int64(time.Millisecond)).UTC(), nil
}

func reviveTime(key string, raw any) (any, error) {
	s, ok := raw.(string)
	if !ok {
		return nil, &DecodeError{Key: key, Err: fmt.Errorf("value is not a string")}
	}
	t, err := ParseTime(s)
	if err != nil {
		return nil, &DecodeError{Key: key, Err: err}
	}
	return t, nil
}

func reviveSet(raw any) (any, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, &DecodeError{Key: "$set", Err: fmt.Errorf("value is not an array")}
	}
	set := make(Set, len(items))
	for i, item := range items {
		revived, err := revive(item)
		if err != nil {
			return nil, err
		}
		set[i] = revived
	}
	return set, nil
}

func revivePrefix(key string, raw any) (any, error) {
	s, ok := raw.(string)
	if !ok {
		return nil, &DecodeError{Key: key, Err: fmt.Errorf("value is not a string")}
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return nil, &DecodeError{Key: key, Err: err}
	}
	return p, nil
}
