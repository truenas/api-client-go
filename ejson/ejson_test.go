// SPDX-License-Identifier: LGPL-3.0-or-later

// ejson round-trips its supported types, and decodes $date without
// double-counting sub-second milliseconds (ports tests/test_ejson.py).
package ejson

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func roundTrip(t *testing.T, v any) any {
	t.Helper()
	data, err := Marshal(v)
	if err != nil {
		t.Fatalf("Marshal(%v): %v", v, err)
	}
	out, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal(%s): %v", data, err)
	}
	return out
}

func TestRoundTripDate(t *testing.T) {
	v := Date{Year: 2024, Month: time.July, Day: 3}
	if got := roundTrip(t, v); got != v {
		t.Errorf("got %v, want %v", got, v)
	}
}

func TestRoundTripDateTime(t *testing.T) {
	// The encoder is second-granular (drops sub-second), so round-trip a
	// whole-second value.
	v := time.Date(2024, time.July, 3, 16, 22, 6, 0, time.UTC)
	if got := roundTrip(t, v); !got.(time.Time).Equal(v) {
		t.Errorf("got %v, want %v", got, v)
	}
}

func TestRoundTripTime(t *testing.T) {
	v := Time{Hour: 16, Minute: 22, Second: 6}
	if got := roundTrip(t, v); got != v {
		t.Errorf("got %v, want %v", got, v)
	}
}

func TestRoundTripTimeWithMicroseconds(t *testing.T) {
	v := Time{Hour: 16, Minute: 22, Second: 6, Nanosecond: 500000000}
	if got := roundTrip(t, v); got != v {
		t.Errorf("got %v, want %v", got, v)
	}
}

func TestRoundTripTimeWithUTCOffset(t *testing.T) {
	v := Time{Hour: 16, Minute: 22, Second: 6, HasOffset: true, Offset: 0}
	if got := roundTrip(t, v); got != v {
		t.Errorf("got %v, want %v", got, v)
	}
}

func TestRoundTripSet(t *testing.T) {
	v := Set{int64(1), int64(2), int64(3), "a"}
	if got := roundTrip(t, v); !reflect.DeepEqual(got, v) {
		t.Errorf("got %v, want %v", got, v)
	}
}

func TestRoundTripIPv4Interface(t *testing.T) {
	v := netip.MustParsePrefix("192.168.1.10/24")
	if got := roundTrip(t, v); got != v {
		t.Errorf("got %v, want %v", got, v)
	}
}

func TestRoundTripIPv6Interface(t *testing.T) {
	v := netip.MustParsePrefix("2001:db8::1/64")
	if got := roundTrip(t, v); got != v {
		t.Errorf("got %v, want %v", got, v)
	}
}

func TestRoundTripNested(t *testing.T) {
	v := map[string]any{
		"when":  time.Date(2024, time.July, 3, 16, 22, 6, 0, time.UTC),
		"items": []any{Set{"a"}, int64(5)},
	}
	got := roundTrip(t, v).(map[string]any)
	if !got["when"].(time.Time).Equal(v["when"].(time.Time)) {
		t.Errorf("when: got %v", got["when"])
	}
	if !reflect.DeepEqual(got["items"], v["items"]) {
		t.Errorf("items: got %v, want %v", got["items"], v["items"])
	}
}

// $date decodes milliseconds since epoch without double-counting the
// sub-second part.
func TestDateDecodeSubsecondMilliseconds(t *testing.T) {
	got, err := Unmarshal([]byte(`{"$date": 1500}`))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(1970, 1, 1, 0, 0, 1, 500000000, time.UTC)
	if !got.(time.Time).Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestDateDecodeWholeSeconds(t *testing.T) {
	got, err := Unmarshal([]byte(`{"$date": 2000}`))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(1970, 1, 1, 0, 0, 2, 0, time.UTC)
	if !got.(time.Time).Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestDateDecodePreEpoch(t *testing.T) {
	got, err := Unmarshal([]byte(`{"$date": -500}`))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(1969, 12, 31, 23, 59, 59, 500000000, time.UTC)
	if !got.(time.Time).Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPlainObjectPassthrough(t *testing.T) {
	got, err := Unmarshal([]byte(`{"a": 1, "b": [true, null, "x"], "c": 1.5}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"a": int64(1),
		"b": []any{true, nil, "x"},
		"c": 1.5,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestDecodeErrorOnBadExtendedValue(t *testing.T) {
	for _, data := range []string{
		`{"$date": "nope"}`,
		`{"$time": "not a time"}`,
		`{"$ipv4_interface": "bogus"}`,
		`{"$type": "date", "$value": "07-03-2024"}`,
	} {
		if _, err := Unmarshal([]byte(data)); err == nil {
			t.Errorf("Unmarshal(%s): expected error, got nil", data)
		}
	}
}

// Objects with a $-key plus other keys, or unknown $type values, pass through
// untouched (same as the Python object_hook).
func TestNonSpecialDollarKeys(t *testing.T) {
	got, err := Unmarshal([]byte(`{"$date": 1000, "other": 1}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"$date": int64(1000), "other": int64(1)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}
