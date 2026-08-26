// SPDX-License-Identifier: LGPL-3.0-or-later

package ejson

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// DateTime wraps time.Time so that struct fields encode as
// {"$date": <milliseconds since epoch>}. The encoding is second-granular:
// sub-second precision is dropped, matching the Python client.
type DateTime time.Time

func (d DateTime) MarshalJSON() ([]byte, error) {
	ms := time.Time(d).UTC().Unix() * 1000
	return json.Marshal(map[string]int64{"$date": ms})
}

func (d *DateTime) UnmarshalJSON(data []byte) error {
	var obj struct {
		Date *int64 `json:"$date"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	if obj.Date == nil {
		return &DecodeError{Key: "$date", Err: fmt.Errorf("missing $date key")}
	}
	revived, err := reviveDate("$date", json.Number(fmt.Sprintf("%d", *obj.Date)))
	if err != nil {
		return err
	}
	*d = DateTime(revived.(time.Time))
	return nil
}

// Time returns the wrapped time.Time.
func (d DateTime) Time() time.Time { return time.Time(d) }

// Date is a calendar date without a time component, encoded as
// {"$type": "date", "$value": "YYYY-MM-DD"}.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// ParseDate parses a "YYYY-MM-DD" string.
func ParseDate(s string) (Date, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return Date{}, err
	}
	return Date{Year: t.Year(), Month: t.Month(), Day: t.Day()}, nil
}

func (d Date) String() string {
	return fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day)
}

func (d Date) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"$type": "date", "$value": d.String()})
}

func (d *Date) UnmarshalJSON(data []byte) error {
	var obj struct {
		Type  string `json:"$type"`
		Value string `json:"$value"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	if obj.Type != "date" {
		return &DecodeError{Key: "date", Err: fmt.Errorf("$type is %q, not \"date\"", obj.Type)}
	}
	parsed, err := ParseDate(obj.Value)
	if err != nil {
		return &DecodeError{Key: "date", Err: err}
	}
	*d = parsed
	return nil
}

// Time is a time of day with optional UTC offset, encoded as
// {"$time": "HH:MM:SS[.ffffff][±HH:MM]"} (ISO 8601, as produced by Python's
// str(datetime.time)).
type Time struct {
	Hour       int
	Minute     int
	Second     int
	Nanosecond int
	// HasOffset reports whether the time carries a UTC offset (Python's
	// tzinfo). Offset is seconds east of UTC and is only meaningful when
	// HasOffset is true.
	HasOffset bool
	Offset    int
}

// ParseTime parses an ISO 8601 time-of-day string such as "16:22:06",
// "16:22:06.500000" or "16:22:06+00:00".
func ParseTime(s string) (Time, error) {
	rest := s
	var t Time

	// Split off a UTC offset, if any ("Z", "+HH:MM[:SS]", "-HH:MM[:SS]").
	if strings.HasSuffix(rest, "Z") {
		t.HasOffset = true
		rest = strings.TrimSuffix(rest, "Z")
	} else if idx := strings.IndexAny(rest, "+-"); idx > 0 {
		off, err := parseOffset(rest[idx:])
		if err != nil {
			return Time{}, err
		}
		t.HasOffset = true
		t.Offset = off
		rest = rest[:idx]
	}

	var frac string
	if idx := strings.IndexByte(rest, '.'); idx >= 0 {
		rest, frac = rest[:idx], rest[idx+1:]
	}

	if _, err := fmt.Sscanf(rest, "%02d:%02d:%02d", &t.Hour, &t.Minute, &t.Second); err != nil {
		// Python also allows "HH:MM".
		if _, err2 := fmt.Sscanf(rest, "%02d:%02d", &t.Hour, &t.Minute); err2 != nil {
			return Time{}, fmt.Errorf("invalid time %q: %v", s, err)
		}
	}
	if t.Hour > 23 || t.Minute > 59 || t.Second > 59 {
		return Time{}, fmt.Errorf("invalid time %q: component out of range", s)
	}
	if frac != "" {
		if len(frac) > 9 {
			frac = frac[:9]
		}
		var ns int
		if _, err := fmt.Sscanf(frac, "%d", &ns); err != nil {
			return Time{}, fmt.Errorf("invalid time %q: bad fraction", s)
		}
		for i := len(frac); i < 9; i++ {
			ns *= 10
		}
		t.Nanosecond = ns
	}
	return t, nil
}

func parseOffset(s string) (int, error) {
	sign := 1
	if s[0] == '-' {
		sign = -1
	}
	var h, m int
	if _, err := fmt.Sscanf(s[1:], "%02d:%02d", &h, &m); err != nil {
		return 0, fmt.Errorf("invalid UTC offset %q", s)
	}
	return sign * (h*3600 + m*60), nil
}

func (t Time) String() string {
	s := fmt.Sprintf("%02d:%02d:%02d", t.Hour, t.Minute, t.Second)
	if t.Nanosecond != 0 {
		// Python formats microsecond precision.
		s += fmt.Sprintf(".%06d", t.Nanosecond/1000)
	}
	if t.HasOffset {
		off := t.Offset
		sign := "+"
		if off < 0 {
			sign = "-"
			off = -off
		}
		s += fmt.Sprintf("%s%02d:%02d", sign, off/3600, (off%3600)/60)
	}
	return s
}

func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"$time": t.String()})
}

func (t *Time) UnmarshalJSON(data []byte) error {
	var obj struct {
		Time *string `json:"$time"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	if obj.Time == nil {
		return &DecodeError{Key: "$time", Err: fmt.Errorf("missing $time key")}
	}
	parsed, err := ParseTime(*obj.Time)
	if err != nil {
		return &DecodeError{Key: "$time", Err: err}
	}
	*t = parsed
	return nil
}

// Set encodes as {"$set": [items...]}. Element order is preserved on this
// side but is undefined in data produced by the Python client.
type Set []any

func (s Set) MarshalJSON() ([]byte, error) {
	items := []any(s)
	if items == nil {
		items = []any{}
	}
	return json.Marshal(map[string][]any{"$set": items})
}

func (s *Set) UnmarshalJSON(data []byte) error {
	var obj struct {
		Set *[]any `json:"$set"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	if obj.Set == nil {
		return &DecodeError{Key: "$set", Err: fmt.Errorf("missing $set key")}
	}
	*s = Set(*obj.Set)
	return nil
}

// prefixValue wraps netip.Prefix to encode as $ipv4_interface/$ipv6_interface.
type prefixValue netip.Prefix

func (p prefixValue) MarshalJSON() ([]byte, error) {
	pfx := netip.Prefix(p)
	key := "$ipv6_interface"
	if pfx.Addr().Is4() {
		key = "$ipv4_interface"
	}
	return json.Marshal(map[string]string{key: pfx.String()})
}
