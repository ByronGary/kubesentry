package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseDuration is time.ParseDuration that also takes days: "30d", "1d12h".
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	var days time.Duration
	if i := strings.IndexByte(s, 'd'); i >= 0 {
		n, err := strconv.ParseFloat(s[:i], 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		days = time.Duration(n * float64(24*time.Hour))
		s = s[i+1:]
		if s == "" {
			return days, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: use e.g. 90m, 24h or 30d", s)
	}
	if days > 0 && d < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return days + d, nil
}

// durationValue is a flag.Value for durations with a day unit.
type durationValue time.Duration

func (d *durationValue) String() string {
	if d == nil {
		return ""
	}
	return formatDuration(time.Duration(*d))
}

func (d *durationValue) Set(s string) error {
	v, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = durationValue(v)
	return nil
}

// formatDuration prints whole days as "30d" and everything else as Go does.
func formatDuration(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	}
	return d.String()
}

// optionalFloat is a flag.Value that remembers whether it was set.
type optionalFloat struct {
	v   float64
	set bool
}

func (o *optionalFloat) String() string {
	if o == nil || !o.set {
		return ""
	}
	return strconv.FormatFloat(o.v, 'f', -1, 64)
}

func (o *optionalFloat) Set(s string) error {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f < 0 {
		return fmt.Errorf("invalid price %q", s)
	}
	o.v, o.set = f, true
	return nil
}

// ptr returns the value, or nil when the flag was not set.
func (o *optionalFloat) ptr() *float64 {
	if !o.set {
		return nil
	}
	v := o.v
	return &v
}

// listValue is a comma-separated flag; set remembers whether it was given.
type listValue struct {
	items []string
	set   bool
}

func newList(def ...string) *listValue { return &listValue{items: def} }

func (l *listValue) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(l.items, ",")
}

func (l *listValue) Set(s string) error {
	l.items, l.set = splitList(s), true
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// parsePrices reads "name=price,..." into a map; empty input is an empty map.
func parsePrices(s string) (map[string]float64, error) {
	out := map[string]float64{}
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("entry %q: want name=price", part)
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || f < 0 {
			return nil, fmt.Errorf("entry %q: invalid price", part)
		}
		out[strings.TrimSpace(k)] = f
	}
	return out, nil
}
