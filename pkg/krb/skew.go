// Package krb provides shared Kerberos helpers for operator and implant paths
// (clock skew preflight, later AES TGT / S4U / KeyList).
package krb

import (
	"fmt"
	"math"
	"time"
)

// DefaultMaxSkew is the typical Kerberos 5-minute tolerance window.
const DefaultMaxSkew = 5 * time.Minute

// SkewResult is the comparison of local clock vs KDC/DC time.
type SkewResult struct {
	LocalUTC  time.Time
	RemoteUTC time.Time
	// Delta is Remote - Local (positive => remote is ahead of local).
	Delta time.Duration
	// MaxSkew is the allowed absolute delta (default 5m if zero when checking).
	MaxSkew time.Duration
}

// AbsDelta returns |Remote - Local|.
func (s SkewResult) AbsDelta() time.Duration {
	if s.Delta < 0 {
		return -s.Delta
	}
	return s.Delta
}

// OK reports whether |delta| is within maxSkew (DefaultMaxSkew if MaxSkew is 0).
func (s SkewResult) OK() bool {
	max := s.MaxSkew
	if max <= 0 {
		max = DefaultMaxSkew
	}
	return s.AbsDelta() <= max
}

// Compare computes Remote - Local with optional maxSkew (0 => DefaultMaxSkew for OK()).
func Compare(local, remote time.Time, maxSkew time.Duration) SkewResult {
	return SkewResult{
		LocalUTC:  local.UTC(),
		RemoteUTC: remote.UTC(),
		Delta:     remote.UTC().Sub(local.UTC()),
		MaxSkew:   maxSkew,
	}
}

// ParseLDAPGeneralizedTime parses LDAP GeneralizedTime (YYYYMMDDHHmmss.0Z or without fraction).
func ParseLDAPGeneralizedTime(s string) (time.Time, error) {
	s = trimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty generalized time")
	}
	// Common AD forms: 20260808104210.0Z or 20260808104210Z
	layouts := []string{
		"20060102150405.0Z",
		"20060102150405Z",
		"20060102150405.000Z",
		time.RFC3339,
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized generalized time %q", s)
}

// FormatDelta humanizes a signed duration for operator output.
func FormatDelta(d time.Duration) string {
	sign := "+"
	if d < 0 {
		sign = "-"
		d = -d
	}
	sec := int64(math.Round(d.Seconds()))
	if sec < 60 {
		return fmt.Sprintf("%s%ds", sign, sec)
	}
	if sec < 3600 {
		return fmt.Sprintf("%s%dm%ds", sign, sec/60, sec%60)
	}
	h := sec / 3600
	m := (sec % 3600) / 60
	return fmt.Sprintf("%s%dh%dm", sign, h, m)
}

// Summary is a one-line operator-facing status.
func (s SkewResult) Summary() string {
	status := "OK"
	if !s.OK() {
		status = "FAIL (KRB_AP_ERR_SKEW likely)"
	}
	max := s.MaxSkew
	if max <= 0 {
		max = DefaultMaxSkew
	}
	return fmt.Sprintf("skew local→remote %s abs=%s max=%s %s | local=%s remote=%s",
		FormatDelta(s.Delta),
		FormatDelta(s.AbsDelta()),
		max.Round(time.Second),
		status,
		s.LocalUTC.Format(time.RFC3339),
		s.RemoteUTC.Format(time.RFC3339),
	)
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 {
		last := s[len(s)-1]
		if last != ' ' && last != '\t' && last != '\n' && last != '\r' {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}
