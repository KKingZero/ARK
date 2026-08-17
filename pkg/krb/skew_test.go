package krb

import (
	"testing"
	"time"
)

func TestCompareOK(t *testing.T) {
	local := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	remote := local.Add(2 * time.Minute)
	r := Compare(local, remote, 0)
	if !r.OK() {
		t.Fatalf("expected OK for 2m skew: %s", r.Summary())
	}
	if r.Delta != 2*time.Minute {
		t.Fatalf("delta=%v", r.Delta)
	}
}

func TestCompareFail(t *testing.T) {
	local := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	// Garfield-class: remote +8h
	remote := local.Add(8 * time.Hour)
	r := Compare(local, remote, DefaultMaxSkew)
	if r.OK() {
		t.Fatalf("expected FAIL for 8h skew")
	}
	if r.AbsDelta() != 8*time.Hour {
		t.Fatalf("abs=%v", r.AbsDelta())
	}
	s := r.Summary()
	if s == "" || len(s) < 10 {
		t.Fatalf("empty summary")
	}
}

func TestLDAPDialAddr(t *testing.T) {
	if got := ldapDialAddr("10.129.1.2"); got != "10.129.1.2:389" {
		t.Fatalf("got %q", got)
	}
	if got := ldapDialAddr("ldap://dc.lab.htb:3268"); got != "dc.lab.htb:3268" {
		t.Fatalf("got %q", got)
	}
}

func TestParseLDAPGeneralizedTime(t *testing.T) {
	cases := []string{
		"20260808104210.0Z",
		"20260808104210Z",
	}
	for _, c := range cases {
		tm, err := ParseLDAPGeneralizedTime(c)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if tm.Year() != 2026 || tm.Month() != 8 || tm.Day() != 8 {
			t.Fatalf("%s -> %v", c, tm)
		}
	}
	if _, err := ParseLDAPGeneralizedTime(""); err == nil {
		t.Fatal("expected error on empty")
	}
}

func TestFormatDelta(t *testing.T) {
	if FormatDelta(8*time.Hour) != "+8h0m" {
		t.Fatalf("got %s", FormatDelta(8*time.Hour))
	}
	if FormatDelta(-90*time.Second) != "-1m30s" {
		t.Fatalf("got %s", FormatDelta(-90*time.Second))
	}
}
