package krb

import (
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
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
	addr, tlsOn, name := ldapDialTarget("ldaps://dc.lab.htb")
	if addr != "dc.lab.htb:636" || !tlsOn || name != "dc.lab.htb" {
		t.Fatalf("ldaps: %s tls=%v name=%s", addr, tlsOn, name)
	}
	addr, tlsOn, _ = ldapDialTarget("ldaps://10.129.1.2:636")
	if addr != "10.129.1.2:636" || !tlsOn {
		t.Fatalf("ldaps port: %s tls=%v", addr, tlsOn)
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

func TestOffsetFromSKEW(t *testing.T) {
	local := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	ke := messages.KRBError{
		ErrorCode: errorcode.KRB_AP_ERR_SKEW,
		STime:     local.Add(8 * time.Hour),
	}
	d := OffsetFromSKEW(ke, local)
	if d != 8*time.Hour {
		t.Fatalf("delta=%v", d)
	}
	SetClockOffset(0)
	t.Cleanup(func() { SetClockOffset(0) })
	live := messages.KRBError{
		ErrorCode: errorcode.KRB_AP_ERR_SKEW,
		STime:     time.Now().UTC().Add(8 * time.Hour),
	}
	ApplySKEW(live)
	if ClockOffset() < 7*time.Hour {
		t.Fatalf("offset %v", ClockOffset())
	}
}

func TestFormatKRBErrorSKEW(t *testing.T) {
	ke := messages.KRBError{
		ErrorCode: errorcode.KRB_AP_ERR_SKEW,
		STime:     time.Now().UTC().Add(8 * time.Hour),
	}
	s := FormatKRBError(ke)
	if !strings.Contains(s, "errorcode=KRB_AP_ERR_SKEW") {
		t.Fatalf("%s", s)
	}
	if !strings.Contains(s, "skew_delta=") {
		t.Fatalf("%s", s)
	}
}

func TestMarshalPAEncTSUsesOffset(t *testing.T) {
	SetClockOffset(8 * time.Hour)
	t.Cleanup(func() { SetClockOffset(0) })
	b, err := marshalPAEncTS(Now())
	if err != nil {
		t.Fatal(err)
	}
	var p types.PAEncTSEnc
	if _, err := asn1.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if p.PATimestamp.Before(time.Now().UTC().Add(7 * time.Hour)) {
		t.Fatalf("timestamp not offset: %s", p.PATimestamp)
	}
}

func TestRequireAESStructured(t *testing.T) {
	err := requireAES(23, "TGT")
	if err == nil || !strings.Contains(err.Error(), "etype=23") {
		t.Fatalf("%v", err)
	}
}
