package smbcli

import (
	"testing"

	"github.com/hirochachacha/go-smb2"
)

func TestParseNTHash(t *testing.T) {
	nt := "603fc24ee01a9409f83c9d1d701485c5"
	b, err := ParseNTHash(nt)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Fatalf("len=%d", len(b))
	}
	if b[0] != 0xaa || b[16] != 0x60 {
		t.Fatalf("unexpected bytes: %x", b)
	}
}

func TestNormalizePath(t *testing.T) {
	if got := NormalizePath(`\foo\bar`); got != "foo/bar" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizePath(""); got != "." {
		t.Fatalf("got %q", got)
	}
}

func TestJoinSMBAddr(t *testing.T) {
	if got := joinSMBAddr("10.1.2.3"); got != "10.1.2.3:445" {
		t.Fatalf("got %q", got)
	}
	if got := joinSMBAddr("10.1.2.3:139"); got != "10.1.2.3:139" {
		t.Fatalf("got %q", got)
	}
	if got := joinSMBAddr("fe80::1"); got != "[fe80::1]:445" {
		t.Fatalf("ipv6 got %q", got)
	}
}

func TestInitiatorTicketWithoutHash(t *testing.T) {
	_, err := initiator(Options{Username: "u", Ticket: "abc"})
	if err == nil {
		t.Fatal("ticket without hash must fail closed")
	}
}

func TestInitiatorAnon(t *testing.T) {
	init, err := initiator(Options{Anonymous: true})
	if err != nil || init == nil {
		t.Fatal(err)
	}
	if init.User != "Guest" || init.Password != "" {
		t.Fatalf("anon must be Guest: user=%q pass=%q", init.User, init.Password)
	}
}

func TestInitiatorGuestEmptyPass(t *testing.T) {
	init, err := initiator(Options{Username: "Guest"})
	if err != nil || init == nil {
		t.Fatal(err)
	}
	if init.User != "Guest" {
		t.Fatalf("user %q", init.User)
	}
}

func TestInitiatorNamedUserEmptyPassFails(t *testing.T) {
	_, err := initiator(Options{Username: "j.harris"})
	if err == nil {
		t.Fatal("named user empty pass must fail")
	}
}

func TestNTLMDialerSigning(t *testing.T) {
	guest := ntlmDialer(&smb2.NTLMInitiator{User: "Guest"})
	if guest.Negotiator.RequireMessageSigning {
		t.Fatal("guest must not require signing")
	}
	auth := ntlmDialer(&smb2.NTLMInitiator{User: "j.harris"})
	if !auth.Negotiator.RequireMessageSigning {
		t.Fatal("authenticated NTLM must require signing")
	}
}
