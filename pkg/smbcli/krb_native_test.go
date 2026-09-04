package smbcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKingZero/ARK/pkg/krb"
)

func TestTicketNativeEnabled(t *testing.T) {
	t.Setenv("ARK_SMB_IMPACKET", "")
	if !ticketNativeEnabled() {
		t.Fatal("default native")
	}
	t.Setenv("ARK_SMB_IMPACKET", "1")
	if ticketNativeEnabled() {
		t.Fatal("impacket override")
	}
}

func TestSpnegoAPReqFromCCache(t *testing.T) {
	dir := t.TempDir()
	raw, err := krb.WriteCCache(krb.CCacheCred{
		ClientRealm: "PIRATE.HTB",
		Client:      []string{"Administrator"},
		ServerRealm: "PIRATE.HTB",
		Server:      []string{"cifs", "web01.pirate.htb"},
		KeyType:     18,
		Key:         []byte("0123456789abcdef0123456789abcdef"),
		Ticket:      []byte("not-a-real-ticket"),
	})
	if err != nil {
		t.Fatal(err)
	}
	cc := filepath.Join(dir, "t.ccache")
	if err := os.WriteFile(cc, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := resolveTicket(Options{Ticket: cc, Domain: "pirate.htb", Host: "web01.pirate.htb"})
	if err != nil {
		t.Fatal(err)
	}
	if auth.user != "Administrator" {
		t.Fatalf("user %s", auth.user)
	}
}

func TestDialKerberosMissingTicket(t *testing.T) {
	_, err := DialKerberos(Options{Host: "10.1.2.3"})
	if err == nil {
		t.Fatal("want error")
	}
}

func TestSMB2Sign(t *testing.T) {
	s := &krbSession{sessionID: 1, sessionKey: []byte("0123456789abcdef0123456789abcdef")}
	pkt := make([]byte, 80)
	copy(pkt[0:4], smb2Protocol)
	s.sign(pkt)
	if smb2le.Uint32(pkt[16:20])&smb2FlagsSigned == 0 {
		t.Fatal("signed flag")
	}
	var zero bool
	for i := 48; i < 64; i++ {
		if pkt[i] != 0 {
			zero = true
			break
		}
	}
	if !zero {
		t.Fatal("empty signature")
	}
}

func TestParseDirInfo(t *testing.T) {
	// one FILE_DIRECTORY_INFORMATION: next=0, name "C$"
	name := utf16le("C$")
	b := make([]byte, 64+len(name))
	smb2le.PutUint32(b[60:64], uint32(len(name)))
	copy(b[64:], name)
	got := parseDirInfo(b)
	if len(got) != 1 || got[0] != "C$" {
		t.Fatalf("%v", got)
	}
}

func TestTicketListSharesNativeNoKDC(t *testing.T) {
	t.Setenv("ARK_SMB_IMPACKET", "0")
	dir := t.TempDir()
	t.Setenv("ARK_TICKET_DIR", dir)
	raw, err := krb.WriteCCache(krb.CCacheCred{
		ClientRealm: "PIRATE.HTB",
		Client:      []string{"Administrator"},
		ServerRealm: "PIRATE.HTB",
		Server:      []string{"krbtgt", "PIRATE.HTB"},
		KeyType:     18,
		Key:         []byte("0123456789abcdef0123456789abcdef"),
		Ticket:      []byte{0x61, 0x03, 0x02, 0x01, 0x05}, // not a real ticket
	})
	if err != nil {
		t.Fatal(err)
	}
	cc := filepath.Join(dir, "t.ccache")
	if err := os.WriteFile(cc, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = TicketListShares(Options{Host: "127.0.0.1:1", Ticket: cc, Domain: "pirate.htb"})
	if err == nil {
		t.Fatal("want error (no live SMB)")
	}
	if strings.Contains(err.Error(), "smbclient.py") {
		t.Fatalf("must not shell Impacket: %v", err)
	}
}
