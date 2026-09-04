package krb

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
)

func TestDetectTicketFormat(t *testing.T) {
	if DetectTicketFormat([]byte{5, 4, 0}) != "ccache" {
		t.Fatal("ccache")
	}
	if DetectTicketFormat([]byte{0x76, 0x82}) != "kirbi" {
		t.Fatal("kirbi")
	}
	if DetectTicketFormat([]byte{0x30}) != "" {
		t.Fatal("unknown")
	}
}

func TestCCacheWriteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ARK_TICKET_DIR", dir)
	raw, err := WriteCCache(CCacheCred{
		ClientRealm: "PUPPET.VL",
		Client:      []string{"bruce.smith"},
		ServerRealm: "PUPPET.VL",
		Server:      []string{"krbtgt", "PUPPET.VL"},
		KeyType:     18,
		Key:         []byte("0123456789abcdef0123456789abcdef"),
		AuthTime:    time.Unix(1700000000, 0).UTC(),
		StartTime:   time.Unix(1700000000, 0).UTC(),
		EndTime:     time.Unix(1700003600, 0).UTC(),
		Flags:       0x40c10000,
		Ticket:      []byte("not-a-real-ticket"),
	})
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "in.ccache")
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.LoadCCache(src); err != nil {
		t.Fatalf("gokrb5 load: %v", err)
	}
	m, err := ImportTicket(src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID == "" || m.Source != "ccache" {
		t.Fatalf("%+v", m)
	}
	if m.Principal != "bruce.smith" || m.Realm != "PUPPET.VL" {
		t.Fatalf("principal %+v", m)
	}
	list, err := ListTickets(dir)
	if err != nil || len(list) != 1 {
		t.Fatalf("list %v %v", list, err)
	}
	got, path, err := LoadTicket(m.ID, dir)
	if err != nil || path == "" || got.ID != m.ID {
		t.Fatalf("load %v %s %v", got, path, err)
	}
	if !bytes.Contains(raw, []byte{0x40, 0xc1, 0x00, 0x00}) {
		t.Fatalf("flags missing: %x", raw)
	}
}

func TestNewConfigAESOnly(t *testing.T) {
	cfg, err := NewConfig("puppet.vl", "10.13.38.33")
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, e := range cfg.LibDefaults.DefaultTktEnctypes {
		joined += e + " "
	}
	if !containsStr(joined, "aes256") {
		t.Fatalf("aes: %s", joined)
	}
	for _, e := range cfg.LibDefaults.DefaultTktEnctypes {
		if e == "rc4-hmac" || e == "arcfour-hmac" {
			t.Fatal("rc4 must not be offered")
		}
	}
}

func TestAskTGTMissingArgs(t *testing.T) {
	if _, err := AskTGT(AskTGTOptions{}); err == nil {
		t.Fatal("want error")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})())
}
