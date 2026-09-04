package smbcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKingZero/ARK/pkg/krb"
)

func TestUseTicket(t *testing.T) {
	if !UseTicket(Options{Ticket: "abc"}) {
		t.Fatal("want ticket")
	}
	if UseTicket(Options{Ticket: "abc", Hash: "aa"}) {
		t.Fatal("hash wins")
	}
	if UseTicket(Options{}) {
		t.Fatal("empty")
	}
}

func TestSmbclientArgv(t *testing.T) {
	argv := smbclientArgv("/bin/smbclient.py", Options{Host: "10.1.2.3"}, ticketAuth{domain: "PIRATE.HTB", user: "Administrator"}, "/tmp/in")
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "-k") || !strings.Contains(joined, "-no-pass") {
		t.Fatalf("%v", argv)
	}
	if strings.Contains(joined, "password") || strings.Contains(strings.ToLower(joined), "--pass") {
		t.Fatalf("password on argv: %v", argv)
	}
	if !strings.Contains(joined, "PIRATE.HTB/Administrator@10.1.2.3") {
		t.Fatalf("target %v", argv)
	}
}

func TestTicketListSharesMock(t *testing.T) {
	t.Setenv("ARK_SMB_IMPACKET", "1")
	dir := t.TempDir()
	t.Setenv("ARK_TICKET_DIR", dir)
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
	oldLook, oldRun := lookSMBClient, runImpacket
	t.Cleanup(func() { lookSMBClient = oldLook; runImpacket = oldRun })
	lookSMBClient = func(names ...string) (string, error) { return "/tmp/fake-smbclient.py", nil }
	var gotArgv []string
	var gotEnv []string
	runImpacket = func(argv []string, env []string) ([]byte, error) {
		gotArgv = append([]string(nil), argv...)
		gotEnv = append([]string(nil), env...)
		return []byte("Impacket v0.13.1\n[*] blah\nC$\nADMIN$\n"), nil
	}
	names, err := TicketListShares(Options{Host: "10.1.2.3", Ticket: cc, Domain: "pirate.htb"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(gotArgv, " ")
	if !strings.Contains(joined, "-k") || !strings.Contains(joined, "-no-pass") {
		t.Fatalf("argv %v", gotArgv)
	}
	envj := strings.Join(gotEnv, " ")
	if !strings.Contains(envj, "KRB5CCNAME="+cc) {
		t.Fatalf("env %v", gotEnv)
	}
	if !contains(names, "C$") {
		t.Fatalf("names %v", names)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
