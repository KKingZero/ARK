package preimplant

import (
	"os"
	"strings"
	"testing"
)

func TestRunPsExecHelp(t *testing.T) {
	if err := RunPsExec([]string{"help"}); err != nil {
		t.Fatal(err)
	}
}

func TestPlanPsExec(t *testing.T) {
	f, _ := ParseFlags([]string{
		"--host", "10.1.2.3:445", "--user", "alice", "--pass", "pw",
		"--payload", "a.exe", "--service", "ArkSvc", "--hostname", "dc.lab.htb",
	})
	p, err := planPsExec(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Service != "ArkSvc" || p.Remote != "ArkSvc.exe" || p.Binary != `C:\Windows\ArkSvc.exe` {
		t.Fatalf("%+v", p)
	}
	if p.Machine != `\\dc.lab.htb` {
		t.Fatalf("machine %s", p.Machine)
	}
	if p.Opts.Host != "10.1.2.3:445" {
		t.Fatalf("host %s", p.Opts.Host)
	}

	f, _ = ParseFlags([]string{"--host", "10.1.2.3", "--user", "alice", "--pass", "pw", "--payload", "a.exe"})
	p, err = planPsExec(f)
	if err != nil || p.Service != "" || p.Machine != `\\10.1.2.3` {
		t.Fatalf("%+v %v", p, err)
	}

	bad := [][]string{
		{"--user", "alice", "--pass", "pw", "--payload", "a.exe"},
		{"--host", "h", "--user", "alice", "--payload", "a.exe"},
		{"--host", "h", "--user", "alice", "--pass", "pw"},
		{"--host", "h", "--user", "alice", "--pass", "pw", "--payload", "a.exe", "--service", "has space"},
		{"--host", "h", "--user", "alice", "--pass", "pw", "--payload", "a.exe", "--service", "way-too-bad"},
		{"--host", "h", "--kerberos", "--payload", "a.exe"},
	}
	for _, args := range bad {
		f, _ = ParseFlags(args)
		if _, err := planPsExec(f); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestPlanPsExecKerberosNeedsDomain(t *testing.T) {
	f, _ := ParseFlags([]string{
		"--host", "10.1.2.3:445", "--user", "alice", "--hash", "aa",
		"--domain", "lab.htb", "--kerberos", "--payload", "a.exe", "--service", "S",
	})
	p, err := planPsExec(f)
	if err != nil {
		t.Fatal(err)
	}
	d, err := planKerberosSMB(p.Opts, p.Kerberos)
	if err != nil || d.Ask == nil || d.Ask.KDC != "10.1.2.3" || d.Ask.Hash != "aa" {
		t.Fatalf("%+v %v", d, err)
	}
	if p.Remote != "S.exe" || !strings.HasPrefix(p.Binary, `C:\Windows\`) {
		t.Fatalf("%+v", p)
	}
}

func TestReadPayloadCaps(t *testing.T) {
	dir := t.TempDir()
	empty := dir + "/empty"
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPayload(empty); err == nil {
		t.Fatal("empty accepted")
	}
	ok := dir + "/ok"
	if err := os.WriteFile(ok, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := readPayload(ok)
	if err != nil || string(b) != "MZ" {
		t.Fatal(err)
	}
}
