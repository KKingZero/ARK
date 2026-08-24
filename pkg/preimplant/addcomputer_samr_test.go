package preimplant

import (
	"fmt"
	"strings"
	"testing"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/ldapcli"
)

func TestAddComputerSAMRArgv(t *testing.T) {
	argv := addComputerSAMRArgv("/bin/addcomputer.py", ldapcli.Options{
		Host:     "10.129.244.95",
		Domain:   "pirate.htb",
		Username: "pentest",
		Password: "p3nt3st2025!&",
	}, "ATTACK", "AttackPass123!")
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "-method SAMR") {
		t.Fatalf("%v", argv)
	}
	if !strings.Contains(joined, "-computer-name ATTACK$") {
		t.Fatalf("name %v", argv)
	}
	if !strings.Contains(joined, "-dc-ip 10.129.244.95") {
		t.Fatalf("dc %v", argv)
	}
	if !strings.Contains(joined, "pirate.htb/pentest:") {
		t.Fatalf("ident %v", argv)
	}
}

func TestSamrAddComputerInvokesRunner(t *testing.T) {
	oldLook, oldRun := lookAddComputer, runAddComputer
	t.Cleanup(func() { lookAddComputer = oldLook; runAddComputer = oldRun })
	lookAddComputer = func() (string, error) { return "/tmp/addcomputer.py", nil }
	var got []string
	runAddComputer = func(argv []string) error {
		got = append([]string(nil), argv...)
		return nil
	}
	err := samrAddComputer(ldapcli.Options{
		Host: "10.0.0.1", Domain: "x.htb", Username: "u", Password: "p",
	}, "BOX", "machpass")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(got, " "), "-method SAMR") {
		t.Fatalf("%v", got)
	}
}

func TestSamrAddComputerNeedsPassword(t *testing.T) {
	err := samrAddComputer(ldapcli.Options{Host: "h", Username: "u"}, "X", "p")
	if err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("%v", err)
	}
}

func TestIsWillNotPerformFallbackGate(t *testing.T) {
	err := fmt.Errorf("add computer CN=ATTACK: LDAP Result Code 53 \"Unwilling To Perform\": WILL_NOT_PERFORM")
	if !ldapcli.IsWillNotPerform(err) {
		t.Fatal("gate")
	}
}
