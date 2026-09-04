package preimplant

import (
	"strings"
	"testing"
)

func TestRunWinRMHelp(t *testing.T) {
	if err := RunWinRM([]string{"help"}); err != nil {
		t.Fatal(err)
	}
}

func TestRunWinRMRequiresHostUser(t *testing.T) {
	err := RunWinRM([]string{"--ps", "whoami"})
	if err == nil {
		t.Fatal("expected usage")
	}
}

func TestRunMSSQLXPRequiresYes(t *testing.T) {
	err := RunMSSQL([]string{"xp", "--host", "127.0.0.1", "--user", "sa", "--pass", "x", "--cmd", "whoami"})
	if err == nil || err.Error() == "" {
		t.Fatalf("got %v", err)
	}
	if err.Error() != "xp_cmdshell requires --yes" {
		t.Fatalf("got %v", err)
	}
}

func TestMSSQLUsageMentionsSOCKSAndCheckout(t *testing.T) {
	if !strings.Contains(mssqlUsage, "ARK_PROXY") || !strings.Contains(mssqlUsage, "ARK_ROOT") {
		t.Fatal(mssqlUsage)
	}
	if strings.Contains(mssqlUsage, "socat") {
		t.Fatal("usage still tells operators to socat")
	}
	if !strings.Contains(mssqlUsage, "--pass-file") {
		t.Fatal(mssqlUsage)
	}
}

func TestFindRepoScriptError(t *testing.T) {
	t.Setenv("ARK_ROOT", t.TempDir())
	_, err := findRepoScript("scripts/does-not-exist-ark.py")
	if err == nil || !strings.Contains(err.Error(), "ARK_ROOT") {
		t.Fatalf("got %v", err)
	}
}
