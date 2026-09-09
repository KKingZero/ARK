package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKingZero/ARK/pkg/arkhome"
)

func TestHostApprovalDescOmitsSecrets(t *testing.T) {
	d := hostApprovalDesc("host_rbcd_write", map[string]any{
		"dc":        "10.0.0.1",
		"to":        "DC$",
		"from":      "ATTACK$",
		"pass_file": "/secret",
		"hash":      "aabb",
	})
	if !strings.Contains(d, "to=DC$") || !strings.Contains(d, "dc=10.0.0.1") {
		t.Fatalf("%s", d)
	}
	if strings.Contains(d, "secret") || strings.Contains(d, "aabb") || strings.Contains(d, "hash") {
		t.Fatalf("leaked secret: %s", d)
	}
}

func TestJailSecretPathCwd(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	p := filepath.Join(dir, "pw.txt")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := jailSecretPath("pw.txt")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "pw.txt" {
		t.Fatal(got)
	}
}

func TestJailSecretPathRejectsDotDot(t *testing.T) {
	if _, err := jailSecretPath("../etc/passwd"); err == nil {
		t.Fatal("expected reject")
	}
}

func TestJailSecretPathArkHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ARK_HOME", home)
	p := filepath.Join(arkhome.Dir(), "t.aes")
	if err := os.WriteFile(p, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := jailSecretPath(p); err != nil {
		t.Fatal(err)
	}
}
