package preimplant

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFlags(t *testing.T) {
	f, bare := ParseFlags([]string{"enum", "--dc", "10.0.0.1", "--anon", "--domain", "a.htb"})
	if f["dc"] != "10.0.0.1" || !flagBool(f, "anon") || f["domain"] != "a.htb" {
		t.Fatalf("%v", f)
	}
	if len(bare) != 1 || bare[0] != "enum" {
		t.Fatalf("bare %v", bare)
	}
}

func TestReadSecretFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p")
	if err := os.WriteFile(p, []byte("RiverDragon#Storm25\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := map[string]string{"pass-file": p}
	s, err := readSecret(f, "pass", "pass-file")
	if err != nil || s != "RiverDragon#Storm25" {
		t.Fatalf("%q %v", s, err)
	}
}
