package arkhome

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirEmptyHomeIsArk(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ARK_HOME", "")
	t.Setenv("EREBUS_HOME", "")
	if got := Dir(); got != filepath.Join(home, ".ark") {
		t.Fatalf("empty home: got %s", got)
	}
}

func TestDirMigratesLegacyOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ARK_HOME", "")
	t.Setenv("EREBUS_HOME", "")
	legacy := filepath.Join(home, ".erebus")
	if err := os.MkdirAll(filepath.Join(legacy, "certs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "server.yaml"), []byte("listeners: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ark := filepath.Join(home, ".ark")
	if err := os.Mkdir(ark, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ark, "redirector.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Dir(); got != ark {
		t.Fatalf("got %s", got)
	}
	b, err := os.ReadFile(filepath.Join(ark, "server.yaml"))
	if err != nil || string(b) != "listeners: []\n" {
		t.Fatalf("server.yaml %q err %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(ark, "certs")); err != nil {
		t.Fatal(err)
	}
	redir, err := os.ReadFile(filepath.Join(ark, "redirector.json"))
	if err != nil || string(redir) != "{}\n" {
		t.Fatalf("redirector clobbered: %q", redir)
	}
	if _, err := os.Stat(filepath.Join(legacy, "server.yaml")); err != nil {
		t.Fatal("legacy tree must stay")
	}
	if err := os.WriteFile(filepath.Join(legacy, "server.yaml"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Dir(); got != ark {
		t.Fatalf("second call %s", got)
	}
	b, err = os.ReadFile(filepath.Join(ark, "server.yaml"))
	if err != nil || string(b) != "listeners: []\n" {
		t.Fatalf("second copy overwrote: %q", b)
	}
}

func TestDirDoesNotClobberExistingArk(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ARK_HOME", "")
	t.Setenv("EREBUS_HOME", "")
	ark := filepath.Join(home, ".ark")
	legacy := filepath.Join(home, ".erebus")
	if err := os.MkdirAll(ark, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ark, "server.yaml"), []byte("ark\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "server.yaml"), []byte("erebus\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Dir(); got != ark {
		t.Fatalf("got %s", got)
	}
	b, err := os.ReadFile(filepath.Join(ark, "server.yaml"))
	if err != nil || string(b) != "ark\n" {
		t.Fatalf("clobbered: %q", b)
	}
}

func TestDirARKHomeOverride(t *testing.T) {
	want := t.TempDir()
	t.Setenv("ARK_HOME", want)
	if got := Dir(); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
