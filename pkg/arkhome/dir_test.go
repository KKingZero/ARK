package arkhome

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirPrefersArkOverLegacy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ARK_HOME", "")
	t.Setenv("EREBUS_HOME", "")

	if got := Dir(); got != filepath.Join(home, ".ark") {
		t.Fatalf("empty home: got %s", got)
	}

	if err := os.Mkdir(filepath.Join(home, ".erebus"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := Dir(); got != filepath.Join(home, ".erebus") {
		t.Fatalf("legacy only: got %s", got)
	}

	if err := os.Mkdir(filepath.Join(home, ".ark"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := Dir(); got != filepath.Join(home, ".ark") {
		t.Fatalf("both present: got %s", got)
	}
}

func TestDirARKHomeOverride(t *testing.T) {
	want := t.TempDir()
	t.Setenv("ARK_HOME", want)
	if got := Dir(); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
