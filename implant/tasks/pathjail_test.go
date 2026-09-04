package tasks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveJailedPathAllowsRelative(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	got, err := resolveJailedPath("notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.Abs(filepath.Join(dir, "notes.txt"))
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestResolveJailedPathRejectsAbsolute(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := resolveJailedPath("/etc/passwd"); err == nil {
		t.Fatal("expected error for absolute path")
	}
}

func TestResolveJailedPathRejectsParentTraversal(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, p := range []string{"../secret", "..", "sub/../../etc/passwd"} {
		if _, err := resolveJailedPath(p); err == nil {
			t.Fatalf("expected error for %q", p)
		}
	}
}

func TestResolveJailedPathNestedRelative(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	sub := filepath.Join(dir, "data")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := resolveJailedPath(filepath.Join("data", "file.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, filepath.Join("data", "file.bin")) {
		t.Fatalf("unexpected resolved path: %s", got)
	}
}

func TestResolveJailedPathRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	t.Chdir(dir)

	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := resolveJailedPath("link"); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestResolveJailedPathRejectsSymlinkParentEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	t.Chdir(dir)

	if err := os.Symlink(outside, filepath.Join(dir, "out")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := resolveJailedPath(filepath.Join("out", "new.txt")); err == nil {
		t.Fatal("expected symlink parent escape to be rejected")
	}
}
