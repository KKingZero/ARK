package arkcli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatusOneShotExits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ark status exec test in -short")
	}
	bin := buildARK(t)
	home := t.TempDir()
	cmd := exec.CommandContext(context.Background(), bin, "status")
	cmd.Env = append(os.Environ(), "HOME="+home, "ARK_HOME="+filepath.Join(home, ".ark"))
	cmd.Dir = home
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Stdin = nil
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("status: %v\n%s", err, out.String())
		}
	case <-time.After(8 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		t.Fatalf("status hung (entered REPL?)\n%s", out.String())
	}
	s := out.String()
	if !strings.Contains(s, "Teamserver") {
		t.Fatalf("missing status:\n%s", s)
	}
	if strings.Contains(s, "Type 'help' for available commands") {
		t.Fatalf("printed startup banner (REPL):\n%s", s)
	}
}
