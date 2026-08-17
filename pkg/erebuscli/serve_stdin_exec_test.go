package erebuscli

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	zcrypto "github.com/KKingZero/erebus-exploit-framwork/pkg/crypto"
)

// Binary-level stdin cases: /dev/null, pipe EOF, setsid+null (nohup-like), pipe close after start.
func TestServeStdinEOF_Binary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping erebus serve exec test in -short")
	}
	bin := buildErebus(t)

	cases := []struct {
		name  string
		stdin func() io.ReadCloser
	}{
		{"devnull", func() io.ReadCloser {
			f, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			return f
		}},
		{"pipeEOF", func() io.ReadCloser {
			return io.NopCloser(io.MultiReader())
		}},
		{"detached", func() io.ReadCloser {
			f, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			return f
		}},
		{"interactiveEOF", func() io.ReadCloser {
			pr, pw := io.Pipe()
			go func() {
				time.Sleep(300 * time.Millisecond)
				_ = pw.Close()
			}()
			return pr
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			secret, err := zcrypto.RandomBytes(32)
			if err != nil {
				t.Fatal(err)
			}
			grpcPort := freePort(t)
			httpsPort := freePort(t)
			dataDir := filepath.Join(home, ".erebus")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			yaml := fmt.Sprintf(`grpc_addr: 127.0.0.1:%d
db_path: %s
data_dir: %s
implant_secret: %s
auto_harvest:
  enabled: false
listeners:
  - name: test-https
    protocol: https
    host: 127.0.0.1
    port: %d
`, grpcPort, filepath.Join(dataDir, "erebus.db"), dataDir, hex.EncodeToString(secret), httpsPort)
			if err := os.WriteFile(filepath.Join(dataDir, "server.yaml"), []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(bin, "serve")
			cmd.Env = append(os.Environ(), "HOME="+home)
			cmd.Dir = home
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			stdin := tc.stdin()
			cmd.Stdin = stdin
			if tc.name == "detached" {
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = stdin.Close()
				_ = cmd.Process.Signal(syscall.SIGTERM)
				done := make(chan struct{})
				go func() { _, _ = cmd.Process.Wait(); close(done) }()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					_ = cmd.Process.Kill()
				}
			})

			waitTCP(t, fmt.Sprintf("127.0.0.1:%d", grpcPort), 15*time.Second)
			waitTCP(t, fmt.Sprintf("127.0.0.1:%d", httpsPort), 15*time.Second)
			// Stdin already closed (or never a TTY). C2 must still accept register.
			registerOK(t, fmt.Sprintf("https://127.0.0.1:%d", httpsPort), secret, "exec-"+tc.name)
		})
	}
}

func buildErebus(t *testing.T) string {
	t.Helper()
	root := findModuleRoot(t)
	// /tmp is often noexec; keep the test binary in the module tree.
	outDir := filepath.Join(root, ".cache", "serve-stdin-test")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(outDir, "erebus")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/erebus")
	cmd.Dir = root
	cmd.Env = os.Environ()
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build ./cmd/erebus: %v\n%s", err, b)
	}
	return out
}

func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
