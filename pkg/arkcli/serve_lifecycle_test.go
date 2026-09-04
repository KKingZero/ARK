package arkcli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	zcrypto "github.com/KKingZero/ARK/pkg/crypto"
	"github.com/KKingZero/ARK/pkg/operatorcli"
	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/KKingZero/ARK/server"
	"github.com/chzyer/readline"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

// Four stdin-death modes from DarkZero/DanglingTree. Each is "REPL returns"
// (EOF / no TTY). C2 must still accept register until waitStop.
func TestServe_REPLExitDoesNotStopC2(t *testing.T) {
	cases := []string{"devnull", "pipeEOF", "detached", "interactiveEOF"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)

			secret, err := zcrypto.RandomBytes(32)
			if err != nil {
				t.Fatal(err)
			}
			grpcAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
			httpsPort := freePort(t)
			dataDir := filepath.Join(home, ".ark")
			cfg := &server.Config{
				GRPCAddr:      grpcAddr,
				DBPath:        filepath.Join(dataDir, "ark.db"),
				DataDir:       dataDir,
				ImplantSecret: hex.EncodeToString(secret),
				Listeners: []server.ListenerConfig{
					{Name: "test-https", Protocol: "https", Host: "127.0.0.1", Port: uint32(httpsPort)},
				},
			}
			ahOff := false
			cfg.AutoHarvest.Enabled = &ahOff

			configPath := filepath.Join(dataDir, "server.yaml")

			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- runServe(cfg, configPath, serveHooks{
					runREPL: func(operatorcli.Options) error {
						// Simulate stdin EOF / missing TTY.
						return io.EOF
					},
					waitStop: func() { <-release },
				})
			}()

			waitTCP(t, grpcAddr, 8*time.Second)
			waitTCP(t, fmt.Sprintf("127.0.0.1:%d", httpsPort), 8*time.Second)
			registerOK(t, fmt.Sprintf("https://127.0.0.1:%d", httpsPort), secret, "serve-eof-"+name)

			close(release)
			select {
			case err := <-done:
				if err != io.EOF {
					t.Fatalf("runServe err: %v", err)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("runServe did not return after waitStop")
			}
		})
	}
}

func TestServe_InterruptStopsC2WithoutWait(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secret, err := zcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	grpcAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	httpsPort := freePort(t)
	dataDir := filepath.Join(home, ".ark")
	cfg := &server.Config{
		GRPCAddr:      grpcAddr,
		DBPath:        filepath.Join(dataDir, "ark.db"),
		DataDir:       dataDir,
		ImplantSecret: hex.EncodeToString(secret),
		Listeners: []server.ListenerConfig{
			{Name: "test-https", Protocol: "https", Host: "127.0.0.1", Port: uint32(httpsPort)},
		},
	}
	ahOff := false
	cfg.AutoHarvest.Enabled = &ahOff
	waitCalled := false
	err = runServe(cfg, filepath.Join(dataDir, "server.yaml"), serveHooks{
		runREPL:  func(operatorcli.Options) error { return readline.ErrInterrupt },
		waitStop: func() { waitCalled = true },
	})
	if err != readline.ErrInterrupt {
		t.Fatalf("err=%v", err)
	}
	if waitCalled {
		t.Fatal("Ctrl+C must stop C2 without waiting for a second signal")
	}
}

func TestServe_ConfigRoundTripNoExtraListeners(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secret, err := zcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	grpcAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	httpsPort := freePort(t)
	dataDir := filepath.Join(home, ".ark")
	cfg := &server.Config{
		GRPCAddr:      grpcAddr,
		DBPath:        filepath.Join(dataDir, "ark.db"),
		DataDir:       dataDir,
		ImplantSecret: hex.EncodeToString(secret),
		Listeners: []server.ListenerConfig{
			{Name: "test-https", Protocol: "https", Host: "127.0.0.1", Port: uint32(httpsPort)},
		},
	}
	ahOff := false
	cfg.AutoHarvest.Enabled = &ahOff
	configPath := filepath.Join(dataDir, "server.yaml")

	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runServe(cfg, configPath, serveHooks{
			runREPL:  func(operatorcli.Options) error { return nil },
			waitStop: func() { <-release },
		})
	}()
	t.Cleanup(func() {
		close(release)
		<-done
	})
	waitTCP(t, grpcAddr, 8*time.Second)

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved server.Config
	if err := yaml.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Listeners) != 1 {
		t.Fatalf("listener count changed: %d", len(saved.Listeners))
	}
}

func registerOK(t *testing.T, baseURL string, secret []byte, implantID string) {
	t.Helper()
	ts := time.Now().UnixMilli()
	reg := &pb.Register{
		ImplantId: implantID,
		Hostname:  "eof-host",
		Username:  "eof-user",
		Os:        "linux",
		Arch:      "amd64",
		Timestamp: ts,
		Hmac:      zcrypto.ComputeHMAC(secret, implantID, ts),
	}
	body, err := proto.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/register", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // lab test only
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("register status %d body=%q", resp.StatusCode, b)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var rr pb.RegisterResponse
	if err := proto.Unmarshal(data, &rr); err != nil {
		t.Fatal(err)
	}
	if !rr.Success || rr.SessionId == "" {
		t.Fatalf("bad register: %+v", &rr)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitTCP(t *testing.T, addr string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s after %s", addr, d)
}
