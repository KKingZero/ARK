package preimplant

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeListenAddr(t *testing.T) {
	got, err := NormalizeListenAddr("", defaultRedirectorListen)
	if err != nil || got != "0.0.0.0:1750" {
		t.Fatalf("%q %v", got, err)
	}
	got, err = NormalizeListenAddr("443", defaultRedirectorListen)
	if err != nil || got != "0.0.0.0:443" {
		t.Fatalf("%q %v", got, err)
	}
	got, err = NormalizeListenAddr(":8443", defaultRedirectorListen)
	if err != nil || got != "0.0.0.0:8443" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := NormalizeListenAddr("nope", defaultRedirectorListen); err == nil {
		t.Fatal("want error")
	}
}

func TestRejectSameRedirectorHop(t *testing.T) {
	if err := RejectSameRedirectorHop("0.0.0.0:1750", "127.0.0.1:1750"); err == nil {
		t.Fatal("hairpin")
	}
	if err := RejectSameRedirectorHop("0.0.0.0:1750", "127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
}

func TestRedirectorPrivPortFailClosed(t *testing.T) {
	orig := httpsListenUp
	httpsListenUp = func(int) bool { return true }
	t.Cleanup(func() { httpsListenUp = orig })
	err := RunInbound([]string{"redirector", "start", "--listen", "0.0.0.0:443", "--to", "127.0.0.1:8443"})
	if err == nil || !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("got %v", err)
	}
}

func TestRedirectorFailClosedTeamserverDown(t *testing.T) {
	orig := httpsListenUp
	httpsListenUp = func(int) bool { return false }
	t.Cleanup(func() { httpsListenUp = orig })
	err := RunInbound([]string{"redirector", "start", "--listen", "127.0.0.1:1750", "--to", "127.0.0.1:8443"})
	if err == nil || !strings.Contains(err.Error(), "teamserver HTTPS down") {
		t.Fatalf("got %v", err)
	}
}

func TestServeRedirectorProxy(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 5)
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Write([]byte("pong!"))
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- ServeRedirector(ctx, listen, backend.Addr().String()) }()
	deadline := time.Now().Add(2 * time.Second)
	var c net.Conn
	for time.Now().Before(deadline) {
		c, err = net.DialTimeout("tcp", listen, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial redirector: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong!" {
		t.Fatalf("got %q", buf)
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeRedirector did not return")
	}
}

func TestRedirectorStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := redirectorStatePath
	redirectorStatePath = func() string { return filepath.Join(dir, "inbound-redirector.json") }
	t.Cleanup(func() { redirectorStatePath = orig })
	st := RedirectorState{Listen: "0.0.0.0:1750", To: "127.0.0.1:8443", PID: os.Getpid()}
	if err := WriteRedirectorState(st); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRedirectorState()
	if err != nil {
		t.Fatal(err)
	}
	if got.Listen != st.Listen || got.To != st.To || got.PID != st.PID {
		t.Fatalf("%+v", got)
	}
	out := FormatRedirectorStatus(got)
	if !strings.Contains(out, "up 0.0.0.0:1750 -> 127.0.0.1:8443") {
		t.Fatal(out)
	}
}

func TestFormatStatusIncludesRedirector(t *testing.T) {
	out := FormatStatus(Status{
		HTTPS:      []string{"up 127.0.0.1:8443"},
		HintPorts:  []int{8443},
		Redirector: RedirectorState{},
	})
	if !strings.Contains(out, "redirector:    down") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "inbound redirector start") {
		t.Fatal(out)
	}
	out = FormatStatus(Status{
		HTTPS:      []string{"up 127.0.0.1:1750"},
		HintPorts:  []int{1750},
		Redirector: RedirectorState{Listen: "0.0.0.0:1750", To: "127.0.0.1:8443", PID: 9},
	})
	if !strings.Contains(out, "redirector:    up 0.0.0.0:1750 -> 127.0.0.1:8443 pid=9") {
		t.Fatal(out)
	}
	if strings.Contains(out, "inbound redirector start --listen") {
		t.Fatal("should not hint start when already up")
	}
}

func TestRunInboundRedirectorHelp(t *testing.T) {
	if err := RunInbound([]string{"redirector", "help"}); err != nil {
		t.Fatal(err)
	}
}
