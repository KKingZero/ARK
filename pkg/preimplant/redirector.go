package preimplant

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KKingZero/ARK/pkg/ntlmrelay"
)

const (
	defaultRedirectorListen = "0.0.0.0:1750"
	defaultRedirectorTo     = "127.0.0.1:8443"
)

const redirectorUsage = `ark inbound redirector — TCP passthrough to teamserver HTTPS (no TLS terminate)

  ark inbound redirector start [--listen 0.0.0.0:1750] [--to 127.0.0.1:8443]
      [--background] [--allow-priv-ports]
  ark inbound redirector stop
  ark inbound redirector status

Default listen is 1750 (Fedora firewalld 1714–1764). 443 needs
--allow-priv-ports or ARK_ALLOW_PRIV_PORTS=1 (CAP_NET_BIND_SERVICE / root).
TLS is not terminated — implant CA pin still applies to the teamserver cert.
Lab-only.
`

// RedirectorState is ~/.ark/inbound-redirector.json.
type RedirectorState struct {
	Listen string `json:"listen"`
	To     string `json:"to"`
	PID    int    `json:"pid"`
}

var redirectorStatePath = func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".ark", "inbound-redirector.json")
	}
	return filepath.Join(home, ".ark", "inbound-redirector.json")
}

var startRedirectorBackground = spawnRedirectorBackground

func inboundRedirector(args []string) error {
	if len(args) < 1 {
		return inboundRedirectorStatus()
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(redirectorUsage)
		return nil
	case "start":
		return inboundRedirectorStart(args[1:], false)
	case "run":
		return inboundRedirectorStart(args[1:], true)
	case "stop":
		return inboundRedirectorStop()
	case "status":
		return inboundRedirectorStatus()
	default:
		return fmt.Errorf("unknown inbound redirector command %q\n%s", args[0], redirectorUsage)
	}
}

func inboundRedirectorStart(args []string, child bool) error {
	f, _ := ParseFlags(args)
	listen, err := NormalizeListenAddr(first(f, "listen"), defaultRedirectorListen)
	if err != nil {
		return err
	}
	to, err := NormalizeListenAddr(first(f, "to"), defaultRedirectorTo)
	if err != nil {
		return fmt.Errorf("--to: %w", err)
	}
	allowPriv := flagBool(f, "allow-priv-ports") || os.Getenv("ARK_ALLOW_PRIV_PORTS") == "1"
	if err := ntlmrelay.CheckListenPort(listen, allowPriv); err != nil {
		return err
	}
	if err := RejectSameRedirectorHop(listen, to); err != nil {
		return err
	}
	toPort, err := portOfAddr(to)
	if err != nil {
		return err
	}
	if !httpsListenUp(toPort) {
		return fmt.Errorf("teamserver HTTPS down on %s — start: ark teamserver", to)
	}
	if !child && flagBool(f, "background", "daemon") {
		return startRedirectorBackground(listen, to, allowPriv)
	}
	if err := claimRedirector(listen, to); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "inbound redirector %s -> %s (Ctrl-C to stop)\n", listen, to)
	err = ServeRedirector(ctx, listen, to)
	clearRedirectorState()
	return err
}

func inboundRedirectorStop() error {
	st, err := ReadRedirectorState()
	if err != nil {
		return fmt.Errorf("inbound redirector stop: %w", err)
	}
	if st.PID > 0 && pidAlive(st.PID) && st.PID != os.Getpid() {
		p, err := os.FindProcess(st.PID)
		if err != nil {
			return err
		}
		if err := p.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("inbound redirector stop pid %d: %w", st.PID, err)
		}
	}
	clearRedirectorState()
	fmt.Printf("inbound redirector stopped pid=%d\n", st.PID)
	return nil
}

func inboundRedirectorStatus() error {
	fmt.Print(FormatRedirectorStatus(LoadRedirectorState()))
	return nil
}

func spawnRedirectorBackground(listen, to string, allowPriv bool) error {
	bin, err := lookARK()
	if err != nil {
		return fmt.Errorf("ark binary: %w", err)
	}
	argv := []string{bin, "inbound", "redirector", "run", "--listen", listen, "--to", to}
	if allowPriv {
		argv = append(argv, "--allow-priv-ports")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("inbound redirector background: %w", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := ReadRedirectorState(); err == nil && st.PID == cmd.Process.Pid && redirectorListenUp(listen) {
			fmt.Printf("inbound redirector background pid=%d %s -> %s\n", st.PID, listen, to)
			fmt.Printf("  implant CALLBACK_URL=https://<tun0>:%d\n", mustPort(listen))
			fmt.Printf("  stop: ark inbound redirector stop\n")
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	return fmt.Errorf("inbound redirector background started pid=%d but listen %s did not come up", cmd.Process.Pid, listen)
}

func claimRedirector(listen, to string) error {
	if st, err := ReadRedirectorState(); err == nil && st.PID > 0 && pidAlive(st.PID) && st.PID != os.Getpid() {
		return fmt.Errorf("inbound redirector already running pid=%d %s -> %s (stop first)", st.PID, st.Listen, st.To)
	}
	return WriteRedirectorState(RedirectorState{Listen: listen, To: to, PID: os.Getpid()})
}

func redirectorListenUp(listen string) bool {
	c, err := net.DialTimeout("tcp", rewriteLoopback(listen), 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func rewriteLoopback(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// NormalizeListenAddr fills host/port defaults. Bare ":443" or "443" are OK.
func NormalizeListenAddr(s, fallback string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = fallback
	}
	if !strings.Contains(s, ":") {
		s = "0.0.0.0:" + s
	} else if strings.HasPrefix(s, ":") {
		s = "0.0.0.0" + s
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("address %q: %w", s, err)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return "", fmt.Errorf("port %q: want 1-65535", port)
	}
	return net.JoinHostPort(host, port), nil
}

// RejectSameRedirectorHop refuses listen==to on loopback (would hairpin).
func RejectSameRedirectorHop(listen, to string) error {
	lh, lp, err1 := net.SplitHostPort(listen)
	th, tp, err2 := net.SplitHostPort(to)
	if err1 != nil || err2 != nil {
		return nil
	}
	if lp != tp {
		return nil
	}
	if loopbackHost(lh) && loopbackHost(th) {
		return fmt.Errorf("redirector listen %s and --to %s are the same hop", listen, to)
	}
	return nil
}

func loopbackHost(h string) bool {
	ip := net.ParseIP(h)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return h == "0.0.0.0" || h == "::" || h == "" || strings.EqualFold(h, "localhost")
}

func portOfAddr(addr string) (int, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("port %q", p)
	}
	return n, nil
}

func mustPort(addr string) int {
	n, _ := portOfAddr(addr)
	return n
}

// ServeRedirector TCP-proxies listen → to until ctx is done.
func ServeRedirector(ctx context.Context, listen, to string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("inbound redirector listen %s: %w", listen, err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go proxyOne(c, to)
	}
}

func proxyOne(c net.Conn, to string) {
	defer c.Close()
	d, err := net.DialTimeout("tcp", to, 8*time.Second)
	if err != nil {
		return
	}
	defer d.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(d, c)
		closeWrite(d)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, d)
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
}

func closeWrite(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.CloseWrite()
		return
	}
	_ = c.Close()
}

// WriteRedirectorState persists listen/to/pid.
func WriteRedirectorState(st RedirectorState) error {
	path := redirectorStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func clearRedirectorState() {
	_ = os.Remove(redirectorStatePath())
}

// ReadRedirectorState loads state and clears it if the PID is dead.
func ReadRedirectorState() (RedirectorState, error) {
	var st RedirectorState
	b, err := os.ReadFile(redirectorStatePath())
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	if st.PID > 0 && !pidAlive(st.PID) {
		clearRedirectorState()
		return st, fmt.Errorf("redirector pid %d is not running (stale state cleared)", st.PID)
	}
	return st, nil
}

// LoadRedirectorState is status-friendly: empty if missing/stale.
func LoadRedirectorState() RedirectorState {
	st, err := ReadRedirectorState()
	if err != nil {
		return RedirectorState{}
	}
	return st
}

// FormatRedirectorStatus is the dedicated status block.
func FormatRedirectorStatus(st RedirectorState) string {
	if st.PID == 0 || st.Listen == "" {
		return "inbound redirector: down\n  ark inbound redirector start --listen 0.0.0.0:1750 --to 127.0.0.1:8443\n  ark inbound redirector start --listen 0.0.0.0:443 --to 127.0.0.1:8443 --allow-priv-ports\n"
	}
	return fmt.Sprintf("inbound redirector: up %s -> %s pid=%d\n", st.Listen, st.To, st.PID)
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
