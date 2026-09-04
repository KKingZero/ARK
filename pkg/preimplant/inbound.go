package preimplant

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/KKingZero/ARK/pkg/netproxy"
	"gopkg.in/yaml.v3"
)

const inboundUsage = `ark inbound — operator-host C2 reachability (no implant opcode)

  ark inbound                 same as status
  ark inbound status          tun0, listeners, proxy env, firewall vs C2 port
  ark inbound env [--port N]  print ALL_PROXY exports for C SOCKS (default 1080)
  ark inbound drop user@H [--out PATH] [--local 8443] [--remote 8443]
  ark inbound httpdrop --callback https://TUN0:1750 --dir DIR [--listen ADDR]  # --listen blocks
  ark inbound redirector start [--listen 0.0.0.0:1750] [--to 127.0.0.1:8443] [--background]
  ark inbound redirector stop|status
  ark inbound through [--port 1080] [--session ID] [--probe HOST:PORT]
  ark inbound close user@H
  ark inbound tunnel user@H [--local 8443] [--remote 8443]   # foreground ssh -N

drop = SSH reverse tunnel + op generate (secret registered).
httpdrop = op generate + HTTP fetch one-liner (no SSH; HTB filters :22).
redirector = TCP passthrough (1750 or 443) → teamserver; no TLS terminate.
through = socks start + env. close tears the ControlMaster.

  ark inbound httpdrop --callback https://<tun0>:1750 --dir /tmp/www --listen 0.0.0.0:1723  # blocks on Serve
  ark inbound drop user@TARGET
  ark inbound through --probe DC:389
  eval "$(ark inbound env)"

Do not use make implant-c-linux on this path (HMAC secret never hits the DB).
Host ldap/smb/ad/kerberos honor ARK_PROXY / ALL_PROXY (SOCKS5).
Lab-only. See docs/OPERATOR_INBOUND.md
`

// RunInbound dispatches inbound status / env / tunnel / drop / through / close.
func RunInbound(args []string) error {
	if len(args) < 1 {
		return inboundStatus()
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(inboundUsage)
		return nil
	case "status":
		return inboundStatus()
	case "env":
		return inboundEnv(args[1:])
	case "tunnel":
		return inboundTunnel(args[1:])
	case "drop":
		return inboundDrop(args[1:])
	case "httpdrop", "http-drop":
		return inboundHTTPDrop(args[1:])
	case "redirector", "redir", "redirect":
		return inboundRedirector(args[1:])
	case "through":
		return inboundThrough(args[1:])
	case "close":
		return inboundClose(args[1:])
	default:
		// bare user@host → tunnel
		if strings.Contains(args[0], "@") {
			return inboundTunnel(args)
		}
		return fmt.Errorf("unknown inbound command %q\n%s", args[0], inboundUsage)
	}
}

func inboundStatus() error {
	fmt.Print(FormatStatus(CollectStatus()))
	return nil
}

func inboundEnv(args []string) error {
	f, _ := ParseFlags(args)
	port := 1080
	if p := first(f, "port"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return fmt.Errorf("--port must be 1-65535")
		}
		port = n
	}
	fmt.Print(EnvExports(port))
	return nil
}

func inboundTunnel(args []string) error {
	f, bare := ParseFlags(args)
	target := first(f, "target", "host")
	if target == "" && len(bare) > 0 {
		target = bare[0]
	}
	local := 8443
	remote := 8443
	if p := first(f, "local", "local-port"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 {
			return fmt.Errorf("--local must be a port")
		}
		local = n
	}
	if p := first(f, "remote", "remote-port"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 {
			return fmt.Errorf("--remote must be a port")
		}
		remote = n
	}
	argv, err := TunnelArgs(target, local, remote)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "inbound tunnel: %s\n", strings.Join(argv, " "))
	fmt.Fprintf(os.Stderr, "build implant with CALLBACK_URL=https://127.0.0.1:%d\n", remote)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Status is a snapshot of operator-host C2 reachability.
type Status struct {
	Tun0             []string
	HTTPS            []string // "up 127.0.0.1:443"
	GRPC             []string
	Proxy            string
	ProxyNote        string // set when ALL_PROXY is not SOCKS5
	FirewallPorts    string
	HintPorts        []int    // https ports for firewall hint
	FirewallMismatch []string // "8443/tcp not in firewalld"
	Redirector       RedirectorState
}

type inboundYAML struct {
	GRPCAddr  string `yaml:"grpc_addr"`
	Listeners []struct {
		Protocol string `yaml:"protocol"`
		Host     string `yaml:"host"`
		Port     uint32 `yaml:"port"`
	} `yaml:"listeners"`
}

// CollectStatus probes tun0, configured listeners, proxy env, firewalld.
func CollectStatus() Status {
	return CollectStatusFrom(defaultServerYAML())
}

// CollectStatusFrom reads listener/gRPC addrs from a server.yaml (or defaults).
func CollectStatusFrom(configPath string) Status {
	httpsPorts, grpcAddr := loadListenTargets(configPath)
	tun := tun0Addrs()
	s := Status{
		Tun0:          tun,
		Proxy:         netproxy.ProxyEnv(),
		FirewallPorts: firewallPorts(),
		HintPorts:     httpsPorts,
		Redirector:    LoadRedirectorState(),
	}
	if p, err := portOfAddr(s.Redirector.Listen); err == nil && p > 0 {
		httpsPorts = uniqInts(append(httpsPorts, p))
		s.HintPorts = httpsPorts
	}
	if s.Proxy != "" && netproxy.SOCKSProxy() == "" {
		s.ProxyNote = "ignored (only socks5); host ldap/smb dial direct"
	}
	hosts := []string{"127.0.0.1"}
	hosts = append(hosts, tun0IPs(tun)...)
	for _, p := range httpsPorts {
		s.HTTPS = append(s.HTTPS, probeHosts(hosts, p)...)
	}
	for _, p := range httpsPorts {
		if s.FirewallPorts != "" && !FirewallAllowsPort(s.FirewallPorts, p) {
			s.FirewallMismatch = append(s.FirewallMismatch, strconv.Itoa(p)+"/tcp")
		}
	}
	if h, p, err := net.SplitHostPort(grpcAddr); err == nil {
		if h == "" || h == "0.0.0.0" || h == "::" {
			h = "127.0.0.1"
		}
		s.GRPC = []string{probeAddr(net.JoinHostPort(h, p))}
	} else {
		s.GRPC = []string{probeAddr(grpcAddr)}
	}
	return s
}

func loadListenTargets(configPath string) (httpsPorts []int, grpcAddr string) {
	grpcAddr = "127.0.0.1:50051"
	httpsPorts = []int{1750, 8443}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return httpsPorts, grpcAddr
	}
	var y inboundYAML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return httpsPorts, grpcAddr
	}
	if y.GRPCAddr != "" {
		grpcAddr = y.GRPCAddr
	}
	var fromCfg []int
	for _, l := range y.Listeners {
		if !strings.EqualFold(l.Protocol, "https") && l.Protocol != "" {
			continue
		}
		if l.Port == 0 {
			continue
		}
		fromCfg = append(fromCfg, int(l.Port))
	}
	if len(fromCfg) > 0 {
		return uniqInts(fromCfg), grpcAddr
	}
	return httpsPorts, grpcAddr
}

func defaultServerYAML() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ark", "server.yaml")
}

// FormatStatus is the human status block.
func FormatStatus(s Status) string {
	var b strings.Builder
	b.WriteString("ark inbound status\n")
	if len(s.Tun0) == 0 {
		b.WriteString("  tun0:          down (HTB VPN not up?)\n")
	} else {
		b.WriteString("  tun0:          " + strings.Join(s.Tun0, " ") + "\n")
	}
	if len(s.HTTPS) == 0 {
		b.WriteString("  https:         (no ports)\n")
	} else {
		for i, line := range s.HTTPS {
			if i == 0 {
				b.WriteString("  https:         " + line + "\n")
			} else {
				b.WriteString("                 " + line + "\n")
			}
		}
	}
	if len(s.GRPC) == 0 {
		b.WriteString("  grpc:          (none)\n")
	} else {
		b.WriteString("  grpc:          " + strings.Join(s.GRPC, " ") + "\n")
	}
	if s.Proxy == "" {
		b.WriteString("  proxy:         (none — host ldap/smb use direct dial)\n")
	} else if s.ProxyNote != "" {
		b.WriteString("  proxy:         " + s.Proxy + " — " + s.ProxyNote + "\n")
	} else {
		b.WriteString("  proxy:         " + s.Proxy + "\n")
	}
	if s.FirewallPorts == "" {
		b.WriteString("  firewalld:     (firewall-cmd not available or no ports)\n")
	} else {
		b.WriteString("  firewalld:     " + s.FirewallPorts + "\n")
	}
	if len(s.FirewallMismatch) > 0 {
		b.WriteString("  MISMATCH:      listener " + strings.Join(s.FirewallMismatch, ", ") + " not in firewalld (target cannot hit tun0)\n")
	}
	if s.Redirector.PID > 0 && s.Redirector.Listen != "" {
		b.WriteString(fmt.Sprintf("  redirector:    up %s -> %s pid=%d\n", s.Redirector.Listen, s.Redirector.To, s.Redirector.PID))
	} else {
		b.WriteString("  redirector:    down\n")
	}
	b.WriteString("\nnext:\n")
	if len(s.Tun0) == 0 {
		b.WriteString("  bring HTB VPN up, then re-run ark inbound status\n")
	}
	if !anyUp(s.HTTPS) {
		b.WriteString("  ark teamserver          # C2 daemon\n")
	}
	b.WriteString("  ark inbound drop user@TARGET     # tunnel + generate (secret in DB)\n")
	b.WriteString("  ark inbound through              # socks start + env; then eval \"$(ark inbound env)\"\n")
	b.WriteString("  ark inbound tunnel user@TARGET   # foreground ssh -N only\n")
	b.WriteString("  ark inbound redirector start     # 1750/443 TCP passthrough to teamserver\n")
	fwPort := 1750
	if len(s.FirewallMismatch) > 0 {
		if n, err := strconv.Atoi(strings.TrimSuffix(s.FirewallMismatch[0], "/tcp")); err == nil {
			fwPort = n
		}
	} else if len(s.HintPorts) > 0 {
		fwPort = s.HintPorts[0]
	}
	b.WriteString(fmt.Sprintf("  sudo firewall-cmd --add-port=%d/tcp   # if target cannot hit tun0\n", fwPort))
	b.WriteString("  ark inbound httpdrop --callback https://<tun0>:1750 --dir DIR  # no SSH\n")
	if s.Redirector.PID == 0 {
		b.WriteString("  ark inbound redirector start --listen 0.0.0.0:1750 --to 127.0.0.1:8443\n")
		b.WriteString("  ark inbound redirector start --listen 0.0.0.0:443 --to 127.0.0.1:8443 --allow-priv-ports\n")
	}
	return b.String()
}

// FirewallAllowsPort reports whether firewall-cmd --list-ports covers TCP port.
// Understands "8443/tcp" and ranges "1714-1764/tcp".
func FirewallAllowsPort(list string, port int) bool {
	if port <= 0 || strings.TrimSpace(list) == "" {
		return false
	}
	for _, tok := range strings.Fields(list) {
		tok = strings.ToLower(tok)
		if strings.HasSuffix(tok, "/udp") {
			continue
		}
		tok = strings.TrimSuffix(tok, "/tcp")
		if a, b, ok := strings.Cut(tok, "-"); ok {
			lo, err1 := strconv.Atoi(a)
			hi, err2 := strconv.Atoi(b)
			if err1 == nil && err2 == nil && port >= lo && port <= hi {
				return true
			}
			continue
		}
		p, err := strconv.Atoi(tok)
		if err == nil && p == port {
			return true
		}
	}
	return false
}

// EnvExports prints shell exports for SOCKS.
func EnvExports(port int) string {
	if port <= 0 {
		port = 1080
	}
	u := fmt.Sprintf("socks5://127.0.0.1:%d", port)
	return fmt.Sprintf("export ALL_PROXY=%s\nexport all_proxy=%s\nexport ARK_PROXY=%s\n", u, u, u)
}

// TunnelArgs builds `ssh -N -R remote:127.0.0.1:local target`.
func TunnelArgs(target string, local, remote int) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" || !strings.Contains(target, "@") {
		return nil, fmt.Errorf("usage: ark inbound tunnel user@HOST")
	}
	if local <= 0 {
		local = 8443
	}
	if remote <= 0 {
		remote = 8443
	}
	fwd := fmt.Sprintf("%d:127.0.0.1:%d", remote, local)
	return []string{
		"ssh", "-N",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=30",
		"-R", fwd,
		target,
	}, nil
}

func tun0Addrs() []string {
	ifi, err := net.InterfaceByName("tun0")
	if err != nil {
		return nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func tun0IPs(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			if host, _, err2 := net.SplitHostPort(a); err2 == nil {
				out = append(out, host)
			}
			continue
		}
		out = append(out, ip.String())
	}
	return uniqStrings(out)
}

func probeHosts(hosts []string, port int) []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range hosts {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, probeAddr(net.JoinHostPort(h, strconv.Itoa(port))))
	}
	return out
}

func probeAddr(addr string) string {
	c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return "down " + addr
	}
	c.Close()
	return "up   " + addr
}

func anyUp(lines []string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, "up") {
			return true
		}
	}
	return false
}

func uniqInts(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, n := range in {
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func firewallPorts() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "firewall-cmd", "--list-ports")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
