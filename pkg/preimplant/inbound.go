package preimplant

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/netproxy"
)

const inboundUsage = `erebus inbound — operator-host C2 reachability (no implant opcode)

  erebus inbound                 same as status
  erebus inbound status          tun0, listeners, proxy env, firewall ports
  erebus inbound env [--port N]  print ALL_PROXY exports for C SOCKS (default 1080)
  erebus inbound tunnel user@H [--local 8443] [--remote 8443]

When the box cannot reach tun0, tunnel makes C2 appear on target localhost:
  CALLBACK_URL=https://127.0.0.1:8443

When the operator host cannot reach the DC, start C SOCKS then:
  eval "$(erebus inbound env --port 1080)"
  erebus ldap enum --dc DC --domain DOM --user u --pass-file p --type interesting

Host ldap/smb/ad/kerberos honor EREBUS_PROXY / ALL_PROXY (SOCKS5).
Lab-only. See docs/OPERATOR_INBOUND.md
`

// RunInbound dispatches inbound status / env / tunnel.
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
	Tun0          []string
	HTTPS         string // "up :8443" or "down :8443"
	GRPC          string
	Proxy         string
	FirewallPorts string
}

// CollectStatus probes tun0, local listeners, proxy env, firewalld.
func CollectStatus() Status {
	s := Status{
		Tun0:          tun0Addrs(),
		HTTPS:         probeLocal(8443),
		GRPC:          probeLocal(50051),
		Proxy:         netproxy.ProxyEnv(),
		FirewallPorts: firewallPorts(),
	}
	return s
}

// FormatStatus is the human status block.
func FormatStatus(s Status) string {
	var b strings.Builder
	b.WriteString("erebus inbound status\n")
	if len(s.Tun0) == 0 {
		b.WriteString("  tun0:          down (HTB VPN not up?)\n")
	} else {
		b.WriteString("  tun0:          " + strings.Join(s.Tun0, " ") + "\n")
	}
	b.WriteString("  https :8443:   " + s.HTTPS + "\n")
	b.WriteString("  grpc  :50051:  " + s.GRPC + "\n")
	if s.Proxy == "" {
		b.WriteString("  proxy:         (none — host ldap/smb use direct dial)\n")
	} else {
		b.WriteString("  proxy:         " + s.Proxy + "\n")
	}
	if s.FirewallPorts == "" {
		b.WriteString("  firewalld:     (firewall-cmd not available or no ports)\n")
	} else {
		b.WriteString("  firewalld:     " + s.FirewallPorts + "\n")
	}
	b.WriteString("\nnext:\n")
	if len(s.Tun0) == 0 {
		b.WriteString("  bring HTB VPN up, then re-run erebus inbound status\n")
	}
	if !strings.HasPrefix(s.HTTPS, "up") {
		b.WriteString("  erebus teamserver          # C2 on :8443\n")
	}
	b.WriteString("  erebus inbound tunnel user@TARGET   # box cannot reach tun0\n")
	b.WriteString("  erebus op socks start --port 1080   # then: eval \"$(erebus inbound env)\"\n")
	b.WriteString("  sudo firewall-cmd --add-port=8443/tcp   # if target cannot hit tun0:8443\n")
	return b.String()
}

// EnvExports prints shell exports for SOCKS.
func EnvExports(port int) string {
	if port <= 0 {
		port = 1080
	}
	u := fmt.Sprintf("socks5://127.0.0.1:%d", port)
	return fmt.Sprintf("export ALL_PROXY=%s\nexport all_proxy=%s\nexport EREBUS_PROXY=%s\n", u, u, u)
}

// TunnelArgs builds `ssh -N -R remote:127.0.0.1:local target`.
func TunnelArgs(target string, local, remote int) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" || !strings.Contains(target, "@") {
		return nil, fmt.Errorf("usage: erebus inbound tunnel user@HOST")
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

func probeLocal(port int) string {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return "down :" + strconv.Itoa(port)
	}
	c.Close()
	return "up   :" + strconv.Itoa(port)
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
