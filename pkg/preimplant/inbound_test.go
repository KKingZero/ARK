package preimplant

import (
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
	if !strings.Contains(s, "EREBUS_PROXY=socks5://127.0.0.1:1080") {
		t.Fatal(s)
	}
	s = EnvExports(0)
	if !strings.Contains(s, ":1080") {
		t.Fatal("default port", s)
	}
}

func TestFormatStatusHints(t *testing.T) {
	out := FormatStatus(Status{
		HTTPS: "down :8443",
		GRPC:  "down :50051",
	})
	if !strings.Contains(out, "erebus teamserver") {
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
