package mqttcli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildHealthcheckJSON(t *testing.T) {
	b, err := BuildHealthcheckJSON(HealthcheckOptions{
		URL:  "http://10.10.14.15:8888",
		Node: "node-6",
		IP:   "172.16.20.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	var p HealthcheckPayload
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if p.Telemetry.URL != "http://10.10.14.15:8888" {
		t.Fatalf("url=%q", p.Telemetry.URL)
	}
	if p.Node != "node-6" {
		t.Fatalf("node=%q", p.Node)
	}
	if !p.Telemetry.Healthy {
		t.Fatal("expected healthy")
	}
	if p.Telemetry.IP != "172.16.20.10" {
		t.Fatalf("ip=%q", p.Telemetry.IP)
	}
	if !strings.Contains(p.Timestamp, "-") {
		t.Fatalf("timestamp format: %q", p.Timestamp)
	}
}

func TestBuildHealthcheckJSONRejectsBadURL(t *testing.T) {
	cases := []string{"", "not-a-url", "ftp://x", "//host/path"}
	for _, u := range cases {
		if _, err := BuildHealthcheckJSON(HealthcheckOptions{URL: u}); err == nil {
			t.Fatalf("expected error for %q", u)
		}
	}
}
