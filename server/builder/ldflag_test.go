package builder

import (
	"strings"
	"testing"
)

func TestValidateLdflagValue(t *testing.T) {
	for _, val := range []string{"https://10.0.0.1:1750", "dc.lab.htb", "10.0.0.1"} {
		if err := validateLdflagValue(val, "value"); err != nil {
			t.Fatalf("%q: %v", val, err)
		}
	}
	for _, val := range []string{"https://x\nid", "dc.lab.htb#evil", "has space", "a$b", "quo'te", "a\"b", "a`b", "a\\b"} {
		if err := validateLdflagValue(val, "value"); err == nil {
			t.Fatalf("%q was accepted", val)
		}
	}
}

func TestBuildCRejectsBadDNSServerBeforeMake(t *testing.T) {
	_, err := BuildC(&BuildRequest{
		OS:          "linux",
		Arch:        "amd64",
		Format:      FormatEXE,
		Transport:   "dns",
		Callbacks:   []string{"https://127.0.0.1:1750"},
		DNSDomain:   "lab.htb",
		DNSServer:   "8.8.8.8\nid",
		ProjectRoot: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("error %v", err)
	}
	if strings.Contains(err.Error(), "Makefile") || strings.Contains(strings.ToLower(err.Error()), "make:") {
		t.Fatalf("make was reached: %v", err)
	}
}
