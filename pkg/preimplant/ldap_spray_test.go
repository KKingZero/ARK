package preimplant

import (
	"strings"
	"testing"
	"time"
)

func TestParseSprayDelay(t *testing.T) {
	d, err := parseSprayDelay("")
	if err != nil || d != 2*time.Second {
		t.Fatalf("default %v %v", d, err)
	}
	if _, err := parseSprayDelay("0s"); err == nil {
		t.Fatal("0s must fail")
	}
	if _, err := parseSprayDelay("1s"); err == nil || !strings.Contains(err.Error(), "2s") {
		t.Fatalf("1s: %v", err)
	}
	d, err = parseSprayDelay("3s")
	if err != nil || d != 3*time.Second {
		t.Fatalf("3s %v %v", d, err)
	}
}

func TestLDAPSprayRequiresYes(t *testing.T) {
	err := ldapSpray([]string{"--dc", "10.0.0.1", "--domain", "a.htb", "--user-file", "u", "--pass-file", "p"})
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("got %v", err)
	}
}

func TestLDAPEnableRequiresYes(t *testing.T) {
	err := ldapEnableDisable([]string{"--dc", "10.0.0.1", "--domain", "a.htb", "--user", "u", "--pass-file", "p", "--target", "m.carter"}, false)
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("got %v", err)
	}
}
