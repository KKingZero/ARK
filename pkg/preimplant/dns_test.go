package preimplant

import (
	"strings"
	"testing"
)

func TestRunDNSHelp(t *testing.T) {
	if err := RunDNS([]string{"help"}); err != nil {
		t.Fatal(err)
	}
}

func TestDNSAddRequiresYes(t *testing.T) {
	err := RunDNS([]string{"add", "--dc", "10.0.0.1", "--domain", "a.htb", "--user", "u", "--pass-file", "p", "--name", "testdns", "--data", "10.1.2.3"})
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("got %v", err)
	}
}
