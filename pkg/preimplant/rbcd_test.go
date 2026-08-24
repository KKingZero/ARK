package preimplant

import (
	"strings"
	"testing"
)

func TestRunRBCDHelp(t *testing.T) {
	if err := RunRBCD([]string{"help"}); err != nil {
		t.Fatal(err)
	}
}

func TestRunRBCDUnknown(t *testing.T) {
	err := RunRBCD([]string{"explode"})
	if err == nil || !strings.Contains(err.Error(), "unknown rbcd") {
		t.Fatalf("got %v", err)
	}
}

func TestRunRBCDWriteRequiresYes(t *testing.T) {
	err := RunRBCD([]string{"write", "--dc", "127.0.0.1", "--domain", "x.htb", "--to", "DC$", "--from", "ATTACK$"})
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("got %v", err)
	}
}

func TestRunRBCDWriteRequiresToFrom(t *testing.T) {
	err := RunRBCD([]string{"write", "--dc", "127.0.0.1", "--yes"})
	if err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("got %v", err)
	}
}
