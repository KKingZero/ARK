package builder

import (
	"strings"
	"testing"
)

func TestBuild_DefaultLanguageIsC(t *testing.T) {
	// Empty language → C path. HTTPS without CACertPath fails closed.
	_, err := Build(&BuildRequest{
		Language:  "",
		OS:        "linux",
		Arch:      "amd64",
		Format:    FormatEXE,
		Transport: "https",
	})
	if err == nil {
		t.Fatal("expected error for C HTTPS without CACertPath")
	}
	if !strings.Contains(err.Error(), "CACertPath") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuild_GoLinuxArchived(t *testing.T) {
	_, err := Build(&BuildRequest{
		Language:  "go",
		OS:        "linux",
		Arch:      "amd64",
		Format:    FormatEXE,
		Callbacks: []string{"https://127.0.0.1:443"},
	})
	if err == nil || !strings.Contains(err.Error(), "archived") {
		t.Fatalf("want go linux archived, got %v", err)
	}
}

func TestBuild_ExplicitGoWindowsStillAccepted(t *testing.T) {
	_, err := Build(&BuildRequest{
		Language:   "go",
		OS:         "windows",
		Arch:       "amd64",
		Format:     FormatEXE,
		Callbacks:  []string{"https://127.0.0.1:443"},
		SleepMs:    5000,
		JitterPct:  10,
		CACertPath: "/nonexistent-ca-for-test.pem",
	})
	if err != nil && strings.Contains(err.Error(), "unsupported implant language") {
		t.Fatalf("go windows rejected: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "archived") {
		t.Fatalf("go windows must not be archived: %v", err)
	}
}

func TestBuild_HTTPSRequiresCACertPath(t *testing.T) {
	_, err := Build(&BuildRequest{
		Language:  "go",
		OS:        "windows",
		Arch:      "amd64",
		Format:    FormatEXE,
		Transport: "https",
		Callbacks: []string{"https://127.0.0.1:443"},
		SleepMs:   5000,
		JitterPct: 10,
	})
	if err == nil {
		t.Fatal("expected error when CACertPath missing for HTTPS")
	}
	if !strings.Contains(err.Error(), "CACertPath") {
		t.Fatalf("expected CACertPath error, got: %v", err)
	}
}

func TestBuild_GoRejectsCDNDomain(t *testing.T) {
	_, err := Build(&BuildRequest{
		Language:   "go",
		OS:         "windows",
		Arch:       "amd64",
		Format:     FormatEXE,
		Transport:  "https",
		Callbacks:  []string{"https://127.0.0.1:443"},
		CDNDomain:  "cdn.example.com",
		CACertPath: "/nonexistent-ca-for-test.pem",
	})
	if err == nil {
		t.Fatal("expected CDNDomain rejection")
	}
	if !strings.Contains(err.Error(), "CDNDomain") {
		t.Fatalf("expected CDNDomain error, got: %v", err)
	}
}

func TestBuildC_LinuxDLLRejected(t *testing.T) {
	_, err := BuildC(&BuildRequest{
		Language: "c",
		OS:       "linux",
		Arch:     "amd64",
		Format:   FormatDLL,
	})
	if err == nil || !strings.Contains(err.Error(), "exe") {
		t.Fatalf("want linux C dll rejected, got %v", err)
	}
}
