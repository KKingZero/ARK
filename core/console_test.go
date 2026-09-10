package core

import (
	"strings"
	"testing"
)

func TestParseLineStripsArkPrefix(t *testing.T) {
	cmd, args := parseLine("ark serve")
	if cmd != "serve" || len(args) != 0 {
		t.Fatalf("ark serve -> %q %v", cmd, args)
	}
	cmd, args = parseLine("serve")
	if cmd != "serve" || len(args) != 0 {
		t.Fatalf("serve -> %q %v", cmd, args)
	}
	cmd, args = parseLine("ark ai hello world")
	if cmd != "ai" || strings.Join(args, " ") != "hello world" {
		t.Fatalf("ark ai hello world -> %q %v", cmd, args)
	}
	cmd, args = parseLine("ark")
	if cmd != "ark" || args != nil {
		t.Fatalf("bare ark -> %q %v", cmd, args)
	}
	cmd, _ = parseLine("  help serve  ")
	if cmd != "help" {
		t.Fatalf("help serve cmd=%q", cmd)
	}
}

func TestPromptTag(t *testing.T) {
	if g := promptTag(false, ""); g != "offline" {
		t.Fatalf("got %q", g)
	}
	if g := promptTag(true, ""); g != "online" {
		t.Fatalf("got %q", g)
	}
	if g := promptTag(true, "lobster-lab"); g != "lobster-lab" {
		t.Fatalf("got %q", g)
	}
	if g := promptTag(false, "acme"); g != "acme" {
		t.Fatalf("engagement should win, got %q", g)
	}
}

func TestReplHelpOmitsBinaryPrefix(t *testing.T) {
	h := replHelpText()
	if strings.Contains(h, "ark serve") {
		t.Fatal("in-shell help must not list ark serve")
	}
	if !strings.Contains(h, "  serve") {
		t.Fatal("expected serve as an in-shell command")
	}
	if !strings.Contains(h, "engagements") {
		t.Fatal("expected engagements")
	}
	if !strings.Contains(h, "status") {
		t.Fatal("expected status")
	}
}

func TestCommandHelpServe(t *testing.T) {
	msg := commandHelp("serve")
	if msg == "" || strings.Contains(msg, "Unknown") {
		t.Fatal(msg)
	}
	if !strings.Contains(msg, "Inside ARK, type serve") {
		t.Fatal(msg)
	}
}

func TestFormatStatusAndServe(t *testing.T) {
	st := RuntimeStatus{
		Teamserver: true,
		Operator:   true,
		GRPCAddr:   "127.0.0.1:50051",
		Listeners:  []string{"HTTPS :1750"},
		Sessions:   3,
		AIProvider: "ollama",
		AIModel:    "gemma4:latest",
		Engagement: "ACME External",
		Approval:   "required",
	}
	got := formatStatus(st)
	for _, want := range []string{"● running", "● connected", "HTTPS :1750", "3 active", "Ollama / gemma4:latest", "ACME External"} {
		if !strings.Contains(got, want) {
			t.Fatalf("status missing %q\n%s", want, got)
		}
	}
	up := formatServeOK(st)
	if !strings.Contains(up, "✓ Teamserver running") {
		t.Fatal(up)
	}
	if !strings.Contains(up, "127.0.0.1:50051") || !strings.Contains(up, ":1750") {
		t.Fatal(up)
	}
}

func TestHandleCommandUnknownAndArkBare(t *testing.T) {
	c := NewConsole(true)
	c.handleCommand("nope")
	c.handleCommand("ark")
	c.handleCommand("help")
	c.handleCommand("help serve")
}
