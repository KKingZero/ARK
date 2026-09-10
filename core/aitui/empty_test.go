package aitui

import "strings"
import "testing"

func TestEmptyStateOfflinePointsAtServe(t *testing.T) {
	s := emptyState(false)
	if !strings.Contains(s, "/serve") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "No active operation") {
		t.Fatal(s)
	}
	if strings.Contains(s, "ark serve") {
		t.Fatal("AI view must not tell users to type ark serve")
	}
}

func TestEmptyStateOnline(t *testing.T) {
	s := emptyState(true)
	if !strings.Contains(s, "Active operation") {
		t.Fatal(s)
	}
}

func TestNavHelpGrammar(t *testing.T) {
	s := navHelpText()
	for _, want := range []string{"Esc", "Tab", "?", "/serve"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in %s", want, s)
		}
	}
}
