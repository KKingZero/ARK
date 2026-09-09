package theme

import (
	"strings"
	"testing"
)

func TestAccentIsCyanNotCrimson(t *testing.T) {
	if Cyan == "#DC143C" {
		t.Fatal("accent still crimson")
	}
	if !strings.EqualFold(Cyan, "#00C8E0") {
		t.Fatalf("Cyan=%s", Cyan)
	}
	if ANSIAccent == "\033[1;38;5;196m" {
		t.Fatal("ANSI accent still red")
	}
}
