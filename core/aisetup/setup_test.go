package aisetup

import "testing"

func TestWizardPhase(t *testing.T) {
	cases := []struct {
		s    step
		n    int
		name string
	}{
		{stepProvider, 1, "Provider"},
		{stepOllamaMode, 2, "Connection"},
		{stepOllamaHost, 2, "Connection"},
		{stepAuth, 2, "Connection"},
		{stepKey, 2, "Connection"},
		{stepModel, 3, "Model"},
		{stepCustomModel, 3, "Model"},
		{stepVerify, 4, "Verify"},
		{stepDone, 4, "Verify"},
	}
	for _, tc := range cases {
		n, name := wizardPhase(tc.s)
		if n != tc.n || name != tc.name {
			t.Fatalf("step %d: got %d/%s want %d/%s", tc.s, n, name, tc.n, tc.name)
		}
	}
}

func TestLocality(t *testing.T) {
	if g := locality("ollama", "http://localhost:11434/v1"); g != "Local" {
		t.Fatal(g)
	}
	if g := locality("anthropic", ""); g != "Cloud" {
		t.Fatal(g)
	}
}
