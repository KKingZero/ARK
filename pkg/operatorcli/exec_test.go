package operatorcli

import "testing"

func TestParseGenerateRejectsBadTransport(t *testing.T) {
	_, err := parseGenerateArgs([]string{"--callback", "https://127.0.0.1:8443", "--transport", "ftp"})
	if err == nil || err.Error() != "--transport must be https or dns" {
		t.Fatalf("got %v", err)
	}
}

func TestParseGenerateCallbackTimeAlias(t *testing.T) {
	got, err := parseGenerateArgs([]string{"--callback-time", "2000", "--jitter-pct", "25"})
	if err != nil {
		t.Fatal(err)
	}
	if got.sleepMs != 2000 || got.jitter != 25 {
		t.Fatalf("sleep=%d jitter=%d", got.sleepMs, got.jitter)
	}
}

func TestParseGenerateRejectsBadTiming(t *testing.T) {
	for _, args := range [][]string{
		{"--sleep", "99"},
		{"--sleep", "86400001"},
		{"--jitter", "-1"},
		{"--jitter", "101"},
	} {
		if _, err := parseGenerateArgs(args); err == nil {
			t.Fatalf("expected error for %v", args)
		}
	}
}

func TestShellCommandFromArgsStripsMarker(t *testing.T) {
	got, err := shellCommandFromArgs([]string{"--", "id"})
	if err != nil || got != "id" {
		t.Fatalf("strip --: got %q err %v", got, err)
	}
	got, err = shellCommandFromArgs([]string{"ls", "-la", "/home"})
	if err != nil || got != "ls -la /home" {
		t.Fatalf("join: got %q err %v", got, err)
	}
	if _, err := shellCommandFromArgs([]string{"--"}); err == nil {
		t.Fatal("bare -- should fail")
	}
}

func TestPeelSessionFlag(t *testing.T) {
	sid, rest := peelSessionFlag([]string{"--session", "abc", "whoami"})
	if sid != "abc" || len(rest) != 1 || rest[0] != "whoami" {
		t.Fatalf("%q %v", sid, rest)
	}
}

func TestSplitSessionSelector(t *testing.T) {
	got := splitSessionSelector("a, b,,c")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}
