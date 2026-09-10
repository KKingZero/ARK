package operatorcli

import "testing"

func TestParseGenerateRejectsBadTransport(t *testing.T) {
	_, err := parseGenerateArgs([]string{"--callback", "https://127.0.0.1:8443", "--transport", "ftp"})
	if err == nil || err.Error() != "--transport must be https or dns" {
		t.Fatalf("got %v", err)
	}
}

func TestPeelSessionFlag(t *testing.T) {
	sid, rest := peelSessionFlag([]string{"--session", "abc", "whoami"})
	if sid != "abc" || len(rest) != 1 || rest[0] != "whoami" {
		t.Fatalf("%q %v", sid, rest)
	}
}
