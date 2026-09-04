package arkcli

import "testing"

func TestRunOpInboundNoCerts(t *testing.T) {
	// inbound must not require teamserver certs
	if err := RunOp(OpOptions{}, []string{"inbound", "env", "--port", "1080"}); err != nil {
		t.Fatal(err)
	}
	if err := RunOp(OpOptions{}, []string{"inbound", "help"}); err != nil {
		t.Fatal(err)
	}
}

func TestOpGenerateValidatesTransportBeforeDial(t *testing.T) {
	err := RunOp(OpOptions{}, []string{
		"generate",
		"--callback", "https://127.0.0.1:8443",
		"--transport", "ftp",
	})
	if err == nil || err.Error() != "--transport must be https or dns" {
		t.Fatalf("expected transport validation error, got %v", err)
	}
}

func TestOpGenerateDNSRequiresDomainBeforeDial(t *testing.T) {
	err := RunOp(OpOptions{}, []string{
		"generate",
		"--callback", "https://127.0.0.1:8443",
		"--transport", "dns",
	})
	if err == nil || err.Error() != "--dns-domain required when --transport dns" {
		t.Fatalf("expected dns-domain validation error, got %v", err)
	}
}
