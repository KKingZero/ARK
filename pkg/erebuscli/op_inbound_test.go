package erebuscli

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
