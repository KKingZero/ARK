package crypto

import (
	"strings"
	"testing"
	"time"
)

func TestVerifyHMAC_AcceptsUnixSecondsAndMillis(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	id := "implant-test"

	sec := time.Now().Unix()
	macSec := ComputeHMAC(secret, id, sec)
	if err := VerifyHMAC(secret, id, sec, macSec, 30); err != nil {
		t.Fatalf("seconds: %v", err)
	}

	ms := time.Now().UnixMilli()
	macMs := ComputeHMAC(secret, id, ms)
	if err := VerifyHMAC(secret, id, ms, macMs, 30); err != nil {
		t.Fatalf("millis: %v", err)
	}
}

func TestVerifyHMAC_RejectsStale(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	id := "implant-test"
	ts := time.Now().Unix() - 120
	mac := ComputeHMAC(secret, id, ts)
	if err := VerifyHMAC(secret, id, ts, mac, 30); err == nil {
		t.Fatal("expected stale timestamp error")
	}
}

// HTB hosts are often 6–8h off operator UTC. Production window is 8h absolute
// (server/listeners/beacon.go). If this fails, offset negotiation is required;
// if it passes, the remaining tax is operator-visible diagnosis, not a wider window.
const htbHMACWindowSec = 8 * 3600

func TestVerifyHMAC_HTBSkewInside8hWindow(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	id := "implant-htb"
	for _, off := range []time.Duration{
		7 * time.Hour,
		-7 * time.Hour,
		6 * time.Hour,
		8 * time.Hour, // diff == window; VerifyHMAC uses > not >=
	} {
		ts := time.Now().Add(off).UnixMilli()
		mac := ComputeHMAC(secret, id, ts)
		if err := VerifyHMAC(secret, id, ts, mac, htbHMACWindowSec); err != nil {
			t.Fatalf("offset %v should pass 8h window: %v", off, err)
		}
	}
}

func TestVerifyHMAC_9hOutside8hWindow(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	id := "implant-htb"
	ts := time.Now().Add(9 * time.Hour).UnixMilli()
	mac := ComputeHMAC(secret, id, ts)
	err := VerifyHMAC(secret, id, ts, mac, htbHMACWindowSec)
	if err == nil {
		t.Fatal("9h skew should fail the 8h window")
	}
	if !strings.Contains(err.Error(), "replay window") {
		t.Fatalf("want replay-window error, got %v", err)
	}
}
