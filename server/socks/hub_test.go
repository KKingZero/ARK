package socks

import "testing"

func TestStopAllIdempotent(t *testing.T) {
	h := NewHub()
	h.StopAll()
	port, err := h.StartForSession("s1", 18791)
	if err != nil {
		t.Fatal(err)
	}
	if port == 0 {
		t.Fatal("expected port")
	}
	h.StopAll()
	h.StopAll()
	if h.Active("s1") {
		t.Fatal("expected stopped")
	}
}
