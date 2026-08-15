package krb

import (
	"testing"
	"time"
)

func TestFaketimeOffset(t *testing.T) {
	if got := FaketimeOffset(7 * time.Hour); got != "+7h" {
		t.Fatalf("7h got %q", got)
	}
	if got := FaketimeOffset(-90 * time.Second); got != "-1m30s" {
		t.Fatalf("-90s got %q", got)
	}
}
