package ldapcli

import (
	"encoding/binary"
	"testing"
)

func TestGenerateKeyCredential(t *testing.T) {
	got, err := GenerateKeyCredential("svc-aegis-build")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Blob) < 32 || binary.LittleEndian.Uint32(got.Blob[:4]) != keyCredBlobVersion {
		t.Fatalf("blob ver %x len %d", got.Blob[:4], len(got.Blob))
	}
	if len(got.PFX) < 64 {
		t.Fatalf("pfx %d", len(got.PFX))
	}
	var zero [16]byte
	if got.DeviceID == zero {
		t.Fatal("device id")
	}
	off := 4
	sawMaterial, sawID := false, false
	for off+3 <= len(got.Blob) {
		ln := int(binary.LittleEndian.Uint16(got.Blob[off : off+2]))
		id := got.Blob[off+2]
		if off+3+ln > len(got.Blob) {
			t.Fatalf("trunc id=%d ln=%d", id, ln)
		}
		if id == keyCredKeyMaterial {
			sawMaterial = true
		}
		if id == keyCredKeyID && ln == 32 {
			sawID = true
		}
		off += 3 + ln
	}
	if !sawMaterial || !sawID {
		t.Fatalf("entries material=%v id=%v", sawMaterial, sawID)
	}
}
