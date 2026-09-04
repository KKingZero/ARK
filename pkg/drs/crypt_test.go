package drs

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDecryptAttributeValueRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	nt, _ := hex.DecodeString("8cacb3a97e460c65d105ca7cd9913925")
	enc, err := EncryptAttributeValue(key, nt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptAttributeValue(key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, nt) {
		t.Fatalf("%x", got)
	}
}

func TestDecryptAttributeValueFailClosed(t *testing.T) {
	if _, err := DecryptAttributeValue(nil, bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("empty key")
	}
	key := bytes.Repeat([]byte{0x11}, 16)
	enc, _ := EncryptAttributeValue(key, []byte("abc"))
	enc[20] ^= 0xff
	if _, err := DecryptAttributeValue(key, enc); err == nil {
		t.Fatal("want crc mismatch")
	}
}
