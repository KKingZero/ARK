package krb

import "testing"

func TestRODCKvno(t *testing.T) {
	if got := RODCKvno(8245); got != 8245<<16 {
		t.Fatalf("%d", got)
	}
}

func TestValidateKeyList(t *testing.T) {
	_, err := ValidateKeyList(KeyListOptions{})
	if err == nil {
		t.Fatal("empty")
	}
	_, err = ValidateKeyList(KeyListOptions{
		RODCNumber: 8245, User: "Administrator", Domain: "x.htb", KDC: "10.0.0.1",
		AESKeyHex: "deadbeef",
	})
	if err == nil {
		t.Fatal("short key")
	}
	kv, err := ValidateKeyList(KeyListOptions{
		RODCNumber: 8245, User: "Administrator", Domain: "x.htb", KDC: "10.0.0.1",
		AESKeyHex: "d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240",
	})
	if err != nil || kv != 8245<<16 {
		t.Fatalf("%d %v", kv, err)
	}
}
