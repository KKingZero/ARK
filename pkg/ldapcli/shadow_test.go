package ldapcli

import "testing"

func TestWriteShadowNil(t *testing.T) {
	if _, err := WriteShadow(nil, "DC=a,DC=b", "u", []byte{1}); err == nil {
		t.Fatal("nil conn")
	}
	if _, err := WriteShadow(nil, "DC=a,DC=b", "u", nil); err == nil {
		t.Fatal("empty blob")
	}
}

func TestClearShadowNil(t *testing.T) {
	if _, err := ClearShadow(nil, "DC=a,DC=b", "u"); err == nil {
		t.Fatal("nil")
	}
}

func TestShadowAttrName(t *testing.T) {
	if AttrKeyCredential != "msDS-KeyCredentialLink" {
		t.Fatal(AttrKeyCredential)
	}
}

func TestDNBinaryEncode(t *testing.T) {
	got := EncodeDNBinary([]byte{0x00, 0x02, 0x00, 0x00}, "CN=u,DC=a,DC=htb")
	want := "B:8:00020000:CN=u,DC=a,DC=htb"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
