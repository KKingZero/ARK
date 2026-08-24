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
