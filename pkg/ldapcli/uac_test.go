package ldapcli

import "testing"

func TestApplyAccountDisable(t *testing.T) {
	if got := ApplyAccountDisable(514, false); got != 512 {
		t.Fatalf("enable 514 → %d", got)
	}
	if got := ApplyAccountDisable(512, true); got != 514 {
		t.Fatalf("disable 512 → %d", got)
	}
	if got := ApplyAccountDisable(512, false); got != 512 {
		t.Fatalf("already enabled %d", got)
	}
	const dontExpire = 512 | 0x10000
	if got := ApplyAccountDisable(dontExpire|UACAccountDisable, false); got != dontExpire {
		t.Fatalf("preserve other bits: %d", got)
	}
}

func TestSetAccountDisabledNilConn(t *testing.T) {
	if _, _, err := SetAccountDisabled(nil, "DC=a,DC=b", "u", false); err == nil {
		t.Fatal("nil conn")
	}
}

func TestCanonicalSetAttrRejectsUAC(t *testing.T) {
	if _, err := CanonicalSetAttr("userAccountControl"); err == nil {
		t.Fatal("UAC must stay off the set allowlist")
	}
}
