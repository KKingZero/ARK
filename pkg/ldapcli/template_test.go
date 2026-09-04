package ldapcli

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestTemplateDN(t *testing.T) {
	dn, err := TemplateDN("CN=Configuration,DC=danglingtree,DC=htb", "VPNUserTemplate")
	if err != nil {
		t.Fatal(err)
	}
	want := "CN=VPNUserTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=danglingtree,DC=htb"
	if dn != want {
		t.Fatalf("%s", dn)
	}
	if _, err := TemplateDN("CN=Configuration,DC=x,DC=htb", "bad,name"); err == nil {
		t.Fatal("specials")
	}
}

func TestEncodeWindowsGUIDRoundTrip(t *testing.T) {
	g, err := EncodeWindowsGUID(GUIDCertificateEnrollment)
	if err != nil {
		t.Fatal(err)
	}
	if len(g) != 16 {
		t.Fatalf("%d", len(g))
	}
	if got := formatWindowsGUID(g); !strings.EqualFold(got, GUIDCertificateEnrollment) {
		t.Fatalf("%s", got)
	}
}

func TestBuildTemplateEnrollSD(t *testing.T) {
	owner, err := EncodeSID("S-1-5-21-1-2-3-1105")
	if err != nil {
		t.Fatal(err)
	}
	sd, err := BuildTemplateEnrollSD(owner, "S-1-5-21-1-2-3-1105")
	if err != nil {
		t.Fatal(err)
	}
	own, findings, err := ParseSecurityDescriptor(sd)
	if err != nil {
		t.Fatal(err)
	}
	if own != "S-1-5-21-1-2-3-1105" {
		t.Fatalf("owner %s", own)
	}
	var enroll, auto, gall bool
	for _, f := range findings {
		for _, r := range f.Rights {
			if r == "GenericAll" {
				gall = true
			}
		}
		if strings.EqualFold(f.ObjectGUID, GUIDCertificateEnrollment) {
			enroll = true
		}
		if strings.EqualFold(f.ObjectGUID, GUIDCertificateAutoEnroll) {
			auto = true
		}
	}
	if !gall || !enroll || !auto {
		t.Fatalf("rights gall=%v enroll=%v auto=%v findings=%+v", gall, enroll, auto, findings)
	}
}

func TestDurationFiletimeNegative(t *testing.T) {
	b := durationFiletime(365 * 24 * time.Hour)
	if len(b) != 8 {
		t.Fatal(len(b))
	}
	v := int64(binary.LittleEndian.Uint64(b))
	if v >= 0 {
		t.Fatalf("want negative FILETIME interval, got %d", v)
	}
}

func TestESC1NameFlagConstant(t *testing.T) {
	if NameFlagEnrolleeSuppliesSubj != 1 {
		t.Fatal(NameFlagEnrolleeSuppliesSubj)
	}
	if schemaV1 != 1 {
		t.Fatal(schemaV1)
	}
}
