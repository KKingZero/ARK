package adcs

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/KKingZero/ARK/pkg/ldapcli"
)

func TestNewESC1CSRContainsUPNAndSID(t *testing.T) {
	sid := "S-1-5-21-111-222-333-500"
	csr, err := NewESC1CSR(CSROptions{
		UPN:      "administrator@danglingtree.htb",
		SID:      sid,
		Template: "VPNUserTemplate",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(csr.DER) < 100 || csr.Key == nil {
		t.Fatal("short csr")
	}
	parsed, err := x509.ParseCertificateRequest(csr.DER)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(csr.DER)
	if !strings.Contains(raw, "administrator@danglingtree.htb") && !bytesContain(csr.DER, []byte("administrator@danglingtree.htb")) {
		t.Fatal("missing UPN")
	}
	sidb, _ := ldapcli.EncodeSID(sid)
	if !bytesContain(csr.DER, sidb) {
		t.Fatal("missing SID bytes")
	}
	if parsed.Subject.CommonName != "administrator" {
		t.Fatalf("cn %s", parsed.Subject.CommonName)
	}
}

func TestNewESC1CSRFailClosed(t *testing.T) {
	if _, err := NewESC1CSR(CSROptions{UPN: "no-at", SID: "S-1-5-21-1-2-3-500"}); err == nil {
		t.Fatal("upn")
	}
	if _, err := NewESC1CSR(CSROptions{UPN: "a@b.htb", SID: "not-a-sid"}); err == nil {
		t.Fatal("sid")
	}
}

func bytesContain(b, sub []byte) bool {
	return strings.Contains(string(b), string(sub))
}
