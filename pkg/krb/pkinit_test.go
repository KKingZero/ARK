package krb

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
)

func TestPKINITMissingFields(t *testing.T) {
	_, err := PKINIT(PKINITOptions{})
	if err == nil || !strings.Contains(err.Error(), "--domain") {
		t.Fatalf("got %v", err)
	}
}

func TestTruncateKey(t *testing.T) {
	in := []byte("full-key-material")
	got := truncateKey(in, 32)
	if len(got) != 32 {
		t.Fatalf("len %d", len(got))
	}
	h := sha1.Sum(append([]byte{0}, in...))
	if !bytes.Equal(got[:20], h[:]) {
		t.Fatalf("first block: %x want %x", got[:20], h[:])
	}
	if !bytes.Equal(got, truncateKey(in, 32)) {
		t.Fatal("not deterministic")
	}
	got16 := truncateKey(in, 16)
	if len(got16) != 16 || !bytes.Equal(got16, got[:16]) {
		t.Fatalf("aes128 slice")
	}
}

func TestDHExchange(t *testing.T) {
	a, err := newDH()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newDH()
	if err != nil {
		t.Fatal(err)
	}
	ab := a.exchange(b.y)
	ba := b.exchange(a.y)
	if !bytes.Equal(ab, ba) || len(ab) == 0 {
		t.Fatalf("shared mismatch %x vs %x", ab, ba)
	}
}

func TestParseDHPublicIntegerBitString(t *testing.T) {
	y := big.NewInt(0)
	y.SetString("aabbccddeeff", 16)
	intDER, err := stdasn1.Marshal(y)
	if err != nil {
		t.Fatal(err)
	}
	got := parseDHPublic(asn1.BitString{Bytes: intDER, BitLength: len(intDER) * 8})
	if got.Cmp(y) != 0 {
		t.Fatalf("got %x want %x", got, y)
	}
	raw := y.Bytes()
	got = parseDHPublic(asn1.BitString{Bytes: raw, BitLength: len(raw) * 8})
	if got.Cmp(y) != 0 {
		t.Fatalf("raw: got %x want %x", got, y)
	}
}

func TestNTFromNTLMBlob(t *testing.T) {
	nt, _ := hex.DecodeString("11223344556677889900aabbccddeeff")
	blob := make([]byte, 40)
	copy(blob[24:40], nt)
	got, ok := ntFromNTLMBlob(blob)
	if !ok || got != hex.EncodeToString(nt) {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	if _, ok := ntFromNTLMBlob(make([]byte, 40)); ok {
		t.Fatal("zero NT should fail")
	}
}

func TestSignAuthPackRoundTrip(t *testing.T) {
	key, cert := testCert(t)
	body := []byte("authpack-der-body")
	cms, err := signAuthPack(body, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	oid, content, err := cmsEContent(cms)
	if err != nil {
		t.Fatal(err)
	}
	if !oid.Equal(oidPKInitAuthData) {
		t.Fatalf("oid %v", oid)
	}
	if !bytes.Equal(content, body) {
		t.Fatalf("eContent %x want %x", content, body)
	}
}

func TestBuildPKINITASReqHasPADATA(t *testing.T) {
	key, cert := testCert(t)
	cfg, err := NewConfig("danglingtree.htb", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cfg.LibDefaults.Forwardable = true
	cfg.LibDefaults.NoAddresses = true
	req, dh, err := buildPKINITASReq("DANGLINGTREE.HTB", "administrator", cfg, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	if dh.y == nil || len(dh.nonce) != 32 {
		t.Fatalf("dh %+v", dh)
	}
	raw, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 200 {
		t.Fatalf("short AS-REQ %d", len(raw))
	}
	var sawPAC, sawPK bool
	for _, pa := range req.PAData {
		if pa.PADataType == 128 {
			sawPAC = true
		}
		if pa.PADataType == 16 {
			sawPK = true
			if len(pa.PADataValue) < 50 {
				t.Fatalf("short PA-PK-AS-REQ")
			}
		}
	}
	if !sawPAC || !sawPK {
		t.Fatalf("padata pac=%v pk=%v", sawPAC, sawPK)
	}
}

func TestKRBErrorNamePKINIT(t *testing.T) {
	if krbErrorName(kdcErrInconsistentKeyPurpose) != "KDC_ERR_INCONSISTENT_KEY_PURPOSE" {
		t.Fatal(krbErrorName(kdcErrInconsistentKeyPurpose))
	}
}

func testCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "administrator"},
		Issuer:       pkix.Name{CommonName: "administrator"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}
