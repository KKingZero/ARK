package krb

import (
	"crypto/rsa"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// PKINITOptions is AS-REQ with a shadow-cred PFX (SOCKS via SendKDC).
type PKINITOptions struct {
	Domain   string
	Username string
	KDC      string
	PFXPath  string
	PFXPass  string
	Dir      string
}

// PKINIT requests a TGT using the PFX and returns the NT hash hex when the PAC is UnPAC-able.
func PKINIT(opts PKINITOptions) (string, error) {
	if opts.Domain == "" || opts.Username == "" || opts.KDC == "" || opts.PFXPath == "" {
		return "", fmt.Errorf("--domain --user --dc --pfx required")
	}
	raw, err := os.ReadFile(opts.PFXPath)
	if err != nil {
		return "", err
	}
	key, cert, err := pkcs12.Decode(raw, opts.PFXPass)
	if err != nil {
		return "", fmt.Errorf("pfx: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("pfx: want RSA private key")
	}
	if cert == nil {
		return "", fmt.Errorf("pfx: missing certificate")
	}
	_ = rsaKey
	// Native PA-PK-AS-REQ (CMS AuthPack) is the remaining wire work.
	// LDAP KeyCredential write + PFX are already in-framework; do not wrap certipy.
	bits := 0
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		bits = pub.N.BitLen()
	}
	return "", fmt.Errorf("pkinit: PA-PK-AS-REQ not assembled (pfx ok cn=%s rsa=%d)", cert.Subject.CommonName, bits)
}
