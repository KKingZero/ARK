package krb

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

var (
	oidSignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA1           = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA1WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidContentType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidPKInitAuthData = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}
	oidPKInitDHKey    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}
	oidDHPublicNumber = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}
)

var asn1Null = []byte{0x05, 0x00}

// signAuthPack is CMS SignedData (id-pkinit-authData) over AuthPack, SHA-1 + RSA.
func signAuthPack(authPack []byte, key *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	if cert == nil || len(cert.Raw) == 0 {
		return nil, fmt.Errorf("pkinit: certificate DER required")
	}
	digest := sha1.Sum(authPack)

	ctVal, err := asn1.Marshal(oidPKInitAuthData)
	if err != nil {
		return nil, err
	}
	mdVal, err := asn1.Marshal(digest[:])
	if err != nil {
		return nil, err
	}
	attrCT, err := cmsAttribute(oidContentType, ctVal)
	if err != nil {
		return nil, err
	}
	attrMD, err := cmsAttribute(oidMessageDigest, mdVal)
	if err != nil {
		return nil, err
	}
	// DER SET OF: content-type (9.3) then message-digest (9.4).
	signedSet := derTLV(0x31, append(attrCT, attrMD...))
	sum := sha1.Sum(signedSet)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
	if err != nil {
		return nil, fmt.Errorf("pkinit: RSA sign: %w", err)
	}

	sid, err := marshalIssuerSerial(cert)
	if err != nil {
		return nil, err
	}
	digestAlg, err := marshalAlgID(oidSHA1)
	if err != nil {
		return nil, err
	}
	sigAlg, err := marshalAlgID(oidSHA1WithRSA)
	if err != nil {
		return nil, err
	}
	sigOctet, err := asn1.Marshal(sig)
	if err != nil {
		return nil, err
	}
	version1, err := asn1.Marshal(1)
	if err != nil {
		return nil, err
	}
	implicitAttrs := append([]byte{0xA0}, signedSet[1:]...)
	signerInfo := derTLV(0x30, concat(version1, sid, digestAlg, implicitAttrs, sigAlg, sigOctet))

	encap, err := marshalEncap(oidPKInitAuthData, authPack)
	if err != nil {
		return nil, err
	}
	version3, err := asn1.Marshal(3)
	if err != nil {
		return nil, err
	}
	digestAlgs := derTLV(0x31, digestAlg)
	certs := derTLV(0xA0, cert.Raw) // [0] IMPLICIT SET OF Certificate
	signers := derTLV(0x31, signerInfo)
	signedData := derTLV(0x30, concat(version3, digestAlgs, encap, certs, signers))

	oidDER, err := asn1.Marshal(oidSignedData)
	if err != nil {
		return nil, err
	}
	explicit := derTLV(0xA0, signedData)
	return derTLV(0x30, append(oidDER, explicit...)), nil
}

func cmsEContent(contentInfo []byte) (asn1.ObjectIdentifier, []byte, error) {
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(contentInfo, &ci); err != nil {
		return nil, nil, fmt.Errorf("pkinit: CMS ContentInfo: %w", err)
	}
	if !ci.Type.Equal(oidSignedData) {
		return nil, nil, fmt.Errorf("pkinit: CMS contentType %v (want signedData)", ci.Type)
	}
	fields, err := derSeqFields(ci.Content.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("pkinit: SignedData: %w", err)
	}
	if len(fields) < 3 {
		return nil, nil, fmt.Errorf("pkinit: SignedData short (%d fields)", len(fields))
	}
	var encap struct {
		Type    asn1.ObjectIdentifier
		Content []byte `asn1:"explicit,optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(fields[2].FullBytes, &encap); err != nil {
		return nil, nil, fmt.Errorf("pkinit: EncapsulatedContentInfo: %w", err)
	}
	if len(encap.Content) == 0 {
		return nil, nil, fmt.Errorf("pkinit: CMS eContent empty")
	}
	return encap.Type, encap.Content, nil
}

func cmsAttribute(oid asn1.ObjectIdentifier, valueDER []byte) ([]byte, error) {
	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	return derTLV(0x30, append(oidDER, derTLV(0x31, valueDER)...)), nil
}

func marshalAlgID(oid asn1.ObjectIdentifier) ([]byte, error) {
	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	return derTLV(0x30, append(oidDER, asn1Null...)), nil
}

func marshalIssuerSerial(cert *x509.Certificate) ([]byte, error) {
	type issSerial struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	return asn1.Marshal(issSerial{
		Issuer: asn1.RawValue{FullBytes: cert.RawIssuer},
		Serial: cert.SerialNumber,
	})
}

func marshalEncap(oid asn1.ObjectIdentifier, content []byte) ([]byte, error) {
	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	octet, err := asn1.Marshal(content)
	if err != nil {
		return nil, err
	}
	return derTLV(0x30, append(oidDER, derTLV(0xA0, octet)...)), nil
}

func derSeqFields(seq []byte) ([]asn1.RawValue, error) {
	var wrap asn1.RawValue
	if _, err := asn1.Unmarshal(seq, &wrap); err != nil {
		return nil, err
	}
	if wrap.Tag != 16 {
		return nil, fmt.Errorf("tag %d (want SEQUENCE)", wrap.Tag)
	}
	var out []asn1.RawValue
	rest := wrap.Bytes
	for len(rest) > 0 {
		var el asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &el)
		if err != nil {
			return nil, err
		}
		out = append(out, el)
	}
	return out, nil
}

func derTLV(tag byte, val []byte) []byte {
	n := len(val)
	var lenb []byte
	switch {
	case n < 0x80:
		lenb = []byte{byte(n)}
	case n < 0x100:
		lenb = []byte{0x81, byte(n)}
	case n < 0x10000:
		lenb = []byte{0x82, byte(n >> 8), byte(n)}
	default:
		lenb = []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	out := make([]byte, 0, 1+len(lenb)+n)
	out = append(out, tag)
	out = append(out, lenb...)
	return append(out, val...)
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
