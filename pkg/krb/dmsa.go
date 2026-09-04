package krb

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	forkasn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// PA_DMSA_KEY_PACKAGE is padata-type 171 (MS-KILE KERB-DMSA-KEY-PACKAGE).
const PA_DMSA_KEY_PACKAGE int32 = 171

// keyUsagePAS4UX509User is MS-SFU checksum usage 26 (EncTGSRepPart application tag).
const keyUsagePAS4UX509User = 26

// DMSAUserID bits (getST --dmsa): UNCONDITIONAL_DELEGATION=2, SIGN_REPLY=4.
const (
	dmsaOptUnconditionalDelegation = 2
	dmsaOptSignReply               = 4
)

// DMSAKey is one key from KERB-DMSA-KEY-PACKAGE.
type DMSAKey struct {
	KeyType  int
	KeyValue []byte
}

// DMSAKeyPackage is current + previous managed keys (including predecessor NT).
type DMSAKeyPackage struct {
	Current  []DMSAKey
	Previous []DMSAKey
}

type dmsaKeyASN struct {
	KeyType  int    `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

type dmsaPkgASN struct {
	Current        []dmsaKeyASN `asn1:"explicit,tag:0"`
	Previous       []dmsaKeyASN `asn1:"explicit,optional,tag:1"`
	EffectiveTime  time.Time    `asn1:"generalized,explicit,optional,tag:2"`
	Reserved       []byte       `asn1:"explicit,optional,tag:3"`
	ExpirationTime time.Time    `asn1:"generalized,explicit,optional,tag:4"`
}

type s4uUserID struct {
	Nonce   int                 `asn1:"explicit,tag:0"`
	CName   types.PrincipalName `asn1:"explicit,tag:1"`
	CRealm  string              `asn1:"generalstring,explicit,tag:2"`
	Options forkasn1.BitString  `asn1:"explicit,optional,tag:4"`
}

type paS4UX509User struct {
	UserID s4uUserID      `asn1:"explicit,tag:0"`
	Cksum  types.Checksum `asn1:"explicit,tag:1"`
}

// ParseDMSAKeyPackage decodes KERB-DMSA-KEY-PACKAGE from a TGS enc-part payload.
func ParseDMSAKeyPackage(b []byte) (DMSAKeyPackage, error) {
	var out DMSAKeyPackage
	if len(b) == 0 {
		return out, fmt.Errorf("empty dMSA key package")
	}
	var p dmsaPkgASN
	_, err := asn1.Unmarshal(b, &p)
	if err != nil {
		return out, fmt.Errorf("KERB-DMSA-KEY-PACKAGE: %w", err)
	}
	for _, k := range p.Current {
		out.Current = append(out.Current, DMSAKey{KeyType: k.KeyType, KeyValue: k.KeyValue})
	}
	for _, k := range p.Previous {
		out.Previous = append(out.Previous, DMSAKey{KeyType: k.KeyType, KeyValue: k.KeyValue})
	}
	if len(out.Current)+len(out.Previous) == 0 {
		return out, fmt.Errorf("KERB-DMSA-KEY-PACKAGE: no keys")
	}
	return out, nil
}

func (k DMSAKey) Hex() string {
	return fmt.Sprintf("%x", k.KeyValue)
}

func (k DMSAKey) TypeName() string {
	switch k.KeyType {
	case 23:
		return "RC4"
	case 17:
		return "AES128"
	case 18:
		return "AES256"
	default:
		return fmt.Sprintf("etype-%d", k.KeyType)
	}
}

// Dump prints current-keys then previous-keys (predecessor NT is RC4 in previous).
func (p DMSAKeyPackage) Dump() string {
	var b strings.Builder
	b.WriteString("dMSA current-keys:\n")
	if len(p.Current) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, k := range p.Current {
		fmt.Fprintf(&b, "  %s:%s\n", k.TypeName(), k.Hex())
	}
	b.WriteString("dMSA previous-keys:\n")
	if len(p.Previous) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, k := range p.Previous {
		fmt.Fprintf(&b, "  %s:%s\n", k.TypeName(), k.Hex())
	}
	return b.String()
}

func marshalPAS4UX509User(user types.PrincipalName, realm string, skey types.EncryptionKey) (types.PAData, error) {
	var nb [4]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return types.PAData{}, err
	}
	nonce := int(binary.BigEndian.Uint32(nb[:]) & 0x7fffffff)
	return marshalPAS4UX509UserNonce(user, realm, skey, nonce)
}

func marshalPAS4UX509UserNonce(user types.PrincipalName, realm string, skey types.EncryptionKey, nonce int) (types.PAData, error) {
	opt := types.NewKrbFlags()
	types.SetFlag(&opt, dmsaOptUnconditionalDelegation)
	types.SetFlag(&opt, dmsaOptSignReply)
	id := s4uUserID{
		Nonce:   nonce,
		CName:   user,
		CRealm:  realm,
		Options: opt,
	}
	encodedID, err := forkasn1.Marshal(id)
	if err != nil {
		return types.PAData{}, fmt.Errorf("S4UUserID: %w", err)
	}
	ckType := chksumtype.HMAC_SHA1_96_AES256
	if skey.KeyType == etypeID.AES128_CTS_HMAC_SHA1_96 {
		ckType = chksumtype.HMAC_SHA1_96_AES128
	}
	et, err := crypto.GetChksumEtype(ckType)
	if err != nil {
		return types.PAData{}, err
	}
	sum, err := et.GetChecksumHash(skey.KeyValue, encodedID, keyUsagePAS4UX509User)
	if err != nil {
		return types.PAData{}, fmt.Errorf("PA-S4U-X509-USER checksum: %w", err)
	}
	enc := paS4UX509User{
		UserID: id,
		Cksum: types.Checksum{
			CksumType: ckType,
			Checksum:  sum,
		},
	}
	b, err := forkasn1.Marshal(enc)
	if err != nil {
		return types.PAData{}, fmt.Errorf("PA-S4U-X509-USER: %w", err)
	}
	return types.PAData{PADataType: patype.PA_FOR_X509_USER, PADataValue: b}, nil
}

func dmsaKeysFromTGS(rep messages.TGSRep) (DMSAKeyPackage, error) {
	for _, pa := range rep.DecryptedEncPart.EncPAData {
		if pa.PADataType != PA_DMSA_KEY_PACKAGE {
			continue
		}
		pkg, err := ParseDMSAKeyPackage(pa.PADataValue)
		if err != nil {
			return pkg, err
		}
		if len(pkg.Previous) == 0 {
			return pkg, fmt.Errorf("s4u --dmsa: KERB-DMSA-KEY-PACKAGE has no previous-keys")
		}
		return pkg, nil
	}
	return DMSAKeyPackage{}, fmt.Errorf("s4u --dmsa: no KERB-DMSA-KEY-PACKAGE (padata %d) in TGS enc-part", PA_DMSA_KEY_PACKAGE)
}
