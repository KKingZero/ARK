package krb

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// RewriteTicketSName is getST -altservice: change the unencrypted ticket sname
// (and optional realm) in the TGS ticket blob. Enc-part is left untouched.
func RewriteTicketSName(tktBytes []byte, alt string) (out []byte, sname types.PrincipalName, realm string, err error) {
	pn, realm, err := parseSPNWithRealm(alt)
	if err != nil {
		return nil, pn, realm, err
	}
	var tkt messages.Ticket
	if err := tkt.Unmarshal(tktBytes); err != nil {
		return nil, pn, realm, fmt.Errorf("altservice: parse ticket: %w", err)
	}
	enc := append([]byte(nil), tkt.EncPart.Cipher...)
	tkt.SName = pn
	if realm != "" {
		tkt.Realm = realm
	} else {
		realm = tkt.Realm
	}
	raw, err := tkt.Marshal()
	if err != nil {
		return nil, pn, realm, fmt.Errorf("altservice: marshal ticket: %w", err)
	}
	var check messages.Ticket
	if err := check.Unmarshal(raw); err != nil {
		return nil, pn, realm, fmt.Errorf("altservice: reparse ticket: %w", err)
	}
	if !bytes.Equal(check.EncPart.Cipher, enc) {
		return nil, pn, realm, fmt.Errorf("altservice: ticket enc-part changed")
	}
	return raw, pn, realm, nil
}

func parseSPNWithRealm(spn string) (types.PrincipalName, string, error) {
	spn = strings.TrimSpace(spn)
	realm := ""
	if i := strings.Index(spn, "@"); i >= 0 {
		realm = strings.ToUpper(strings.TrimSpace(spn[i+1:]))
		spn = strings.TrimSpace(spn[:i])
	}
	if !strings.Contains(spn, "/") {
		return types.PrincipalName{}, realm, fmt.Errorf("altservice %q: want SERVICE/host", spn)
	}
	return types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn), realm, nil
}
