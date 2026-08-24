package krb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

const tokIDKRBAPReq = "0100"

// CachedTicket is one ccache credential plus the unmarshaled ticket.
type CachedTicket struct {
	Ticket     messages.Ticket
	SessionKey types.EncryptionKey
	CName      types.PrincipalName
	CRealm     string
	Server     []string
	SRealm     string
}

// GSSAuthenticator is a GSSAPI authenticator whose CTime is krb.Now() (not wall clock).
func GSSAuthenticator(realm string, cname types.PrincipalName) (types.Authenticator, error) {
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		return auth, err
	}
	t := Now()
	auth.CTime = t
	auth.Cusec = int((t.UnixNano() / int64(time.Microsecond)) - (t.Unix() * 1e6))
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  gssAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}),
	}
	return auth, nil
}

// MarshalKRB5APReqToken wraps an AP-REQ as a GSSAPI KRB5 MechToken (RFC 4121).
func MarshalKRB5APReqToken(apReq messages.APReq) ([]byte, error) {
	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, err
	}
	tokID, err := hex.DecodeString(tokIDKRBAPReq)
	if err != nil {
		return nil, err
	}
	tb, err := apReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("AP-REQ: %w", err)
	}
	b := append(oid, tokID...)
	b = append(b, tb...)
	return asn1tools.AddASNAppTag(b, 0), nil
}

// APReqFromCached builds an AP-REQ for a cached service ticket using krb.Now().
func APReqFromCached(ct CachedTicket) (messages.APReq, error) {
	auth, err := GSSAuthenticator(ct.CRealm, ct.CName)
	if err != nil {
		return messages.APReq{}, err
	}
	apReq, err := messages.NewAPReq(ct.Ticket, ct.SessionKey, auth)
	if err != nil {
		return messages.APReq{}, err
	}
	types.SetFlag(&apReq.APOptions, flags.APOptionMutualRequired)
	return apReq, nil
}

// LoadCCacheTickets reads every credential that has a parseable ticket blob.
func LoadCCacheTickets(path string) ([]CachedTicket, error) {
	cc, err := credentials.LoadCCache(path)
	if err != nil {
		return nil, fmt.Errorf("ccache: %w", err)
	}
	var out []CachedTicket
	for _, e := range cc.GetEntries() {
		if e == nil || len(e.Ticket) == 0 {
			continue
		}
		var tkt messages.Ticket
		if err := tkt.Unmarshal(e.Ticket); err != nil {
			continue
		}
		out = append(out, CachedTicket{
			Ticket:     tkt,
			SessionKey: e.Key,
			CName:      e.Client.PrincipalName,
			CRealm:     e.Client.Realm,
			Server:     e.Server.PrincipalName.NameString,
			SRealm:     e.Server.Realm,
		})
	}
	return out, nil
}

// FindCachedTicket matches SPN (SERVICE/host) case-insensitively.
func FindCachedTicket(tickets []CachedTicket, spn string) (CachedTicket, bool) {
	want := strings.ToLower(strings.TrimSpace(spn))
	if i := strings.Index(want, "@"); i >= 0 {
		want = want[:i]
	}
	for _, t := range tickets {
		got := strings.ToLower(strings.Join(t.Server, "/"))
		if got == want {
			return t, true
		}
	}
	return CachedTicket{}, false
}

// TGTFromCCache returns the krbtgt credential if present.
func TGTFromCCache(tickets []CachedTicket) (CachedTicket, bool) {
	for _, t := range tickets {
		if len(t.Server) > 0 && strings.EqualFold(t.Server[0], "krbtgt") {
			return t, true
		}
	}
	return CachedTicket{}, false
}

// ServiceTicketFromCCache returns a matching ST, or TGS-REQ from a TGT using krb.Now().
func ServiceTicketFromCCache(path, spn, domain, kdc string) (CachedTicket, error) {
	tickets, err := LoadCCacheTickets(path)
	if err != nil {
		return CachedTicket{}, err
	}
	if ct, ok := FindCachedTicket(tickets, spn); ok {
		return ct, nil
	}
	tgt, ok := TGTFromCCache(tickets)
	if !ok {
		return CachedTicket{}, fmt.Errorf("ccache has no ticket for %s and no TGT", spn)
	}
	if kdc == "" {
		return CachedTicket{}, fmt.Errorf("kdc required to TGS-REQ %s from TGT", spn)
	}
	if domain == "" {
		domain = tgt.CRealm
	}
	cfg, err := NewConfig(domain, kdc)
	if err != nil {
		return CachedTicket{}, err
	}
	cfg.LibDefaults.Forwardable = true
	cfg.LibDefaults.NoAddresses = true
	pn, err := parseSPN(spn)
	if err != nil {
		// ldap/host without slash already rejected; allow krbtgt-style
		pn = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn)
	}
	req, err := messages.NewTGSReq(tgt.CName, Realm(domain), cfg, tgt.Ticket, tgt.SessionKey, pn, false)
	if err != nil {
		return CachedTicket{}, fmt.Errorf("TGS-REQ %s: %w", spn, err)
	}
	if err := restampTGSPAData(&req, tgt.Ticket, tgt.SessionKey); err != nil {
		return CachedTicket{}, err
	}
	rep, err := tgsExchange(kdc, req, tgt.Ticket, tgt.SessionKey)
	if err != nil {
		return CachedTicket{}, fmt.Errorf("TGS-REQ %s: %w", spn, err)
	}
	return CachedTicket{
		Ticket:     rep.Ticket,
		SessionKey: rep.DecryptedEncPart.Key,
		CName:      rep.CName,
		CRealm:     rep.CRealm,
		Server:     rep.DecryptedEncPart.SName.NameString,
		SRealm:     rep.DecryptedEncPart.SRealm,
	}, nil
}

func gssAuthenticatorChksum(flagList []int) []byte {
	a := make([]byte, 24)
	binary.LittleEndian.PutUint32(a[:4], 16)
	for _, i := range flagList {
		f := binary.LittleEndian.Uint32(a[20:24])
		f |= uint32(i)
		binary.LittleEndian.PutUint32(a[20:24], f)
	}
	return a
}

// DecryptAPRepEncPart decrypts an AP-REP enc-part with the AP-REQ session key.
func DecryptAPRepEncPart(enc types.EncryptedData, sessionKey types.EncryptionKey) (messages.EncAPRepPart, error) {
	var part messages.EncAPRepPart
	b, err := crypto.DecryptEncPart(enc, sessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return part, err
	}
	if err := part.Unmarshal(b); err != nil {
		return part, err
	}
	return part, nil
}
