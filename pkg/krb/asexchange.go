package krb

import (
	"encoding/hex"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// asExchange is an AES AS-REQ/AS-REP over SendKDC (SOCKS-aware).
func asExchange(kdc, domain, username, password string) (messages.ASRep, error) {
	var none messages.ASRep
	cfg, err := NewConfig(domain, kdc)
	if err != nil {
		return none, err
	}
	cfg.LibDefaults.Forwardable = true
	cfg.LibDefaults.NoAddresses = true
	user := samOnly(username)
	realm := Realm(domain)
	bootstrapOffset(kdc)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)
	req, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return none, err
	}
	rep, err := sendASReq(kdc, req)
	if err != nil {
		ke, ok := asKRBError(err, nil)
		if !ok {
			return none, err
		}
		if ke.ErrorCode == errorcode.KRB_AP_ERR_SKEW {
			ApplySKEW(ke)
			return none, wrapKRB(ke)
		}
		if ke.ErrorCode != errorcode.KDC_ERR_PREAUTH_REQUIRED && ke.ErrorCode != errorcode.KDC_ERR_PREAUTH_FAILED {
			return none, wrapKRB(ke)
		}
		preauth := ke
		rep, err = asWithPA(kdc, &req, password, preauth)
		if err != nil {
			return none, err
		}
	}
	creds := credentials.New(user, realm).WithPassword(password)
	if _, err := rep.DecryptEncPart(creds); err != nil {
		return none, fmt.Errorf("decrypt AS-REP: %w", err)
	}
	if rep.DecryptedEncPart.Nonce != req.ReqBody.Nonce {
		return none, fmt.Errorf("AS nonce mismatch")
	}
	if err := requireAES(rep.DecryptedEncPart.Key.KeyType, "TGT"); err != nil {
		return none, err
	}
	return rep, nil
}

func asWithPA(kdc string, req *messages.ASReq, password string, preauth messages.KRBError) (messages.ASRep, error) {
	var none messages.ASRep
	if err := addPAEncTimestamp(req, password, preauth); err != nil {
		return none, err
	}
	rep, err := sendASReq(kdc, *req)
	if err == nil {
		return rep, nil
	}
	ke, ok := asKRBError(err, nil)
	if !ok || ke.ErrorCode != errorcode.KRB_AP_ERR_SKEW {
		return none, wrapKRB(err)
	}
	ApplySKEW(ke)
	if err := addPAEncTimestamp(req, password, preauth); err != nil {
		return none, err
	}
	rep, err = sendASReq(kdc, *req)
	if err != nil {
		return none, wrapKRB(err)
	}
	return rep, nil
}

func sendASReq(kdc string, req messages.ASReq) (messages.ASRep, error) {
	var rep messages.ASRep
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
	return rep, nil
}

func addPAEncTimestamp(req *messages.ASReq, password string, ke messages.KRBError) error {
	var pas types.PADataSequence
	if len(ke.EData) > 0 {
		if err := pas.Unmarshal(ke.EData); err != nil {
			return fmt.Errorf("PREAUTH e-data: %w", err)
		}
	}
	etID, salt, params, err := pickAESPreauth(pas)
	if err != nil {
		return err
	}
	et, err := crypto.GetEtype(etID)
	if err != nil {
		return err
	}
	if params == "" {
		params = et.GetDefaultStringToKeyParams()
	}
	kb, err := et.StringToKey(password, salt, params)
	if err != nil {
		return fmt.Errorf("string-to-key: %w", err)
	}
	key := types.EncryptionKey{KeyType: etID, KeyValue: kb}
	ts, err := marshalPAEncTS(Now())
	if err != nil {
		return err
	}
	enc, err := crypto.GetEncryptedData(ts, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, 0)
	if err != nil {
		return fmt.Errorf("PA-ENC-TIMESTAMP: %w", err)
	}
	pb, err := enc.Marshal()
	if err != nil {
		return err
	}
	filtered := req.PAData[:0]
	for _, pa := range req.PAData {
		if pa.PADataType != patype.PA_ENC_TIMESTAMP {
			filtered = append(filtered, pa)
		}
	}
	req.PAData = append(filtered, types.PAData{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: pb})
	return nil
}

func pickAESPreauth(pas types.PADataSequence) (et int32, salt, params string, err error) {
	var infos types.ETypeInfo2
	for _, pa := range pas {
		if pa.PADataType != patype.PA_ETYPE_INFO2 {
			continue
		}
		info, e := pa.GetETypeInfo2()
		if e != nil {
			return 0, "", "", e
		}
		infos = append(infos, info...)
	}
	var offered []int32
	for _, e := range infos {
		offered = append(offered, e.EType)
		if e.EType != etypeID.AES256_CTS_HMAC_SHA1_96 && e.EType != etypeID.AES128_CTS_HMAC_SHA1_96 {
			continue
		}
		if et == etypeID.AES256_CTS_HMAC_SHA1_96 {
			continue
		}
		if et == 0 || e.EType == etypeID.AES256_CTS_HMAC_SHA1_96 {
			et = e.EType
			salt = e.Salt
			if len(e.S2KParams) == 4 {
				params = hex.EncodeToString(e.S2KParams)
			} else {
				params = ""
			}
		}
	}
	if et != 0 {
		return et, salt, params, nil
	}
	if len(offered) == 0 {
		return 0, "", "", fmt.Errorf("PREAUTH required but no ETYPE-INFO2")
	}
	return 0, "", "", fmt.Errorf("KDC offered etypes %v; AES required", offered)
}

func asKRBError(err error, body []byte) (messages.KRBError, bool) {
	if ke, ok := err.(messages.KRBError); ok {
		return ke, true
	}
	if len(body) == 0 {
		return messages.KRBError{}, false
	}
	var ke messages.KRBError
	if ke.Unmarshal(body) == nil {
		return ke, true
	}
	return messages.KRBError{}, false
}
