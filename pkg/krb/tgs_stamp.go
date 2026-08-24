package krb

import (
	"fmt"
	"time"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// restampTGSPAData rebuilds PA-TGS-REQ with Now() in the authenticator.
// Other padata (PA-FOR-USER) is kept.
func restampTGSPAData(req *messages.TGSReq, tgt messages.Ticket, sessionKey types.EncryptionKey) error {
	b, err := req.ReqBody.Marshal()
	if err != nil {
		return fmt.Errorf("TGS body: %w", err)
	}
	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return err
	}
	cb, err := etype.GetChecksumHash(sessionKey.KeyValue, b, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	if err != nil {
		return fmt.Errorf("TGS authenticator checksum: %w", err)
	}
	auth, err := types.NewAuthenticator(tgt.Realm, req.ReqBody.CName)
	if err != nil {
		return err
	}
	t := Now()
	auth.CTime = t
	auth.Cusec = int((t.UnixNano() / int64(time.Microsecond)) - (t.Unix() * 1e6))
	auth.Cksum = types.Checksum{
		CksumType: etype.GetHashID(),
		Checksum:  cb,
	}
	apReq, err := messages.NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		return fmt.Errorf("TGS AP-REQ: %w", err)
	}
	apb, err := apReq.Marshal()
	if err != nil {
		return err
	}
	kept := make(types.PADataSequence, 0, len(req.PAData))
	for _, pa := range req.PAData {
		if pa.PADataType != patype.PA_TGS_REQ {
			kept = append(kept, pa)
		}
	}
	req.PAData = append(types.PADataSequence{{
		PADataType:  patype.PA_TGS_REQ,
		PADataValue: apb,
	}}, kept...)
	return nil
}
