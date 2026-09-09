package krb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jcmturner/gokrb5/v8/messages"
)

// AskTGTOptions is a password AS-REQ for an AES TGT, or NT-hash overpass (RC4).
type AskTGTOptions struct {
	Domain   string
	Username string
	Password string
	Hash     string // 32-hex NT or LM:NT — overpass etype 23
	KDC      string
	Dir      string
}

// AskTGT requests a TGT and stores it as a ccache loot object.
// Password path is AES-only. --hash is NT-hash overpass (RC4-HMAC).
func AskTGT(opts AskTGTOptions) (TicketMeta, error) {
	if opts.Domain == "" || opts.Username == "" || opts.KDC == "" {
		return TicketMeta{}, fmt.Errorf("--domain --user --dc required")
	}
	if opts.Password != "" && opts.Hash != "" {
		return TicketMeta{}, fmt.Errorf("asktgt: --pass-file and --hash are mutually exclusive")
	}
	if opts.Password == "" && opts.Hash == "" {
		return TicketMeta{}, fmt.Errorf("--pass-file or --hash required")
	}
	var asRep messages.ASRep
	var err error
	if opts.Hash != "" {
		asRep, err = asExchangeHash(opts.KDC, opts.Domain, opts.Username, opts.Hash)
	} else {
		asRep, err = asExchange(opts.KDC, opts.Domain, opts.Username, opts.Password)
	}
	if err != nil {
		return TicketMeta{}, fmt.Errorf("AS-REQ: %w", err)
	}
	et := asRep.DecryptedEncPart.Key.KeyType
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
		Principal: strings.Join(asRep.CName.NameString, "/"),
		Realm:     asRep.CRealm,
		Server:    strings.Join(asRep.Ticket.SName.NameString, "/") + "@" + asRep.Ticket.Realm,
		EType:     et,
		End:       enc.EndTime,
		Source:    "asktgt",
		CCache:    ccPath,
	}
	if err := writeMeta(dir, meta); err != nil {
		return TicketMeta{}, err
	}
	return meta, nil
}
