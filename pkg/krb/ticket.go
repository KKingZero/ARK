package krb

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// TicketMeta is the on-disk loot record (no key material in the JSON).
type TicketMeta struct {
	ID        string    `json:"id"`
	Principal string    `json:"principal"`
	Realm     string    `json:"realm"`
	Server    string    `json:"server"`
	EType     int32     `json:"etype"`
	End       time.Time `json:"end,omitempty"`
	Source    string    `json:"source"` // ccache | kirbi | asktgt
	CCache    string    `json:"ccache"`
}

// DefaultTicketDir is ~/.erebus/tickets (override with EREBUS_TICKET_DIR).
func DefaultTicketDir() string {
	if d := os.Getenv("EREBUS_TICKET_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "erebus-tickets")
	}
	return filepath.Join(home, ".erebus", "tickets")
}

// DetectTicketFormat returns "ccache", "kirbi", or "".
func DetectTicketFormat(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	if b[0] == 5 && b[1] >= 1 && b[1] <= 4 {
		return "ccache"
	}
	if b[0] == 0x76 {
		return "kirbi"
	}
	return ""
}

// ImportTicket copies kirbi/ccache into the store and returns loot meta.
func ImportTicket(srcPath, dir string) (TicketMeta, error) {
	b, err := os.ReadFile(srcPath)
	if err != nil {
		return TicketMeta{}, err
	}
	kind := DetectTicketFormat(b)
	if kind == "" {
		return TicketMeta{}, fmt.Errorf("not a ccache (0x05) or kirbi (0x76) file")
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
	meta := TicketMeta{ID: id, Source: kind, CCache: ccPath}

	switch kind {
	case "ccache":
		if err := os.WriteFile(ccPath, b, 0o600); err != nil {
			return TicketMeta{}, err
		}
		cc, err := credentials.LoadCCache(ccPath)
		if err != nil {
			return TicketMeta{}, fmt.Errorf("parse ccache: %w", err)
		}
		fillMetaFromCCache(&meta, cc)
	case "kirbi":
		ccBytes, info, err := KirbiToCCache(b)
		if err != nil {
			return TicketMeta{}, err
		}
		if err := os.WriteFile(ccPath, ccBytes, 0o600); err != nil {
			return TicketMeta{}, err
		}
		meta.Principal = info.Principal
		meta.Realm = info.Realm
		meta.Server = info.Server
		meta.EType = info.EType
		meta.End = info.End
	}
	if err := writeMeta(dir, meta); err != nil {
		return TicketMeta{}, err
	}
	return meta, nil
}

// ListTickets reads store metadata.
func ListTickets(dir string) ([]TicketMeta, error) {
	if dir == "" {
		dir = DefaultTicketDir()
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []TicketMeta
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m TicketMeta
		if json.Unmarshal(b, &m) == nil && m.ID != "" {
			out = append(out, m)
		}
	}
	return out, nil
}

// LoadTicket returns meta + ccache path for an id or a raw file path.
func LoadTicket(idOrPath, dir string) (TicketMeta, string, error) {
	if idOrPath == "" {
		return TicketMeta{}, "", fmt.Errorf("ticket id or path required")
	}
	if st, err := os.Stat(idOrPath); err == nil && !st.IsDir() {
		kind := ""
		if b, rerr := os.ReadFile(idOrPath); rerr == nil {
			kind = DetectTicketFormat(b)
		}
		if kind == "ccache" {
			return TicketMeta{ID: filepath.Base(idOrPath), CCache: idOrPath, Source: "ccache"}, idOrPath, nil
		}
		if kind == "kirbi" {
			m, err := ImportTicket(idOrPath, dir)
			return m, m.CCache, err
		}
	}
	if dir == "" {
		dir = DefaultTicketDir()
	}
	p := filepath.Join(dir, idOrPath+".json")
	b, err := os.ReadFile(p)
	if err != nil {
		return TicketMeta{}, "", fmt.Errorf("ticket %q: %w", idOrPath, err)
	}
	var m TicketMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return TicketMeta{}, "", err
	}
	if m.CCache == "" {
		return TicketMeta{}, "", fmt.Errorf("ticket %s has no ccache path", idOrPath)
	}
	return m, m.CCache, nil
}

func fillMetaFromCCache(m *TicketMeta, cc *credentials.CCache) {
	m.Realm = cc.GetClientRealm()
	m.Principal = cc.GetClientPrincipalName().PrincipalNameString()
	if ents := cc.GetEntries(); len(ents) > 0 {
		e := ents[0]
		m.Server = strings.Join(e.Server.PrincipalName.NameString, "/")
		if e.Server.Realm != "" && !strings.Contains(m.Server, "@") {
			m.Server += "@" + e.Server.Realm
		}
		m.EType = e.Key.KeyType
		m.End = e.EndTime
	}
}

func writeMeta(dir string, m TicketMeta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, m.ID+".json"), b, 0o600)
}

func newTicketID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// KirbiInfo is extracted from a decrypted KRB-CRED.
type KirbiInfo struct {
	Principal string
	Realm     string
	Server    string
	EType     int32
	End       time.Time
}

// KirbiToCCache converts a Rubeus-style kirbi (KRB-CRED, usually etype 0) to MIT ccache bytes.
func KirbiToCCache(b []byte) ([]byte, KirbiInfo, error) {
	var cred messages.KRBCred
	if err := cred.Unmarshal(b); err != nil {
		return nil, KirbiInfo{}, fmt.Errorf("kirbi: %w", err)
	}
	if cred.EncPart.EType != 0 {
		return nil, KirbiInfo{}, fmt.Errorf("kirbi EncPart etype %d (need 0 / already-decrypted Rubeus export)", cred.EncPart.EType)
	}
	if err := cred.DecryptedEncPart.Unmarshal(cred.EncPart.Cipher); err != nil {
		return nil, KirbiInfo{}, fmt.Errorf("kirbi enc-part: %w", err)
	}
	if len(cred.Tickets) == 0 || len(cred.DecryptedEncPart.TicketInfo) == 0 {
		return nil, KirbiInfo{}, fmt.Errorf("kirbi has no tickets")
	}
	info := cred.DecryptedEncPart.TicketInfo[0]
	tkt := cred.Tickets[0]
	tktBytes, err := tkt.Marshal()
	if err != nil {
		return nil, KirbiInfo{}, err
	}
	client := info.PName
	if len(client.NameString) == 0 {
		return nil, KirbiInfo{}, fmt.Errorf("kirbi missing client principal")
	}
	realm := info.PRealm
	if realm == "" {
		realm = tkt.Realm
	}
	server := info.SName
	if len(server.NameString) == 0 {
		server = tkt.SName
	}
	srealm := info.SRealm
	if srealm == "" {
		srealm = tkt.Realm
	}
	cc, err := WriteCCache(CCacheCred{
		ClientRealm: realm,
		Client:      client.NameString,
		ServerRealm: srealm,
		Server:      server.NameString,
		KeyType:     info.Key.KeyType,
		Key:         info.Key.KeyValue,
		AuthTime:    info.AuthTime,
		StartTime:   info.StartTime,
		EndTime:     info.EndTime,
		RenewTill:   info.RenewTill,
		Flags:       bitStringUint32(info.Flags.Bytes),
		Ticket:      tktBytes,
	})
	if err != nil {
		return nil, KirbiInfo{}, err
	}
	out := KirbiInfo{
		Principal: strings.Join(client.NameString, "/"),
		Realm:     realm,
		Server:    strings.Join(server.NameString, "/") + "@" + srealm,
		EType:     info.Key.KeyType,
		End:       info.EndTime,
	}
	return cc, out, nil
}
