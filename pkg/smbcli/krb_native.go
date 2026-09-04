package smbcli

import (
	"fmt"
	"os"
	"strings"

	"github.com/KKingZero/ARK/pkg/krb"
	"github.com/KKingZero/ARK/pkg/netproxy"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// DialKerberos authenticates with a ccache/kirbi ticket (no Impacket).
func DialKerberos(opts Options) (*Session, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("host required")
	}
	auth, err := resolveTicket(opts)
	if err != nil {
		return nil, err
	}
	host := hostWithoutPort(opts.Host)
	kdc := host
	if opts.Domain == "" {
		opts.Domain = auth.realm
	}
	spn := "cifs/" + host
	ct, err := krb.ServiceTicketFromCCache(auth.ccache, spn, opts.Domain, kdc)
	if err != nil {
		return nil, fmt.Errorf("cifs ticket %s: %w", spn, err)
	}
	token, err := spnegoAPReq(ct)
	if err != nil {
		return nil, err
	}
	addr := joinSMBAddr(opts.Host)
	conn, err := netproxy.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("smb connect %s: %w", addr, err)
	}
	ks, err := smb2KerberosSession(conn, host, token, ct.SessionKey)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Session{kerb: ks, host: opts.Host}, nil
}

func spnegoAPReq(ct krb.CachedTicket) ([]byte, error) {
	apReq, err := krb.APReqFromCached(ct)
	if err != nil {
		return nil, err
	}
	mech, err := krb.MarshalKRB5APReqToken(apReq)
	if err != nil {
		return nil, err
	}
	neg := spnego.NegTokenInit{
		MechTypes:      []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
		MechTokenBytes: mech,
	}
	tok := spnego.SPNEGOToken{Init: true, NegTokenInit: neg}
	return tok.Marshal()
}

func ticketNativeEnabled() bool {
	v := strings.TrimSpace(os.Getenv("ARK_SMB_IMPACKET"))
	return v == "" || v == "0" || strings.EqualFold(v, "false")
}

func sessionKeyBytes(k types.EncryptionKey) []byte {
	return k.KeyValue
}
