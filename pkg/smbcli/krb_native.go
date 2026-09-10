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
	plan, err := kerberosPlan(opts)
	if err != nil {
		return nil, err
	}
	if opts.Domain == "" {
		opts.Domain = auth.realm
	}
	ct, err := krb.ServiceTicketFromCCache(auth.ccache, plan.SPN, opts.Domain, plan.KDC)
	if err != nil {
		return nil, fmt.Errorf("cifs ticket %s: %w", plan.SPN, err)
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
	ks, err := smb2KerberosSession(conn, hostWithoutPort(opts.Host), token, ct.SessionKey)
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

// kerberosDialPlan splits TCP target, CIFS SPN, and KDC.
type kerberosDialPlan struct {
	SPN string
	KDC string
}

func kerberosPlan(opts Options) (kerberosDialPlan, error) {
	if strings.TrimSpace(opts.Host) == "" {
		return kerberosDialPlan{}, fmt.Errorf("host required")
	}
	host := hostWithoutPort(opts.Host)
	name := strings.TrimSpace(opts.Hostname)
	if name == "" {
		name = host
	}
	spn := strings.TrimSpace(opts.SPN)
	if spn == "" {
		spn = "cifs/" + name
	}
	kdc := strings.TrimSpace(opts.KDC)
	if kdc == "" {
		kdc = host
	}
	return kerberosDialPlan{SPN: spn, KDC: kdc}, nil
}

func ticketNativeEnabled() bool {
	v := strings.TrimSpace(os.Getenv("ARK_SMB_IMPACKET"))
	return v == "" || v == "0" || strings.EqualFold(v, "false")
}

func sessionKeyBytes(k types.EncryptionKey) []byte {
	return k.KeyValue
}
