package ldapcli

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/krb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/netproxy"
	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

var _ ldap.GSSAPIClient = (*clockedGSSAPI)(nil)

// clockedGSSAPI is ldap.GSSAPIClient whose AP-REQ authenticators use krb.Now().
// go-ldap's NewClientFromCCache uses gokrb5 NewAuthenticator (wall clock) and
// fails KRB_AP_ERR_SKEW on Pirate-class DCs.
type clockedGSSAPI struct {
	ccache string
	domain string
	kdc    string
	ekey   types.EncryptionKey
	subkey types.EncryptionKey
}

func bindGSSAPI(opts Options) (*ldap.Conn, error) {
	if _, err := os.Stat(opts.CCache); err != nil {
		return nil, fmt.Errorf("ccache: %w", err)
	}
	host, _ := splitHostPort(opts.Host, 389)
	port := 389
	if opts.Port != 0 && opts.Port != 636 {
		port = opts.Port
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	raw, err := netproxy.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("ldap %s: %w", addr, err)
	}
	conn := ldap.NewConn(raw, false)
	conn.Start()
	spn := "ldap/" + host
	gss := &clockedGSSAPI{ccache: opts.CCache, domain: opts.Domain, kdc: host}
	if err := conn.GSSAPIBind(gss, spn, ""); err != nil {
		conn.Close()
		// One skew retry: ApplySKEW if the error names KRB_AP_ERR_SKEW, then bind again.
		if !isKerberosSkew(err) {
			return nil, fmt.Errorf("LDAP GSSAPI bind %s: %w", spn, err)
		}
		raw2, derr := netproxy.DialTimeout("tcp", addr, dialTimeout)
		if derr != nil {
			return nil, fmt.Errorf("LDAP GSSAPI bind %s: %w", spn, err)
		}
		conn2 := ldap.NewConn(raw2, false)
		conn2.Start()
		gss2 := &clockedGSSAPI{ccache: opts.CCache, domain: opts.Domain, kdc: host}
		if err2 := conn2.GSSAPIBind(gss2, spn, ""); err2 != nil {
			conn2.Close()
			return nil, fmt.Errorf("LDAP GSSAPI bind %s: %w", spn, err2)
		}
		return conn2, nil
	}
	return conn, nil
}

func (c *clockedGSSAPI) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(target, token, nil)
}

func (c *clockedGSSAPI) InitSecContextWithOptions(target string, input []byte, _ []int) ([]byte, bool, error) {
	if len(input) == 0 {
		ct, err := krb.ServiceTicketFromCCache(c.ccache, target, c.domain, c.kdc)
		if err != nil {
			return nil, false, err
		}
		c.ekey = ct.SessionKey
		apReq, err := krb.APReqFromCached(ct)
		if err != nil {
			return nil, false, err
		}
		out, err := krb.MarshalKRB5APReqToken(apReq)
		if err != nil {
			return nil, false, err
		}
		return out, true, nil
	}
	var token spnego.KRB5Token
	if err := token.Unmarshal(input); err != nil {
		return nil, false, err
	}
	if token.IsKRBError() {
		krb.ApplySKEW(token.KRBError)
		return nil, true, token.KRBError
	}
	if token.IsAPRep() {
		part, err := krb.DecryptAPRepEncPart(token.APRep.EncPart, c.ekey)
		if err != nil {
			return nil, false, err
		}
		c.subkey = part.Subkey
		return []byte{}, false, nil
	}
	return []byte{}, true, nil
}

func (c *clockedGSSAPI) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	token := &gssapi.WrapToken{}
	if err := token.Unmarshal(input, true); err != nil {
		return nil, err
	}
	if token.Flags&0b1 == 0 {
		return nil, fmt.Errorf("got a Wrapped token that's not from the server")
	}
	key := c.ekey
	if token.Flags&0b100 != 0 {
		key = c.subkey
	}
	if _, err := token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, err
	}
	if len(token.Payload) != 4 {
		return nil, fmt.Errorf("server send bad final token for SASL GSSAPI Handshake")
	}
	payload := append([]byte{0, 0, 0, 0}, []byte(authzid)...)
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	outTok := &gssapi.WrapToken{
		Flags:     0b100,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 1,
		Payload:   payload,
	}
	if err := outTok.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}
	return outTok.Marshal()
}

func (c *clockedGSSAPI) DeleteSecContext() error {
	c.ekey = types.EncryptionKey{}
	c.subkey = types.EncryptionKey{}
	return nil
}

func (c *clockedGSSAPI) Close() error {
	return c.DeleteSecContext()
}

func isKerberosSkew(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "krb_ap_err_skew") || strings.Contains(s, "clock skew")
}
