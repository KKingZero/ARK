package preimplant

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKingZero/ARK/pkg/krb"
	"github.com/KKingZero/ARK/pkg/ldapcli"
	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/KKingZero/ARK/pkg/suggestions"
	"github.com/go-ldap/ldap/v3"
)

// RunLDAP dispatches host-side LDAP (no teamserver / implant).
func RunLDAP(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", ldapUsage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(ldapUsage)
		return nil
	case "bind":
		return ldapBind(args[1:])
	case "enum":
		return ldapEnum(args[1:])
	case "dangling":
		return ldapDangling(args[1:])
	case "set":
		return ldapSet(args[1:])
	default:
		return fmt.Errorf("unknown ldap command %q\n%s", args[0], ldapUsage)
	}
}

const ldapUsage = `ark ldap — operator-host LDAP (no implant)

  ark ldap bind --dc H --domain D --user U (--pass-file P | --pass P | --hash H) [--tls-verify]
  ark ldap enum --dc H --domain D --user U --pass-file P --type interesting
  ark ldap dangling --dc H --domain D --user U --pass-file P
  ark ldap enum --type maq --dc H --domain D --user U --pass-file P
  ark ldap enum --type acl --dc H --domain D --user U --pass-file P [--all]
  ark ldap set --dc H --domain D --user U --pass-file P --target SAM scriptPath VALUE --yes
  ark ldap set --dc H --domain D --user U --pass-file P --target DC01$ servicePrincipalName HTTP/web.domain.htb --yes
  ark ldap bind --dc H --domain D --ticket ID   # GSSAPI from imported ccache

Uses LDAPS first (lab self-signed OK). Honors ARK_PROXY / ALL_PROXY (SOCKS5).
Types: acl, asrep_roastable (alias asrep), computers, constrained_delegation, dangling,
dcs, domain_admins, gpos, groups, interesting, kerberoastable (alias spn), maq,
rbcd, secrets, shadow (alias keycred), trusts, unconstrained_delegation, users, admins.
acl is host-only (parses nTSecurityDescriptor). Default hides DA/EA/BA/SYSTEM trustees; --all includes them.

Lab-only. See docs/OPERATOR_PRE_IMPLANT.md
`

func ldapOpts(f map[string]string) (ldapcli.Options, error) {
	o := ldapcli.DefaultOptions()
	o.Host = first(f, "dc", "host")
	o.Domain = f["domain"]
	o.Username = first(f, "user", "username")
	pass, err := readSecret(f, "pass", "pass-file")
	if err != nil {
		return o, err
	}
	o.Password = pass
	o.Hash = first(f, "hash", "ntlm-hash")
	if tid := first(f, "ticket", "ccache"); tid != "" {
		_, p, err := krb.LoadTicket(tid, "")
		if err != nil {
			return o, err
		}
		o.CCache = p
	}
	if flagBool(f, "tls-verify", "verify-tls") {
		o.InsecureSkipVerify = false
	}
	if o.Host == "" {
		return o, fmt.Errorf("--dc is required")
	}
	return o, nil
}

func ldapBind(args []string) error {
	f, _ := ParseFlags(args)
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	printProxyHint()
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	who := opts.Username
	if who == "" {
		who = "(unbound/anonymous)"
	}
	fmt.Printf("OK ldap %s as %s (ldaps preferred)\n", opts.Host, who)
	return nil
}

func ldapEnum(args []string) error {
	f, bare := ParseFlags(args)
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	q := first(f, "type", "query")
	if q == "" && len(bare) > 0 {
		q = bare[0]
	}
	if q == "" {
		q = "interesting"
	}
	q = ldapcli.CanonicalQuery(q)
	if q == "dangling" {
		return ldapDangling(args)
	}
	printProxyHint()
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	base := ldapcli.BaseDN(opts.Domain)
	if base == "" {
		return fmt.Errorf("--domain required")
	}
	if q == "maq" {
		return printMAQ(conn, base)
	}
	if q == "acl" {
		return printACL(conn, base, flagBool(f, "all"))
	}
	filter, err := ldapcli.FilterFor(q, base)
	if err != nil {
		return err
	}
	attrs := ldapcli.DefaultAttrs[q]
	entries, err := ldapcli.Search(conn, base, filter, attrs)
	if err != nil {
		return err
	}
	fmt.Printf("query=%s count=%d\n", q, len(entries))
	for _, e := range entries {
		fmt.Println(e.DN)
		names := make([]string, 0, len(e.Attributes))
		for _, a := range e.Attributes {
			names = append(names, a.Name)
		}
		sort.Strings(names)
		for _, name := range names {
			if redactAttr(name) {
				fmt.Printf("  %s: [redacted]\n", name)
				continue
			}
			vals := e.GetAttributeValues(name)
			if len(vals) == 0 {
				continue
			}
			fmt.Printf("  %s: %s\n", name, strings.Join(vals, "; "))
		}
	}
	return nil
}

func ldapDangling(args []string) error {
	f, _ := ParseFlags(args)
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	printProxyHint()
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	res, err := ldapcli.DanglingTemplates(conn)
	if err != nil {
		return err
	}
	fmt.Printf("configNC=%s ca=%s\n", res.ConfigNC, strings.Join(res.CA, ","))
	fmt.Printf("published=%d existing=%d dangling=%d\n", len(res.Published), len(res.Existing), len(res.Missing))
	if len(res.Missing) == 0 {
		fmt.Println("no dangling published templates")
		return nil
	}
	fmt.Println("dangling (CA lists these names; no AD object):")
	for _, n := range res.Missing {
		fmt.Println(" ", n)
	}
	return nil
}

func printACL(conn *ldap.Conn, base string, includePrivileged bool) error {
	objs, err := ldapcli.SearchACL(conn, base, includePrivileged)
	if err != nil {
		return err
	}
	fmt.Printf("query=acl count=%d privileged=%v\n", len(objs), includePrivileged)
	if len(objs) == 0 {
		fmt.Println("no interesting DACL rights (or SD not readable)")
		fmt.Println("next: ark ldap enum --type interesting")
		fmt.Println("next: ark ldap enum --type rbcd")
		return nil
	}
	for _, o := range objs {
		sam := o.SAM
		if sam == "" {
			sam = o.DN
		}
		fmt.Printf("%s (%s)\n", sam, o.Category)
		if o.OwnerSID != "" {
			fmt.Printf("  owner: %s\n", o.OwnerSID)
		}
		fmt.Printf("  dn: %s\n", o.DN)
		for _, f := range o.Findings {
			who := f.TrusteeSID
			if f.Trustee != "" {
				who = f.Trustee + " " + f.TrusteeSID
			}
			fmt.Printf("  %s <- %s\n", strings.Join(f.Rights, ","), who)
		}
	}
	res := aclToEnumResult(objs)
	for _, s := range suggestions.ForACL(res) {
		fmt.Println("next:", s)
	}
	return nil
}

func aclToEnumResult(objs []ldapcli.ObjectACL) *pb.LDAPEnumResult {
	r := &pb.LDAPEnumResult{
		QueryType:    "acl",
		TotalResults: int32(len(objs)),
	}
	for _, o := range objs {
		attrs := map[string]*pb.LDAPValues{
			"sAMAccountName":    {Values: []string{o.SAM}},
			"objectCategory":    {Values: []string{o.Category}},
			"distinguishedName": {Values: []string{o.DN}},
		}
		var rights, trustees []string
		for _, f := range o.Findings {
			rights = append(rights, f.Rights...)
			if f.TrusteeSID != "" {
				trustees = append(trustees, f.TrusteeSID)
			}
		}
		attrs["rights"] = &pb.LDAPValues{Values: rights}
		attrs["trustee"] = &pb.LDAPValues{Values: trustees}
		r.Entries = append(r.Entries, &pb.LDAPEntry{Dn: o.DN, Attributes: attrs})
	}
	return r
}

func ldapSet(args []string) error {
	f, bare := ParseFlags(args)
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	target := first(f, "target", "sam")
	attr := first(f, "attr", "attribute")
	value := first(f, "value")
	if attr == "" && len(bare) >= 2 {
		if target == "" {
			target = bare[0]
			bare = bare[1:]
		}
		attr = bare[0]
		if value == "" && len(bare) > 1 {
			value = strings.Join(bare[1:], " ")
		}
	}
	if target == "" || attr == "" {
		return fmt.Errorf("usage: ark ldap set --target SAM scriptPath VALUE --yes")
	}
	if !flagBool(f, "yes") {
		return fmt.Errorf("refusing to set %s on %q without --yes", attr, target)
	}
	opts.RequireTLS = true
	printProxyHint()
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	base := ldapcli.BaseDN(opts.Domain)
	if base == "" {
		return fmt.Errorf("--domain required")
	}
	if err := ldapcli.SetAttr(conn, base, target, attr, value); err != nil {
		return err
	}
	fmt.Printf("OK ldap set %s on %s\n", attr, target)
	return nil
}

func printMAQ(conn *ldap.Conn, base string) error {
	n, ok, err := ldapcli.ReadMAQ(conn, base)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Printf("maq unset at %s (AD default is 10)\n", base)
		return nil
	}
	fmt.Printf("maq=%d base=%s\n", n, base)
	if n == 0 {
		fmt.Println("MAQ is 0 — addcomputer will refuse")
	}
	return nil
}

func redactAttr(name string) bool {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "password"), strings.Contains(n, "unicodepwd"),
		strings.Contains(n, "ntpwdhistory"), strings.Contains(n, "lmpwdhistory"),
		strings.Contains(n, "secret"), n == "userpassword",
		strings.EqualFold(name, "nTSecurityDescriptor"):
		return true
	default:
		return false
	}
}

func first(f map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := f[k]; v != "" {
			return v
		}
	}
	return ""
}
