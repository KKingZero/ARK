package preimplant

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/ldapcli"
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
	default:
		return fmt.Errorf("unknown ldap command %q\n%s", args[0], ldapUsage)
	}
}

const ldapUsage = `erebus ldap — operator-host LDAP (no implant)

  erebus ldap bind --dc H --domain D --user U (--pass-file P | --pass P | --hash H) [--tls-verify]
  erebus ldap enum --dc H --domain D --user U --pass-file P --type interesting
  erebus ldap dangling --dc H --domain D --user U --pass-file P

Uses LDAPS first (lab self-signed OK). Types: interesting, users, groups, admins,
kerberoastable, asrep_roastable, computers, dcs, rbcd, dangling.

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
	if q == "dangling" {
		return ldapDangling(args)
	}
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	base := ldapcli.BaseDN(opts.Domain)
	if base == "" {
		return fmt.Errorf("--domain required")
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
