package preimplant

import (
	"fmt"

	"github.com/KKingZero/ARK/pkg/ldapcli"
)

const dnsUsage = `ark dns — operator-host ADIDNS (LDAP, no implant)

  ark dns add    --dc H --domain D --user U --pass-file P --name testdns --type A --data 10.10.15.135 --yes
  ark dns add    --dc H --domain D --user U --pass-file P --forest --name testdns --type A --data 10.10.15.135 --yes
  ark dns delete --dc H --domain D --user U --pass-file P --name testdns --yes

Writes dnsNode/dnsRecord under DomainDnsZones (or ForestDnsZones with --forest).
--yes required. Lab-only.
`

// RunDNS is host-side ADIDNS add/delete.
func RunDNS(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", dnsUsage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(dnsUsage)
		return nil
	case "add":
		return dnsAdd(args[1:])
	case "delete", "del", "rm":
		return dnsDelete(args[1:])
	default:
		return fmt.Errorf("unknown dns command %q\n%s", args[0], dnsUsage)
	}
}

func dnsAdd(args []string) error {
	f, _ := ParseFlags(args)
	name := first(f, "name")
	typ := first(f, "type")
	data := first(f, "data", "ip")
	if name == "" || data == "" {
		return fmt.Errorf("%s", dnsUsage)
	}
	if typ == "" {
		typ = "A"
	}
	if typ != "A" && typ != "a" {
		return fmt.Errorf("v1 supports --type A only")
	}
	if !flagBool(f, "yes") {
		return fmt.Errorf("refusing dns add %q without --yes", name)
	}
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	opts.RequireTLS = true
	printProxyHint()
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	dn, err := ldapcli.AddDNSRecordA(conn, opts.Domain, name, data, flagBool(f, "forest"))
	if err != nil {
		return err
	}
	fmt.Printf("OK dns add A %s -> %s (%s)\n", name, data, dn)
	return nil
}

func dnsDelete(args []string) error {
	f, _ := ParseFlags(args)
	name := first(f, "name")
	if name == "" {
		return fmt.Errorf("%s", dnsUsage)
	}
	if !flagBool(f, "yes") {
		return fmt.Errorf("refusing dns delete %q without --yes", name)
	}
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	opts.RequireTLS = true
	printProxyHint()
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	dn, err := ldapcli.DeleteDNSNode(conn, opts.Domain, name, flagBool(f, "forest"))
	if err != nil {
		return err
	}
	fmt.Printf("OK dns delete %s (%s)\n", name, dn)
	return nil
}
