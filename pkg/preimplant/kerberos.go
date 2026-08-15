package preimplant

import (
	"fmt"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/krb"
)

// RunKerberos is host-side (no teamserver): skew | with-skew.
func RunKerberos(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", krbUsage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(krbUsage)
		return nil
	case "skew":
		return kerberosSkew(args[1:])
	case "with-skew":
		return kerberosWithSkew(args[1:])
	default:
		return fmt.Errorf("unknown kerberos command %q\n%s", args[0], krbUsage)
	}
}

const krbUsage = `erebus kerberos — operator-host clock helper (no implant)

  erebus kerberos skew --dc H
  erebus kerberos with-skew --dc H -- certipy auth -pfx admin.pfx -dc-ip H

with-skew wraps the command in libfaketime (EREBUS_FAKETIME_SO or system .so).
Lab-only. See docs/OPERATOR_PRE_IMPLANT.md
`

func kerberosSkew(args []string) error {
	f, _ := ParseFlags(args)
	dc := first(f, "dc", "host")
	if dc == "" {
		return fmt.Errorf("--dc required")
	}
	res, err := krb.CheckSkewVsDC(dc, first(f, "user"), first(f, "pass"), krb.DefaultMaxSkew)
	if err != nil {
		return err
	}
	fmt.Println(res.Summary())
	if !res.OK() {
		return fmt.Errorf("clock skew too large (use erebus kerberos with-skew)")
	}
	return nil
}

func kerberosWithSkew(args []string) error {
	f, rest := ParseFlags(args)
	dc := first(f, "dc", "host")
	if dc == "" || len(rest) == 0 {
		return fmt.Errorf("usage: erebus kerberos with-skew --dc H -- <command...>")
	}
	res, err := krb.CheckSkewVsDC(dc, first(f, "user"), first(f, "pass"), 24*time.Hour)
	if err != nil {
		return err
	}
	fmt.Println(res.Summary())
	return krb.RunWithSkew(res.Delta, rest)
}
