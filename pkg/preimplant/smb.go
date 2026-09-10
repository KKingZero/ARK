package preimplant

import (
	"fmt"

	"github.com/KKingZero/ARK/pkg/smbcli"
)

// RunSMB dispatches host-side SMB (no implant).
func RunSMB(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", smbUsage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(smbUsage)
		return nil
	case "shares", "list_shares":
		return smbShares(args[1:])
	case "ls", "list_dir", "dir":
		return smbLs(args[1:])
	case "get", "download":
		return smbGet(args[1:])
	default:
		return fmt.Errorf("unknown smb command %q\n%s", args[0], smbUsage)
	}
}

const smbUsage = `ark smb — operator-host SMB (no implant)

  ark smb shares --host H [--anon | --user U --pass-file P --domain D]
  ark smb ls --host H --share IT [--path .]
  ark smb get --host H --share C$ --path Users\\a\\Desktop\\user.txt --out user.txt
  ark smb ls --host 10.1.2.3 --hostname dc.lab.htb --share SYSVOL --ticket ID

Hash: --hash 32hex-NT. Ticket: --ticket ID|path (store via ark kerberos ticket import / s4u).
Kerberos: --hostname sets cifs/ SPN when --host is an IP; --kdc / --spn optional.
--anon is a Guest session (empty password). Signing-required DCs reject Guest.
Kerberos SMB is native (cifs/ TGS + SMB2). Impacket wrap: ARK_SMB_IMPACKET=1.
Honors ARK_PROXY / ALL_PROXY (SOCKS5).
Lab-only. See docs/OPERATOR_PRE_IMPLANT.md
`

func smbOpts(f map[string]string) (smbcli.Options, error) {
	o := smbcli.Options{
		Host:      first(f, "host", "dc"),
		Domain:    f["domain"],
		Username:  first(f, "user", "username"),
		Anonymous: flagBool(f, "anon", "anonymous", "guest"),
		Hostname:  first(f, "hostname", "name"),
		SPN:       first(f, "spn"),
		KDC:       first(f, "kdc", "dc-ip"),
	}
	pass, err := readSecret(f, "pass", "pass-file")
	if err != nil {
		return o, err
	}
	o.Password = pass
	o.Hash = first(f, "hash", "ntlm-hash")
	o.Ticket = first(f, "ticket", "ccache")
	if o.Host == "" {
		return o, fmt.Errorf("--host is required")
	}
	return o, nil
}

func smbShares(args []string) error {
	f, _ := ParseFlags(args)
	opts, err := smbOpts(f)
	if err != nil {
		return err
	}
	printProxyHint()
	if smbcli.UseTicket(opts) {
		names, err := smbcli.TicketListShares(opts)
		if err != nil {
			return err
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	}
	s, err := smbcli.Dial(opts)
	if err != nil {
		return err
	}
	defer s.Close()
	names, err := s.ListShares()
	if err != nil {
		return err
	}
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

func smbLs(args []string) error {
	f, _ := ParseFlags(args)
	opts, err := smbOpts(f)
	if err != nil {
		return err
	}
	share := f["share"]
	if share == "" {
		return fmt.Errorf("--share required")
	}
	printProxyHint()
	if smbcli.UseTicket(opts) {
		names, err := smbcli.TicketListDir(opts, share, f["path"])
		if err != nil {
			return err
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	}
	s, err := smbcli.Dial(opts)
	if err != nil {
		return err
	}
	defer s.Close()
	names, err := s.ListDir(share, f["path"])
	if err != nil {
		return err
	}
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

func smbGet(args []string) error {
	f, _ := ParseFlags(args)
	opts, err := smbOpts(f)
	if err != nil {
		return err
	}
	share := f["share"]
	p := first(f, "path", "file")
	if share == "" || p == "" {
		return fmt.Errorf("--share and --path required")
	}
	printProxyHint()
	return smbcli.DownloadTo(opts, share, p, first(f, "out", "output"))
}
