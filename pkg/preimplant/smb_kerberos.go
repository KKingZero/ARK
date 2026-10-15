package preimplant

import (
	"fmt"
	"os"
	"strings"

	"github.com/KKingZero/ARK/pkg/krb"
	"github.com/KKingZero/ARK/pkg/smbcli"
)

// kerberosSMBDecision is the pure plan for ark smb/psexec --kerberos.
// Ask is set only when a new TGT must be requested. Tests never call the KDC.
type kerberosSMBDecision struct {
	Ask         *krb.AskTGTOptions
	ClearSecret bool
}

func planKerberosSMB(o smbcli.Options, kerberos bool) (kerberosSMBDecision, error) {
	if !kerberos {
		return kerberosSMBDecision{}, nil
	}
	if strings.TrimSpace(o.Ticket) != "" {
		return kerberosSMBDecision{ClearSecret: true}, nil
	}
	if strings.TrimSpace(o.Username) == "" {
		return kerberosSMBDecision{}, fmt.Errorf("smb --kerberos requires --user or --ticket")
	}
	if o.Password == "" && o.Hash == "" {
		return kerberosSMBDecision{}, fmt.Errorf("smb --kerberos requires --pass-file, --pass, or --hash")
	}
	if o.Password != "" && o.Hash != "" {
		return kerberosSMBDecision{}, fmt.Errorf("smb --kerberos: --pass and --hash are mutually exclusive")
	}
	if strings.TrimSpace(o.Domain) == "" {
		return kerberosSMBDecision{}, fmt.Errorf("smb --kerberos requires --domain")
	}
	kdc := strings.TrimSpace(o.KDC)
	if kdc == "" {
		kdc = stripSMBPort(o.Host)
	}
	if kdc == "" {
		return kerberosSMBDecision{}, fmt.Errorf("smb --kerberos requires --host or --kdc")
	}
	return kerberosSMBDecision{
		Ask: &krb.AskTGTOptions{
			Domain:   o.Domain,
			Username: o.Username,
			Password: o.Password,
			Hash:     o.Hash,
			KDC:      kdc,
		},
		ClearSecret: true,
	}, nil
}

// applyKerberosSMB requests a TGT when the plan says so, then clears the
// password and hash so Dial takes the native Kerberos path.
func applyKerberosSMB(o smbcli.Options, kerberos bool) (smbcli.Options, error) {
	d, err := planKerberosSMB(o, kerberos)
	if err != nil {
		return o, err
	}
	if d.Ask != nil {
		meta, err := krb.AskTGT(*d.Ask)
		if err != nil {
			return o, err
		}
		o.Ticket = meta.ID
		fmt.Fprintf(os.Stdout, "ticket %s\n", meta.ID)
	}
	if d.ClearSecret {
		o.Password = ""
		o.Hash = ""
	}
	return o, nil
}

func stripSMBPort(host string) string {
	host = strings.TrimSpace(host)
	if host == "" || strings.Contains(host, "]") {
		return host
	}
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}
