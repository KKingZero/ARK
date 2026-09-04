package preimplant

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/KKingZero/ARK/pkg/ldapcli"
)

// TODO(native): replace Impacket wrap with host SAMR over SMB.

var (
	lookAddComputer = lookAddComputerBin
	runAddComputer  = runAddComputerCmd
)

func lookAddComputerBin() (string, error) {
	names := []string{"addcomputer.py", "impacket-addcomputer"}
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	home, _ := os.UserHomeDir()
	for _, n := range names {
		p := filepath.Join(home, ".local", "bin", n)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("addcomputer.py not found in PATH (temporary Impacket SAMR wrap)")
}

func runAddComputerCmd(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty argv")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", argv[0], err, truncate(string(out), 400))
	}
	return nil
}

func addComputerSAMRArgv(bin string, opts ldapcli.Options, name, pass string) []string {
	dom, user := ldapcli.SplitUser(opts.Username, opts.Domain)
	if opts.Domain != "" && strings.Contains(opts.Domain, ".") {
		dom = opts.Domain
	}
	ident := dom + "/" + user + ":" + opts.Password
	sam := name
	if !strings.HasSuffix(strings.ToUpper(sam), "$") {
		sam += "$"
	}
	return []string{
		bin,
		ident,
		"-method", "SAMR",
		"-computer-name", sam,
		"-computer-pass", pass,
		"-dc-ip", opts.Host,
	}
}

// samrAddComputer creates a workstation via Impacket addcomputer.py -method SAMR.
func samrAddComputer(opts ldapcli.Options, name, pass string) error {
	if opts.Username == "" || opts.Password == "" {
		return fmt.Errorf("SAMR add-computer needs --user and password (not hash/ticket)")
	}
	if strings.Contains(opts.Password, ":") {
		return fmt.Errorf("bind password contains colon; native SAMR not shipped")
	}
	bin, err := lookAddComputer()
	if err != nil {
		return err
	}
	argv := addComputerSAMRArgv(bin, opts, name, pass)
	return runAddComputer(argv)
}
