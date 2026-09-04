package preimplant

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/KKingZero/ARK/pkg/ldapcli"
)

// samrSetPassword uses Samba `net rpc password` (what worked on DanglingTree
// when LDAPS unicodePwd was rejected). Bind secret goes in PASSWD_FILE, not argv.
func samrSetPassword(opts ldapcli.Options, target, newPass string) error {
	netBin, err := exec.LookPath("net")
	if err != nil {
		return fmt.Errorf("samba net not in PATH (install samba-common-tools)")
	}
	if opts.Username == "" || opts.Password == "" {
		return fmt.Errorf("SAMR fallback needs --user and password (not hash)")
	}
	dir, err := os.MkdirTemp("", "ark-samr-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	pwFile := filepath.Join(dir, "passwd")
	if err := os.WriteFile(pwFile, []byte(opts.Password), 0o600); err != nil {
		return err
	}
	_, user := ldapcli.SplitUser(opts.Username, opts.Domain)
	domain := opts.Domain
	if domain == "" {
		domain, _ = ldapcli.SplitUser(opts.Username, "")
	}
	cmd := exec.Command(netBin, "rpc", "password", target, newPass,
		"-U", domain+"/"+user,
		"-S", opts.Host,
		"-W", domain,
	)
	cmd.Env = append(os.Environ(), "PASSWD_FILE="+pwFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("net rpc password: %w (%s)", err, truncate(string(out), 400))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
