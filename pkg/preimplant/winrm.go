package preimplant

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const winrmUsage = `ark winrm — operator-host WinRM/PSRP (no implant)

  ark winrm --host H --user U --domain D --pass-file P --ps "whoami"
  ark winrm --host H --user U --domain D --hash-file nt.txt --ps "hostname"
  ark winrm --host H --user U --hash H --cmd "whoami"
  ark winrm --host H --user U --pass-file P --copy local remote
  ark winrm --host H --user U --pass-file P --fetch remote local

Default is PowerShell remoting (--ps). --cmd is WinRS (often Access Denied on hardened DCs).
PTH: --hash 32hex-NT or LM:NT. Honors ARK_PROXY / ALL_PROXY (SOCKS5 via PySocks).
Requires python3 + pypsrp. Needs the ARK checkout: scripts/host_winrm.py is not
installed with ~/.local/bin/ark. Set ARK_ROOT=/path/to/ARK if you are not
running from the repo. Lab-only.
`

// RunWinRM is host-side PSRP/WinRS (wraps scripts/host_winrm.py).
func RunWinRM(args []string) error {
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Print(winrmUsage)
		return nil
	}
	f, bare := ParseFlags(args)
	host := first(f, "host", "target")
	user := first(f, "user", "username")
	if host == "" || user == "" {
		return fmt.Errorf("%s", winrmUsage)
	}
	script, err := findRepoScript("scripts/host_winrm.py")
	if err != nil {
		return err
	}
	argv := []string{script, "--host", host, "--user", user}
	if d := first(f, "domain"); d != "" {
		argv = append(argv, "--domain", d)
	}
	if p := first(f, "pass-file"); p != "" {
		argv = append(argv, "--pass-file", p)
	}
	if p := first(f, "pass", "password"); p != "" {
		argv = append(argv, "--password", p)
	}
	if p := first(f, "hash-file"); p != "" {
		argv = append(argv, "--hash-file", p)
	}
	if p := first(f, "hash"); p != "" {
		argv = append(argv, "--hash", p)
	}
	if flagBool(f, "ssl") {
		argv = append(argv, "--ssl")
	}
	if flagBool(f, "cmd") {
		argv = append(argv, "--cmd")
	} else {
		argv = append(argv, "--ps")
	}
	if local := first(f, "copy"); local != "" {
		remote := first(f, "remote")
		if remote == "" && len(bare) > 0 {
			remote = bare[0]
		}
		if remote == "" {
			return fmt.Errorf("--copy LOCAL requires --remote PATH")
		}
		argv = append(argv, "--copy", local, remote)
	} else if remote := first(f, "fetch"); remote != "" {
		local := first(f, "out")
		if local == "" && len(bare) > 0 {
			local = bare[0]
		}
		if local == "" {
			return fmt.Errorf("--fetch REMOTE requires --out PATH")
		}
		argv = append(argv, "--fetch", remote, local)
	} else {
		cmd := strings.Join(bare, " ")
		if cmd == "" {
			return fmt.Errorf("command required")
		}
		argv = append(argv, cmd)
	}
	printProxyHint()
	return runPython(argv)
}

func runPython(scriptAndArgs []string) error {
	return runPythonWithEnv(scriptAndArgs, nil)
}

func runPythonWithEnv(scriptAndArgs []string, extraEnv []string) error {
	py := "python3"
	if p := os.Getenv("ARK_PYTHON"); p != "" {
		py = p
	}
	cmd := exec.Command(py, scriptAndArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), extraEnv...)
	return cmd.Run()
}

func findRepoScript(rel string) (string, error) {
	if v := os.Getenv("ARK_ROOT"); v != "" {
		p := filepath.Join(v, rel)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	wd, _ := os.Getwd()
	dir := wd
	for i := 0; i < 8; i++ {
		p := filepath.Join(dir, rel)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), rel)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found — ark winrm/mssql wrap scripts/ from a checkout; export ARK_ROOT=/path/to/ARK (~/.local/bin/ark does not ship the scripts)", rel)
}
