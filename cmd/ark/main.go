package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/KKingZero/ARK/core"
	"github.com/KKingZero/ARK/pkg/arkcli"
	"github.com/KKingZero/ARK/pkg/operatorcli"
	"github.com/KKingZero/ARK/pkg/preimplant"
	"github.com/KKingZero/ARK/server"
)

func main() {
	// Default: interactive startup UI (banner + ark › prompt)
	if len(os.Args) < 2 {
		runConsole([]string{})
		return
	}

	switch os.Args[1] {
	case "serve":
		// `serve` starts teamserver + operator REPL. Stdin/REPL EOF does not stop C2.
		// Use `ark teamserver` (or serve --teamserver) for daemon-only (no REPL).
		if hasFlag(os.Args[2:], "--teamserver", "-d") {
			runTeamserver(stripFlags(os.Args[2:], "--teamserver", "-d"))
			return
		}
		if err := arkcli.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "ark: %v\n", err)
			os.Exit(1)
		}
	case "teamserver":
		runTeamserver(os.Args[2:])
	case "operator":
		runOperator(os.Args[2:])
	case "op":
		runOp(os.Args[2:])
	case "certs":
		runCerts(os.Args[2:])
	case "mqtt":
		if err := preimplant.RunMQTT(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ark mqtt: %v\n", err)
			os.Exit(1)
		}
	case "relay":
		if err := preimplant.RunRelay(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ark relay: %v\n", err)
			os.Exit(1)
		}
	case "ldap":
		if err := preimplant.RunLDAP(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ark ldap: %v\n", err)
			os.Exit(1)
		}
	case "smb":
		if err := preimplant.RunSMB(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ark smb: %v\n", err)
			os.Exit(1)
		}
	case "ad":
		if err := preimplant.RunAD(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ark ad: %v\n", err)
			os.Exit(1)
		}
	case "kerberos":
		if err := preimplant.RunKerberos(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ark kerberos: %v\n", err)
			os.Exit(1)
		}
	case "rbcd":
		if err := preimplant.RunRBCD(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ark rbcd: %v\n", err)
			os.Exit(1)
		}
	case "inbound":
		if err := preimplant.RunInbound(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ark inbound: %v\n", err)
			os.Exit(1)
		}
	case "adcs":
		if err := preimplant.RunADCS(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ark adcs: %v\n", err)
			os.Exit(1)
		}
	case "winrm":
		if err := preimplant.RunWinRM(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ark winrm: %v\n", err)
			os.Exit(1)
		}
	case "mssql":
		if err := preimplant.RunMSSQL(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "ark mssql: %v\n", err)
			os.Exit(1)
		}
	case "console":
		runConsole(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		// Support ark -json without subcommand
		if os.Args[1] == "-json" {
			runConsole(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func runConsole(args []string) {
	fs := flag.NewFlagSet("console", flag.ExitOnError)
	jsonMode := fs.Bool("json", false, "Enable JSON output mode for AI/programmatic control")
	_ = fs.Parse(args)
	core.NewConsole(*jsonMode).Start()
}

func runTeamserver(args []string) {
	configPath := server.ConfigPath()
	passphrase := os.Getenv("ARK_PASSPHRASE")
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case "-passphrase":
			if i+1 < len(args) {
				passphrase = args[i+1]
				i++
			}
		}
	}
	if err := arkcli.RunTeamserver(configPath, passphrase); err != nil {
		fmt.Fprintf(os.Stderr, "ark teamserver: %v\n", err)
		os.Exit(1)
	}
}

func runOperator(args []string) {
	serverAddr := "127.0.0.1:50051"
	defCert, defKey, defCA := arkcli.DefaultCertPaths()
	cert, key, ca := defCert, defKey, defCA
	apCert, apKey := "", ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-server":
			if i+1 < len(args) {
				serverAddr = args[i+1]
				i++
			}
		case "-cert":
			if i+1 < len(args) {
				cert = args[i+1]
				i++
			}
		case "-key":
			if i+1 < len(args) {
				key = args[i+1]
				i++
			}
		case "-ca":
			if i+1 < len(args) {
				ca = args[i+1]
				i++
			}
		case "-approver-cert":
			if i+1 < len(args) {
				apCert = args[i+1]
				i++
			}
		case "-approver-key":
			if i+1 < len(args) {
				apKey = args[i+1]
				i++
			}
		}
	}

	if cert == defCert && key == defKey && ca == defCA {
		if opCert, opKey, opCA, err := arkcli.EnsureOperatorCerts(arkcli.DataDir()); err == nil {
			cert, key, ca = opCert, opKey, opCA
		}
	}

	if err := operatorcli.RunREPL(operatorcli.Options{
		Server:           serverAddr,
		CertFile:         cert,
		KeyFile:          key,
		CAFile:           ca,
		ApproverCertFile: apCert,
		ApproverKeyFile:  apKey,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ark operator: %v\n", err)
		os.Exit(1)
	}
}

func runOp(args []string) {
	opts := arkcli.OpOptions{Server: "127.0.0.1:50051"}
	defCert, defKey, defCA := arkcli.DefaultCertPaths()
	opts.CertFile, opts.KeyFile, opts.CAFile = defCert, defKey, defCA
	apC, apK := arkcli.DefaultApproverCertPaths()
	opts.ApproverCertFile, opts.ApproverKeyFile = apC, apK

	// Global flags may appear before the op subcommand.
	i := 0
	for i < len(args) {
		switch args[i] {
		case "-server":
			if i+1 < len(args) {
				opts.Server = args[i+1]
				i += 2
				continue
			}
		case "-cert":
			if i+1 < len(args) {
				opts.CertFile = args[i+1]
				i += 2
				continue
			}
		case "-key":
			if i+1 < len(args) {
				opts.KeyFile = args[i+1]
				i += 2
				continue
			}
		case "-ca":
			if i+1 < len(args) {
				opts.CAFile = args[i+1]
				i += 2
				continue
			}
		case "-approver-cert":
			if i+1 < len(args) {
				opts.ApproverCertFile = args[i+1]
				i += 2
				continue
			}
		case "-approver-key":
			if i+1 < len(args) {
				opts.ApproverKeyFile = args[i+1]
				i += 2
				continue
			}
		}
		break
	}
	if err := arkcli.RunOp(opts, args[i:]); err != nil {
		fmt.Fprintf(os.Stderr, "ark op: %v\n", err)
		os.Exit(1)
	}
}

func runCerts(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: ark certs seats\n")
		os.Exit(1)
	}
	switch args[0] {
	case "seats":
		if err := arkcli.RunCertsSeats(arkcli.DataDir()); err != nil {
			fmt.Fprintf(os.Stderr, "ark certs seats: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown certs command: %s (try: seats)\n", args[0])
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `ARK C2 v%s

Usage:
  ark              Interactive console (startup UI)
  ark -json         JSON console mode
  ark serve         Start teamserver + operator REPL (stdin/EOF does not stop C2)
  ark serve --teamserver   Teamserver only (same as ark teamserver)
  ark teamserver    Run teamserver only (preferred daemon / HTB C2)
  ark operator      Connect to teamserver REPL
  ark op            One-shot operator commands (sessions/shell/generate/...)
  ark ldap          Host-side LDAP (LDAPS, enum, dangling templates)
  ark adcs          Dangling ESC1 template + WCCE req (no Certipy)
  ark smb           Host-side SMB list/get (no implant)
  ark ad            Host-side AD writes (password, dcsync, shadow)
  ark rbcd          Host-side RBCD write/clear/show
  ark kerberos      Skew, AES asktgt, golden/silver, keylist, pkinit
  ark inbound       tun0 / drop / httpdrop / through (SOCKS+env)
  ark winrm         Host-side WinRM/PSRP (pypsrp, SOCKS)
  ark mssql         Host-side MSSQL query / xp_cmdshell (impacket, SOCKS)
  ark mqtt          Pre-implant MQTT sub/pub/healthcheck-hijack (no teamserver)
  ark relay         Pre-implant HTTP NTLM relay + held session GET (no teamserver)
  ark certs seats   Ensure operator + approver mTLS certs
  ark help          Show this help

Data directory: %s

Pre-implant lab helpers (authorized labs only):
  ark ldap help
  ark smb help
  ark ad help
  ark rbcd help
  ark kerberos help
  ark inbound help
  ark winrm help
  ark mssql help
  ark mqtt help
  ark relay help
  docs/OPERATOR_PRE_IMPLANT.md
`, core.Version, arkcli.DataDir())
}

func hasFlag(args []string, names ...string) bool {
	set := map[string]struct{}{}
	for _, n := range names {
		set[n] = struct{}{}
	}
	for _, a := range args {
		if _, ok := set[a]; ok {
			return true
		}
	}
	return false
}

func stripFlags(args []string, names ...string) []string {
	set := map[string]struct{}{}
	for _, n := range names {
		set[n] = struct{}{}
	}
	out := make([]string, 0, len(args))
	for _, a := range args {
		if _, ok := set[a]; ok {
			continue
		}
		out = append(out, a)
	}
	return out
}
