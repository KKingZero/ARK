package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/KKingZero/erebus-exploit-framwork/core"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/erebuscli"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/operatorcli"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/preimplant"
	"github.com/KKingZero/erebus-exploit-framwork/server"
)

func main() {
	// Default: interactive startup UI (banner + erebus › prompt)
	if len(os.Args) < 2 {
		runConsole([]string{})
		return
	}

	switch os.Args[1] {
	case "serve":
		// `serve` starts teamserver + operator REPL. Stdin/REPL EOF does not stop C2.
		// Use `erebus teamserver` (or serve --teamserver) for daemon-only (no REPL).
		if hasFlag(os.Args[2:], "--teamserver", "-d") {
			runTeamserver(stripFlags(os.Args[2:], "--teamserver", "-d"))
			return
		}
		if err := erebuscli.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "erebus: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "erebus mqtt: %v\n", err)
			os.Exit(1)
		}
	case "relay":
		if err := preimplant.RunRelay(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "erebus relay: %v\n", err)
			os.Exit(1)
		}
	case "ldap":
		if err := preimplant.RunLDAP(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "erebus ldap: %v\n", err)
			os.Exit(1)
		}
	case "smb":
		if err := preimplant.RunSMB(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "erebus smb: %v\n", err)
			os.Exit(1)
		}
	case "ad":
		if err := preimplant.RunAD(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "erebus ad: %v\n", err)
			os.Exit(1)
		}
	case "kerberos":
		if err := preimplant.RunKerberos(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "erebus kerberos: %v\n", err)
			os.Exit(1)
		}
	case "console":
		runConsole(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		// Support erebus -json without subcommand
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
	passphrase := os.Getenv("EREBUS_PASSPHRASE")
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
	if err := erebuscli.RunTeamserver(configPath, passphrase); err != nil {
		fmt.Fprintf(os.Stderr, "erebus teamserver: %v\n", err)
		os.Exit(1)
	}
}

func runOperator(args []string) {
	serverAddr := "127.0.0.1:50051"
	defCert, defKey, defCA := erebuscli.DefaultCertPaths()
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
		if opCert, opKey, opCA, err := erebuscli.EnsureOperatorCerts(erebuscli.DataDir()); err == nil {
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
		fmt.Fprintf(os.Stderr, "erebus operator: %v\n", err)
		os.Exit(1)
	}
}

func runOp(args []string) {
	opts := erebuscli.OpOptions{Server: "127.0.0.1:50051"}
	defCert, defKey, defCA := erebuscli.DefaultCertPaths()
	opts.CertFile, opts.KeyFile, opts.CAFile = defCert, defKey, defCA
	apC, apK := erebuscli.DefaultApproverCertPaths()
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
	if err := erebuscli.RunOp(opts, args[i:]); err != nil {
		fmt.Fprintf(os.Stderr, "erebus op: %v\n", err)
		os.Exit(1)
	}
}

func runCerts(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: erebus certs seats\n")
		os.Exit(1)
	}
	switch args[0] {
	case "seats":
		if err := erebuscli.RunCertsSeats(erebuscli.DataDir()); err != nil {
			fmt.Fprintf(os.Stderr, "erebus certs seats: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown certs command: %s (try: seats)\n", args[0])
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Erebus Exploitation Framework v%s

Usage:
  erebus              Interactive console (startup UI)
  erebus -json         JSON console mode
  erebus serve         Start teamserver + operator REPL (stdin/EOF does not stop C2)
  erebus serve --teamserver   Teamserver only (same as erebus teamserver)
  erebus teamserver    Run teamserver only (preferred daemon / HTB C2)
  erebus operator      Connect to teamserver REPL
  erebus op            One-shot operator commands (sessions/shell/generate/...)
  erebus ldap          Host-side LDAP (LDAPS, enum, dangling templates)
  erebus smb           Host-side SMB list/get (no implant)
  erebus ad            Host-side AD writes (password reset)
  erebus kerberos      Clock skew check / libfaketime wrap
  erebus mqtt          Pre-implant MQTT sub/pub/healthcheck-hijack (no teamserver)
  erebus relay         Pre-implant HTTP NTLM relay + held session GET (no teamserver)
  erebus certs seats   Ensure operator + approver mTLS certs
  erebus help          Show this help

Data directory: %s

Pre-implant lab helpers (authorized labs only):
  erebus ldap help
  erebus smb help
  erebus ad help
  erebus kerberos help
  erebus mqtt help
  erebus relay help
  docs/OPERATOR_PRE_IMPLANT.md
`, core.Version, erebuscli.DataDir())
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
