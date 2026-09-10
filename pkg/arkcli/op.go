package arkcli

import "github.com/KKingZero/ARK/pkg/operatorcli"

// OpOptions configures non-interactive operator commands.
type OpOptions struct {
	Server           string
	CertFile         string
	KeyFile          string
	CAFile           string
	ApproverCertFile string
	ApproverKeyFile  string
}

// RunOp executes a one-shot operator command using the same handlers as the REPL.
func RunOp(opts OpOptions, args []string) error {
	if opts.Server == "" {
		opts.Server = "127.0.0.1:50051"
	}
	if opts.CertFile == "" || opts.KeyFile == "" || opts.CAFile == "" {
		c, k, ca := DefaultCertPaths()
		if opts.CertFile == "" {
			opts.CertFile = c
		}
		if opts.KeyFile == "" {
			opts.KeyFile = k
		}
		if opts.CAFile == "" {
			opts.CAFile = ca
		}
	}
	return operatorcli.Exec(operatorcli.Options{
		Server:           opts.Server,
		CertFile:         opts.CertFile,
		KeyFile:          opts.KeyFile,
		CAFile:           opts.CAFile,
		ApproverCertFile: opts.ApproverCertFile,
		ApproverKeyFile:  opts.ApproverKeyFile,
	}, args)
}
