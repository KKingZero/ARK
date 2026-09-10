package core

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KKingZero/ARK/core/banner"
	"github.com/KKingZero/ARK/core/theme"
	"github.com/KKingZero/ARK/pkg/arkcli"
	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/KKingZero/ARK/server"
	"github.com/chzyer/readline"
)

// Version is the ARK framework version shown at startup.
const Version = "0.1.0"

const promptDefault = theme.ANSIAccent + "ark" + theme.ANSIDim + "[%s] › " + theme.ANSIReset

type Console struct {
	workspace  string
	session    string
	running    bool
	mode       OutputMode
	team       TeamClient
	teamBanner bool
	online     bool
	ownedTS    *arkcli.TeamserverHandle
}

func NewConsole(jsonMode bool) *Console {
	m := OutputHuman
	if jsonMode {
		m = OutputJSON
	}
	return &Console{running: true, mode: m}
}

func (c *Console) Start() {
	c.StartWith("")
}

// StartWith runs an optional first command (e.g. "ai") then the REPL.
func (c *Console) StartWith(boot string) {
	defer c.stopOwnedTeamserver()
	c.online = c.probeOnline()
	if c.mode == OutputJSON {
		if boot != "" {
			c.handleCommand(boot)
		}
		c.startJSON()
		return
	}
	c.startInteractive(boot)
}

func (c *Console) probeOnline() bool {
	cfg, err := server.LoadConfig(server.ConfigPath())
	if err != nil {
		cfg = server.DefaultConfig()
	}
	return arkcli.GRPCReachable(cfg.GRPCAddr)
}

func printStartupBanner() {
	fmt.Print(banner.Text)
	fmt.Println("Type 'help' for available commands")
	fmt.Println()
}

// startInteractive runs the human-friendly readline REPL
func (c *Console) startInteractive(boot string) {
	printStartupBanner()
	if boot != "" {
		c.handleCommand(boot)
		if !c.running {
			return
		}
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          c.prompt(),
		HistoryFile:     arkHistoryPath(),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    consoleCompleter(),
	})
	if err != nil {
		panic(err)
	}
	defer rl.Close()

	for c.running {
		rl.SetPrompt(c.prompt())
		line, err := rl.Readline()
		if err != nil {
			break
		}
		input := strings.TrimSpace(line)
		if input == "" {
			continue
		}
		c.handleCommand(input)
		if commandMayContainSecret(input) {
			scrubLastHistoryEntry(arkHistoryPath())
		}
	}
}

func consoleCompleter() *readline.PrefixCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("help"),
		readline.PcItem("?"),
		readline.PcItem("serve"),
		readline.PcItem("status"),
		readline.PcItem("ai",
			readline.PcItem("setup"),
			readline.PcItem("provider"),
			readline.PcItem("models"),
			readline.PcItem("providers"),
			readline.PcItem("config"),
			readline.PcItem("help"),
		),
		readline.PcItem("sessions"),
		readline.PcItem("loot"),
		readline.PcItem("engagements",
			readline.PcItem("new"),
			readline.PcItem("list"),
		),
		readline.PcItem("workspace",
			readline.PcItem("new"),
			readline.PcItem("list"),
		),
		readline.PcItem("report", readline.PcItem("generate")),
		readline.PcItem("clear"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)
}

// startJSON runs a line-oriented JSON mode for AI/programmatic control.
func (c *Console) startJSON() {
	emit(c.mode, Response{
		Status:  "ok",
		Command: "init",
		Message: "ARK console ready",
		Data: map[string]interface{}{
			"version": Version,
			"mode":    "json",
		},
	})

	scanner := bufio.NewScanner(os.Stdin)
	for c.running && scanner.Scan() {
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}
		c.handleCommand(input)
	}
}

func (c *Console) prompt() string {
	return fmt.Sprintf(promptDefault, promptTag(c.online, c.workspace))
}

func (c *Console) handleCommand(input string) {
	cmd, args := parseLine(input)
	if cmd == "" {
		return
	}

	switch strings.ToLower(cmd) {
	case "help", "?":
		c.cmdHelp(args)
	case "serve":
		c.cmdServe()
	case "status":
		c.cmdStatus()
	case "clear":
		if c.mode == OutputHuman {
			fmt.Print("\033[H\033[2J")
			printStartupBanner()
		}
	case "sessions":
		c.cmdSessions(args)
	case "engagements", "workspace":
		c.cmdEngagements(args)
	case "loot":
		c.cmdLoot()
	case "report":
		c.cmdReport(args)
	case "ai":
		c.cmdAI(args)
	case "ark":
		emitError(c.mode, "ark", "You're already in the ARK shell. Type `serve`, not `ark serve`.")
	case "exit", "quit":
		emit(c.mode, Response{
			Status:  "ok",
			Command: "exit",
			Message: "\n> Exiting ARK. Stay in the shadows.\n",
		})
		c.running = false
	default:
		emitError(c.mode, cmd, fmt.Sprintf("Unknown command: %s (try help)", cmd))
	}
}

func (c *Console) cmdHelp(args []string) {
	if len(args) > 0 {
		topic := strings.Join(args, " ")
		msg := commandHelp(topic)
		if msg == "" {
			emitError(c.mode, "help", fmt.Sprintf("No help for %q. Type help.", topic))
			return
		}
		emit(c.mode, Response{
			Status:  "ok",
			Command: "help",
			Message: "\n" + msg + "\n",
			Data:    map[string]string{"topic": topic},
		})
		return
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "help",
		Message: replHelpText(),
		Data: map[string]interface{}{
			"layer": "ark-shell",
		},
	})
}

func (c *Console) cmdSessions(args []string) {
	client, addr, err := c.team.connect()
	if err != nil {
		emit(c.mode, Response{
			Status:  "info",
			Command: "sessions",
			Message: fmt.Sprintf("> Teamserver unavailable (%v)\n> Start with: serve", err),
			Data: map[string]interface{}{
				"sessions": []interface{}{},
				"count":    0,
			},
		})
		return
	}
	c.maybeTeamBanner(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if len(args) > 0 && args[0] == "-i" {
		id := ""
		if len(args) > 1 {
			id = args[1]
		}
		if id == "" {
			emitError(c.mode, "sessions", "Usage: sessions -i <session-id>")
			return
		}
		resp, err := client.GetSession(ctx, &pb.GetSessionRequest{SessionId: id})
		if err != nil {
			emitError(c.mode, "sessions", err.Error())
			return
		}
		s := resp.Session
		msg := fmt.Sprintf("> Session %s\n  Host: %s@%s\n  OS: %s/%s  Transport: %s\n  Alive: %v  Last checkin: %d",
			s.SessionId, s.Username, s.Hostname, s.Os, s.Arch, s.Transport, s.Alive, s.LastCheckin)
		emit(c.mode, Response{
			Status:  "ok",
			Command: "sessions",
			Message: msg,
			Data:    map[string]interface{}{"session": s},
		})
		return
	}

	resp, err := client.ListSessions(ctx, &pb.ListSessionsRequest{})
	if err != nil {
		emitError(c.mode, "sessions", err.Error())
		return
	}
	if len(resp.Sessions) == 0 {
		emit(c.mode, Response{
			Status:  "ok",
			Command: "sessions",
			Message: "> No active sessions",
			Data: map[string]interface{}{
				"sessions": []interface{}{},
				"count":    0,
			},
		})
		return
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("> %d session(s)\n", len(resp.Sessions)))
	b.WriteString(fmt.Sprintf("  %-36s %-15s %-12s %-8s %-10s %-6s\n", "SESSION", "HOSTNAME", "USER", "OS", "TRANSPORT", "ALIVE"))
	for _, s := range resp.Sessions {
		alive := "yes"
		if !s.Alive {
			alive = "no"
		}
		b.WriteString(fmt.Sprintf("  %-36s %-15s %-12s %-8s %-10s %-6s\n",
			s.SessionId, s.Hostname, s.Username, s.Os, s.Transport, alive))
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "sessions",
		Message: b.String(),
		Data: map[string]interface{}{
			"sessions": resp.Sessions,
			"count":    len(resp.Sessions),
		},
	})
}

func (c *Console) cmdLoot() {
	client, addr, err := c.team.connect()
	if err != nil {
		emit(c.mode, Response{
			Status:  "info",
			Command: "loot",
			Message: fmt.Sprintf("> Teamserver unavailable (%v)\n> Start with: serve", err),
			Data: map[string]interface{}{
				"items": []interface{}{},
				"count": 0,
			},
		})
		return
	}
	c.maybeTeamBanner(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := client.ListLoot(ctx, &pb.ListLootRequest{})
	if err != nil {
		emitError(c.mode, "loot", err.Error())
		return
	}
	if len(resp.Items) == 0 {
		emit(c.mode, Response{
			Status:  "ok",
			Command: "loot",
			Message: "> Loot database empty — run some modules first",
			Data: map[string]interface{}{
				"items": []interface{}{},
				"count": 0,
			},
		})
		return
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("> %d loot item(s)\n", len(resp.Items)))
	for _, item := range resp.Items {
		b.WriteString(fmt.Sprintf("  [%s] %s from %s (%d bytes)\n", item.Type, item.Id, item.Source, len(item.Data)))
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "loot",
		Message: b.String(),
		Data: map[string]interface{}{
			"items": resp.Items,
			"count": len(resp.Items),
		},
	})
}

func (c *Console) cmdReport(args []string) {
	if len(args) == 0 || args[0] != "generate" {
		emitError(c.mode, "report", "Usage: report generate")
		return
	}
	emit(c.mode, Response{
		Status:  "ok",
		Command: "report",
		Message: "> Report generation is not available yet.\n> Use operator REPL loot/tasks output or export from Zypheron.",
		Data: map[string]string{
			"action": "generate",
			"status": "unavailable",
		},
	})
}

func (c *Console) maybeTeamBanner(addr string) {
	if c.teamBanner || c.mode == OutputJSON {
		return
	}
	c.teamBanner = true
	fmt.Fprintf(os.Stderr, "[ark] connected to teamserver at %s\n", addr)
}
