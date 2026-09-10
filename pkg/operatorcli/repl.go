package operatorcli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKingZero/ARK/core/banner"
	"github.com/KKingZero/ARK/core/theme"
	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/chzyer/readline"
)

type REPL struct {
	cmds *Commands
	rl   *readline.Instance
}

func NewREPL(client pb.ErebusC2Client, approverClient pb.ErebusC2Client) (*REPL, error) {
	cmds := NewCommands(client, approverClient)

	// Build completer from command names
	handlers := cmds.Handlers()
	names := make([]string, 0, len(handlers))
	for name := range handlers {
		names = append(names, name)
	}
	sort.Strings(names)

	var items []readline.PrefixCompleterInterface
	for _, name := range names {
		items = append(items, readline.PcItem(name))
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          theme.ANSIAccent + "ark" + theme.ANSIDim + "[operator] › " + theme.ANSIReset,
		AutoComplete:    readline.NewPrefixCompleter(items...),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return nil, fmt.Errorf("readline init: %w", err)
	}

	return &REPL{
		cmds: cmds,
		rl:   rl,
	}, nil
}

func (r *REPL) Run() error {
	defer r.rl.Close()

	fmt.Print(banner.Text)
	fmt.Println("Type 'help' for available commands")
	fmt.Println()

	handlers := r.cmds.Handlers()

	for {
		// Update prompt with active session
		if r.cmds.sessionID != "" {
			sid := r.cmds.sessionID
			if len(sid) > 8 {
				sid = sid[:8]
			}
			r.rl.SetPrompt(fmt.Sprintf("%sark%s[%s] › %s", theme.ANSIAccent, theme.ANSIDim, sid, theme.ANSIReset))
		}

		line, err := r.rl.Readline()
		if err != nil {
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]
		args := parts[1:]

		handler, ok := handlers[cmd]
		if !ok {
			fmt.Printf("Unknown command: %s (type 'help')\n", cmd)
			continue
		}

		if err := handler(args); err != nil {
			if err == errExit {
				return nil
			}
			fmt.Printf("Error: %v\n", err)
		}
	}
}
