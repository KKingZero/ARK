package operatorcli

import (
	"fmt"
	"sort"
	"strings"

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
		Prompt:          "ark > ",
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

	fmt.Println("ARK C2 Operator Console")
	fmt.Println("Type 'help' for available commands")
	fmt.Println()

	handlers := r.cmds.Handlers()

	for {
		// Update prompt with active session
		if r.cmds.sessionID != "" {
			r.rl.SetPrompt(fmt.Sprintf("ark [%s] > ", r.cmds.sessionID[:8]))
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
