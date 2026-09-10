package core

import (
	"fmt"
	"strings"
)

// replHelpText is the ARK-shell help (no `ark` binary prefix on commands).
func replHelpText() string {
	var b strings.Builder
	sec := func(title string) {
		b.WriteString("\n")
		b.WriteString(title)
		b.WriteString("\n")
	}
	row := func(cmd, desc string) {
		b.WriteString(fmt.Sprintf("  %-20s%s\n", cmd, desc))
	}
	sec("CORE")
	row("serve", "Start operator")
	row("ai [message]", "Open or query ARK AI")
	sec("OPERATIONS")
	row("sessions", "Active sessions")
	row("loot", "Captured artifacts")
	row("engagements", "Named engagements")
	row("report", "Generate report")
	sec("AI")
	row("ai setup", "Configure model")
	row("ai provider", "Change provider")
	row("ai models", "Models")
	sec("SYSTEM")
	row("status", "ARK status")
	row("clear", "")
	row("exit", "")
	b.WriteString("\nRun `help <command>` for details.\n")
	b.WriteString("?  same as help.  Esc / exit leaves the shell.\n")
	return b.String()
}

func commandHelp(topic string) string {
	topic = strings.ToLower(strings.TrimSpace(topic))
	topic = strings.TrimPrefix(topic, "ark ")
	switch topic {
	case "serve":
		return `serve
  Start the teamserver in this process and stay in the ARK shell.

  After it comes up:
    status             show listeners / sessions / AI
    ai                 open ARK AI (Auto can drive the operator)
    sessions           list implants

  From bash this is:  ark serve
  That bash form also attaches the implant operator REPL.
  Inside ARK, type serve — not ark serve.`
	case "ai":
		return `ai [message]
  Open the ARK AI view. Optional message is sent as the first turn.

  ai setup             provider / key / model wizard
  ai provider <name>   switch provider
  ai models            list models
  ai providers         list providers
  ai config            show active provider (masked keys)

  Inside AI:
    /serve /back /quit /clear /mode
    Esc back   Tab provider   ⇧Tab mode   ? help`
	case "status":
		return `status
  One-shot C2 picture: teamserver, operator, listener, sessions, AI, engagement.`
	case "sessions":
		return `sessions
  List active implant sessions (requires serve).

  sessions -i <id>     session details`
	case "loot":
		return `loot
  List captured artifacts (requires serve).`
	case "engagements", "workspace":
		return `engagements
  Named operation context. Shown in the prompt as ark[<name>] ›

  engagements              show current
  engagements list         same
  engagements new <name>   create and switch

  workspace is an alias.`
	case "report":
		return `report generate
  Generate a pentest report (not available yet).`
	case "clear":
		return `clear
  Clear the screen.`
	case "exit", "quit":
		return `exit
  Leave the ARK shell. If this shell started the teamserver, it stops.`
	case "help", "?":
		return `help [command]
  Command index, or details for one command.`
	default:
		return ""
	}
}
