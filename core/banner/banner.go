package banner

import (
	"strings"

	"github.com/KKingZero/ARK/core/theme"
)

// Art is the uncolored ARK wordmark (hull + open-bottom A).
const Art = `
╔══════════════════════════════════════════════════════════════╗
║         /|    |\                                             ║
║        / |    | \                                            ║
║       /  |    |  \           /\      _____      _  __        ║
║      |   |    |   |         /  \    |  _  \    | |/ /        ║
║      |   |    |   |        / /\ \   | |_) |    | ' /         ║
║      |   |    |   |       / /  \ \  |  _ <     |  <          ║
║      |   |    |   |      / /    \ \ | | \ \    | . \         ║
║      |   |    |   |     /_/      \_\ |_|  \_\   |_|\_\       ║
║       \   \__/   /                                           ║
║        \___==___/                                            ║
║                      C2  ·  BY ZYPHERON                      ║
║                  SPEED · STEALTH · CONTROL                   ║
╚══════════════════════════════════════════════════════════════╝
`

// Text is Art with cyan on the mark, dim on the box.
var Text = Color(Art)

// Color paints hull/letters cyan and box-drawing dim gray.
func Color(art string) string {
	var b strings.Builder
	for i, line := range strings.Split(art, "\n") {
		if i > 0 {
			b.WriteByte('\n')
		}
		if line == "" {
			continue
		}
		runes := []rune(line)
		if len(runes) < 2 {
			b.WriteString(line)
			continue
		}
		first, last := runes[0], runes[len(runes)-1]
		box := first == '╔' || first == '╚' || first == '║'
		if !box {
			b.WriteString(line)
			continue
		}
		inner := strings.TrimSpace(string(runes[1 : len(runes)-1]))
		switch {
		case first == '╔' || first == '╚' || inner == "":
			b.WriteString(theme.ANSIDim)
			b.WriteString(line)
			b.WriteString(theme.ANSIReset)
		case strings.Contains(inner, "C2") || strings.Contains(inner, "SPEED"):
			b.WriteString(theme.ANSIDim)
			b.WriteRune(first)
			b.WriteString(theme.ANSIReset)
			b.WriteString(string(runes[1 : len(runes)-1]))
			b.WriteString(theme.ANSIDim)
			b.WriteRune(last)
			b.WriteString(theme.ANSIReset)
		default:
			b.WriteString(theme.ANSIDim)
			b.WriteRune(first)
			b.WriteString(theme.ANSIAccent)
			b.WriteString(string(runes[1 : len(runes)-1]))
			b.WriteString(theme.ANSIDim)
			b.WriteRune(last)
			b.WriteString(theme.ANSIReset)
		}
	}
	return b.String()
}
