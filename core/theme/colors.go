package theme

import "github.com/charmbracelet/lipgloss"

// Cyan is the ARK UI accent (prompt, active state, branding).
const Cyan = "#00C8E0"

// Deep is a darker cyan for secondary chrome.
const Deep = "#0891B2"

const (
	ANSIReset  = "\033[0m"
	ANSIAccent = "\033[1;38;5;51m"
	ANSIDeep   = "\033[38;5;45m"
	ANSIDim    = "\033[38;5;245m"
)

// Crimson is a deprecated alias of Cyan (old red accent).
const Crimson = Cyan

// ANSICrimson is a deprecated alias of ANSIAccent.
const ANSICrimson = ANSIAccent

var (
	cyan = lipgloss.Color(Cyan)
	deep = lipgloss.Color(Deep)
	mute = lipgloss.Color("240")

	Default = lipgloss.NewStyle()

	Accent      = lipgloss.NewStyle().Foreground(cyan).Bold(true)
	AccentPlain = lipgloss.NewStyle().Foreground(cyan)
	DeepStyle   = lipgloss.NewStyle().Foreground(deep)
	Dim         = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))

	Border = lipgloss.NewStyle().BorderForeground(mute)
	Box    = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(mute).
		Padding(0, 1)

	Active   = Accent
	Inactive = Dim
)
