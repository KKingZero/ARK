package core

import "strings"

// parseLine splits an ARK-shell line into command + args.
// A leading "ark" token is stripped so `ark serve` at `ark ›` runs `serve`.
func parseLine(input string) (cmd string, args []string) {
	parts := strings.Fields(strings.TrimSpace(input))
	if len(parts) == 0 {
		return "", nil
	}
	if strings.EqualFold(parts[0], "ark") {
		if len(parts) == 1 {
			return "ark", nil
		}
		parts = parts[1:]
	}
	return parts[0], parts[1:]
}

// promptTag is the bracketed context in `ark[tag] ›`.
// Engagement name wins; otherwise online/offline from teamserver reachability.
func promptTag(online bool, engagement string) string {
	if e := strings.TrimSpace(engagement); e != "" {
		return e
	}
	if online {
		return "online"
	}
	return "offline"
}
