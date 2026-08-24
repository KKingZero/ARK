package preimplant

import (
	"fmt"
	"os"
	"strings"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/netproxy"
)

// ParseFlags splits --key value / --bool flags. Bare args returned separately.
func ParseFlags(args []string) (map[string]string, []string) {
	out := map[string]string{}
	var bare []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			bare = append(bare, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "--") {
			key := strings.TrimPrefix(a, "--")
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				out[key] = args[i+1]
				i++
			} else {
				out[key] = "1"
			}
			continue
		}
		bare = append(bare, a)
	}
	return out, bare
}

func flagBool(f map[string]string, keys ...string) bool {
	for _, k := range keys {
		if v, ok := f[k]; ok && v != "" && v != "0" && !strings.EqualFold(v, "false") {
			return true
		}
	}
	return false
}

func readSecret(f map[string]string, inlineKey, fileKey string) (string, error) {
	if p := f[fileKey]; p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return f[inlineKey], nil
}

func writeSecretFile(path, secret string) error {
	if path == "" {
		return fmt.Errorf("path required")
	}
	return os.WriteFile(path, []byte(secret), 0o600)
}

// printProxyHint names the SOCKS hop before dial so a failed bind is not "wrong DC".
func printProxyHint() {
	if p := netproxy.SOCKSProxy(); p != "" {
		fmt.Printf("via %s\n", p)
		return
	}
	if raw := netproxy.ProxyEnv(); raw != "" {
		fmt.Printf("proxy %s ignored (only socks5)\n", raw)
	}
}
