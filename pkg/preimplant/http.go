package preimplant

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
	"github.com/KKingZero/ARK/pkg/netproxy"
)

const httpUsage = `ark http — operator-host HTTP (NTLM, no implant)

  ark http get  --url https://host/ --user U --pass-file P --domain D --insecure
  ark http post --url https://host/path --user U --pass-file P --data BODY --insecure
  ark http get  --url https://host/Package --user U --pass-file P --out body.html --insecure

NTLM via go-ntlmssp. Redirects drop Authorization (do not follow auth).
Honors ARK_PROXY / ALL_PROXY (SOCKS5). Lab-only.
`

// RunHTTP is host-side GET/POST with optional NTLM.
func RunHTTP(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", httpUsage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(httpUsage)
		return nil
	case "get":
		return httpDo(args[1:], http.MethodGet)
	case "post":
		return httpDo(args[1:], http.MethodPost)
	default:
		return fmt.Errorf("unknown http command %q\n%s", args[0], httpUsage)
	}
}

func httpDo(args []string, method string) error {
	f, _ := ParseFlags(args)
	rawURL := first(f, "url")
	user := first(f, "user", "username")
	if rawURL == "" || user == "" {
		return fmt.Errorf("%s", httpUsage)
	}
	pass, err := readSecret(f, "pass", "pass-file")
	if err != nil {
		return err
	}
	cfg := httpClientConfig{
		Insecure: flagBool(f, "insecure"),
		NTLM:     !flagBool(f, "no-ntlm"),
		Domain:   first(f, "domain"),
		User:     user,
		Pass:     pass,
	}
	client := newHTTPClient(cfg)
	var body io.Reader
	if method == http.MethodPost {
		if d := first(f, "data", "body"); d != "" {
			body = strings.NewReader(d)
		}
	}
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return err
	}
	if cfg.NTLM {
		u := user
		if cfg.Domain != "" && !strings.Contains(u, `\`) && !strings.Contains(u, "@") {
			u = cfg.Domain + `\` + user
		}
		req.SetBasicAuth(u, pass)
	}
	printProxyHint()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("HTTP %d %s\n", resp.StatusCode, resp.Status)
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	out := first(f, "out", "output")
	if out == "" || out == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(out, data, 0o600)
}

type httpClientConfig struct {
	Insecure bool
	NTLM     bool
	Domain   string
	User     string
	Pass     string
}

func newHTTPClient(cfg httpClientConfig) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}, //nolint:gosec // lab --insecure
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			timeout := 15 * time.Second
			if deadline, ok := ctx.Deadline(); ok {
				timeout = time.Until(deadline)
			}
			return netproxy.DialTimeout(network, addr, timeout)
		},
	}
	var rt http.RoundTripper = transport
	if cfg.NTLM {
		rt = ntlmssp.Negotiator{RoundTripper: transport}
	}
	return &http.Client{
		Transport: rt,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Header.Del("Authorization")
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}
}
