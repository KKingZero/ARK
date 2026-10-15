package preimplant

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
	"github.com/KKingZero/ARK/pkg/netproxy"
)

const httpUsage = `ark http — operator-host HTTP (no implant)

  ark http get  --url http://host/api/status
  ark http post --url http://host/login --data password=secret --cookie-jar cj
  ark http post --url http://host/api --data-file body.json --content-type application/json
  ark http get  --url http://host/dashboard --cookie-jar cj --out body.html
  ark http get  --url https://host/ --user U --pass-file P --domain D --insecure

Anonymous by default. NTLM only when --user is set (pass or pass-file required).
--no-ntlm with --user sends no Authorization header.
--header and --cookie may be repeated. --cookie-jar is name=value lines, mode 600.
Response status and headers are printed like curl -i. With --out, headers go to
stderr and the body goes to the file.
Redirects drop Authorization. Cookies ride the jar across redirects.
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
	res, err := httpFetch(args, method)
	if err != nil {
		return err
	}
	return writeHTTPResult(os.Stdout, os.Stderr, res)
}

type httpResult struct {
	proto   string
	status  string
	header  http.Header
	body    []byte
	outPath string
}

func httpFetch(args []string, method string) (httpResult, error) {
	f, _ := ParseFlags(args)
	rawURL := first(f, "url")
	if rawURL == "" {
		return httpResult{}, fmt.Errorf("%s", httpUsage)
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return httpResult{}, fmt.Errorf("http: bad --url %q", rawURL)
	}
	user := first(f, "user", "username")
	var pass string
	if user != "" {
		pass, err = readSecret(f, "pass", "pass-file")
		if err != nil {
			return httpResult{}, err
		}
		if pass == "" {
			return httpResult{}, fmt.Errorf("http: --user requires --pass or --pass-file")
		}
	}
	body, err := httpBody(f, method)
	if err != nil {
		return httpResult{}, err
	}
	header, err := parseHeaderFlags(flagAll(args, "header"))
	if err != nil {
		return httpResult{}, err
	}
	jarCookies, err := loadCookieJar(first(f, "cookie-jar"))
	if err != nil {
		return httpResult{}, err
	}
	for _, raw := range flagAll(args, "cookie") {
		more, err := parseCookiePairs(raw)
		if err != nil {
			return httpResult{}, err
		}
		for k, v := range more {
			jarCookies[k] = v
		}
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return httpResult{}, err
	}
	if len(jarCookies) > 0 {
		jar.SetCookies(u, cookiesFor(jarCookies))
	}
	cfg := httpClientConfig{
		Insecure: flagBool(f, "insecure"),
		NTLM:     user != "" && !flagBool(f, "no-ntlm"),
		Domain:   first(f, "domain"),
		User:     user,
		Pass:     pass,
	}
	client := newHTTPClient(cfg, jar)
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, rdr)
	if err != nil {
		return httpResult{}, err
	}
	for k, vals := range header {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	if ct := first(f, "content-type"); ct != "" {
		if strings.ContainsAny(ct, "\r\n") {
			return httpResult{}, fmt.Errorf("http: --content-type contains a newline")
		}
		req.Header.Set("Content-Type", ct)
	} else if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cfg.NTLM {
		nu := user
		if cfg.Domain != "" && !strings.Contains(nu, `\`) && !strings.Contains(nu, "@") {
			nu = cfg.Domain + `\` + user
		}
		req.SetBasicAuth(nu, pass)
	}
	printProxyHint()
	resp, err := client.Do(req)
	if err != nil {
		return httpResult{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return httpResult{}, err
	}
	if jarPath := first(f, "cookie-jar"); jarPath != "" {
		final := u
		if resp.Request != nil && resp.Request.URL != nil {
			final = resp.Request.URL
		}
		if err := saveCookieJar(jarPath, jarSnapshot(jar, u, final)); err != nil {
			return httpResult{}, err
		}
	}
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	return httpResult{
		proto:   proto,
		status:  resp.Status,
		header:  resp.Header.Clone(),
		body:    data,
		outPath: first(f, "out", "output"),
	}, nil
}

func writeHTTPResult(stdout, stderr io.Writer, res httpResult) error {
	hw := stdout
	if res.outPath != "" {
		hw = stderr
	}
	fmt.Fprintf(hw, "%s %s\n", res.proto, res.status)
	for _, k := range slices.Sorted(maps.Keys(res.header)) {
		for _, v := range res.header[k] {
			fmt.Fprintf(hw, "%s: %s\n", k, v)
		}
	}
	fmt.Fprintln(hw)
	if res.outPath != "" {
		return os.WriteFile(res.outPath, res.body, 0o600)
	}
	_, err := stdout.Write(res.body)
	return err
}

func httpBody(f map[string]string, method string) (string, error) {
	if method != http.MethodPost && method != http.MethodPut {
		return "", nil
	}
	if p := first(f, "data-file"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return first(f, "data", "body"), nil
}

func flagAll(args []string, key string) []string {
	want := "--" + key
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			break
		}
		if args[i] != want {
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			continue
		}
		out = append(out, args[i+1])
		i++
	}
	return out
}

func parseHeaderFlags(raw []string) (http.Header, error) {
	h := make(http.Header)
	for _, line := range raw {
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || name == "" {
			return nil, fmt.Errorf("http: --header must be Name: value")
		}
		if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("http: header contains a newline")
		}
		h.Add(name, value)
	}
	return h, nil
}

func parseCookiePairs(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || name == "" {
			return nil, fmt.Errorf("http: --cookie must be name=value")
		}
		if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("http: cookie contains a newline")
		}
		out[name] = value
	}
	return out, nil
}

func loadCookieJar(path string) (map[string]string, error) {
	out := map[string]string{}
	if path == "" {
		return out, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("http: bad cookie jar line %q", line)
		}
		out[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	return out, nil
}

func saveCookieJar(path string, cookies map[string]string) error {
	var b strings.Builder
	b.WriteString("# ark http cookie jar\n")
	for _, name := range slices.Sorted(maps.Keys(cookies)) {
		fmt.Fprintf(&b, "%s=%s\n", name, cookies[name])
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func cookiesFor(m map[string]string) []*http.Cookie {
	names := slices.Sorted(maps.Keys(m))
	out := make([]*http.Cookie, 0, len(names))
	for _, name := range names {
		out = append(out, &http.Cookie{Name: name, Value: m[name], Path: "/"})
	}
	return out
}

func jarSnapshot(jar http.CookieJar, urls ...*url.URL) map[string]string {
	out := map[string]string{}
	if jar == nil {
		return out
	}
	for _, u := range urls {
		if u == nil {
			continue
		}
		for _, c := range jar.Cookies(u) {
			out[c.Name] = c.Value
		}
	}
	return out
}

type httpClientConfig struct {
	Insecure bool
	NTLM     bool
	Domain   string
	User     string
	Pass     string
}

func newHTTPClient(cfg httpClientConfig, jar http.CookieJar) *http.Client {
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
		Jar:       jar,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}
}
