package smbcli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/krb"
	"github.com/jcmturner/gokrb5/v8/credentials"
)

// TODO(native): replace Impacket wrap with a Kerberos SMB initiator
// (go-smb2 Initiator methods are unexported; needs a fork or another stack).

var (
	lookSMBClient = lookImpacketBin
	runImpacket   = runImpacketCmd
)

// UseTicket is Kerberos SMB (no NT hash). NTLM go-smb2 cannot consume a ccache.
func UseTicket(opts Options) bool {
	return opts.Ticket != "" && opts.Hash == ""
}

func lookImpacketBin(names ...string) (string, error) {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	home, _ := os.UserHomeDir()
	for _, n := range names {
		p := filepath.Join(home, ".local", "bin", n)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH (temporary Impacket wrap)", names[0])
}

func runImpacketCmd(argv []string, env []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty argv")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w (%s)", argv[0], err, truncate(string(out), 500))
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

type ticketAuth struct {
	ccache string
	domain string
	user   string
	realm  string
}

func resolveTicket(opts Options) (ticketAuth, error) {
	_, path, err := krb.LoadTicket(opts.Ticket, "")
	if err != nil {
		return ticketAuth{}, err
	}
	cc, err := credentials.LoadCCache(path)
	if err != nil {
		return ticketAuth{}, fmt.Errorf("ccache: %w", err)
	}
	realm := cc.GetClientRealm()
	user := ""
	if pn := cc.GetClientPrincipalName(); len(pn.NameString) > 0 {
		user = pn.NameString[0]
	}
	dom := opts.Domain
	if dom == "" {
		dom = realm
	}
	return ticketAuth{ccache: path, domain: dom, user: user, realm: realm}, nil
}

func smbclientArgv(bin string, opts Options, auth ticketAuth, inputFile string) []string {
	target := fmt.Sprintf("%s/%s@%s", auth.domain, auth.user, opts.Host)
	argv := []string{bin, "-k", "-no-pass", target, "-inputfile", inputFile}
	if opts.Host != "" {
		argv = append(argv, "-target-ip", hostWithoutPort(opts.Host))
	}
	return argv
}

func hostWithoutPort(host string) string {
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host, "]") {
		return host[:i]
	}
	return host
}

func ticketEnv(auth ticketAuth, opts Options) ([]string, error) {
	dir := filepath.Dir(auth.ccache)
	kdc := hostWithoutPort(opts.Host)
	conf, err := krb.WriteConfigFile(dir, strings.ToLower(auth.realm), kdc)
	if err != nil {
		// realm may already be FQDN; try Domain
		if opts.Domain != "" {
			conf, err = krb.WriteConfigFile(dir, opts.Domain, kdc)
		}
		if err != nil {
			return nil, err
		}
	}
	env := []string{
		"KRB5CCNAME=" + auth.ccache,
		"KRB5_CONFIG=" + conf,
	}
	if d := krb.ClockOffset(); d != 0 {
		extra, err := krb.FaketimeEnv(d)
		if err != nil {
			return nil, fmt.Errorf("smb --ticket needs faketime SO (EREBUS_FAKETIME_SO) while skew_delta=%s; native Kerberos SMB not shipped: %w", krb.FormatDelta(d), err)
		}
		env = append(env, extra...)
	}
	return env, nil
}

func runTicketShell(opts Options, commands string) (string, error) {
	auth, err := resolveTicket(opts)
	if err != nil {
		return "", err
	}
	if auth.user == "" {
		return "", fmt.Errorf("smb --ticket: ccache has no client principal")
	}
	bin, err := lookSMBClient("smbclient.py", "impacket-smbclient")
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "erebus-smb-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte(commands), 0o600); err != nil {
		return "", err
	}
	env, err := ticketEnv(auth, opts)
	if err != nil {
		return "", err
	}
	argv := smbclientArgv(bin, opts, auth, in)
	out, err := runImpacket(argv, env)
	return string(out), err
}

func parseSmbclientLines(out string) []string {
	var lines []string
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "Impacket") || strings.HasPrefix(ln, "[*]") || strings.HasPrefix(ln, "[-]") {
			continue
		}
		lines = append(lines, ln)
	}
	return lines
}

// TicketListShares lists shares via Impacket smbclient.py -k.
func TicketListShares(opts Options) ([]string, error) {
	out, err := runTicketShell(opts, "shares\n")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, ln := range parseSmbclientLines(out) {
		n := strings.TrimSpace(ln)
		if n == "" || strings.Contains(n, " ") && !strings.HasSuffix(n, "$") {
			// skip banner-ish lines; keep typical share names
			if strings.Contains(n, "Sharename") || strings.Contains(n, "---------") || strings.HasPrefix(n, "Type") {
				continue
			}
		}
		fields := strings.Fields(n)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Sharename" || fields[0] == "---------" {
			continue
		}
		names = append(names, fields[0])
	}
	return names, nil
}

// TicketListDir lists a share path via Impacket smbclient.py -k.
func TicketListDir(opts Options, share, path string) ([]string, error) {
	if share == "" {
		return nil, fmt.Errorf("share required")
	}
	p := NormalizePath(path)
	if p == "." {
		p = ""
	}
	cmd := "use " + share + "\nls " + p + "\n"
	out, err := runTicketShell(opts, cmd)
	if err != nil {
		return nil, err
	}
	return parseSmbclientLines(out), nil
}

// TicketDownload copies a remote file via Impacket smbclient.py -k.
func TicketDownload(opts Options, share, remote, destPath string) error {
	if share == "" || remote == "" {
		return fmt.Errorf("share and path required")
	}
	dir, err := os.MkdirTemp("", "erebus-smbget-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	local := filepath.Join(dir, "out.bin")
	if destPath != "" && destPath != "-" {
		local = destPath
	}
	cmd := "use " + share + "\nget " + strings.ReplaceAll(NormalizePath(remote), "/", "\\") + " " + local + "\n"
	if _, err := runTicketShell(opts, cmd); err != nil {
		return err
	}
	if destPath == "" || destPath == "-" {
		b, err := os.ReadFile(local)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(b)
		return err
	}
	return nil
}
