package krb

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// FaketimeSO looks for libfaketime (lab clock skew). Override with EREBUS_FAKETIME_SO.
func FaketimeSO() string {
	if p := os.Getenv("EREBUS_FAKETIME_SO"); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	candidates := []string{
		"/usr/lib64/libfaketime.so.1",
		"/usr/lib/x86_64-linux-gnu/libfaketime.so.1",
		"/usr/lib/libfaketime.so.1",
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append([]string{
			filepath.Join(dir, "libfaketime.so.1"),
			filepath.Join(dir, "fk", "usr", "lib64", "libfaketime.so.1"),
		}, candidates...)
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// FaketimeOffset formats a Remote-Local delta for libfaketime (e.g. +7h2m).
func FaketimeOffset(delta time.Duration) string {
	sign := "+"
	if delta < 0 {
		sign = "-"
		delta = -delta
	}
	sec := int64(delta.Round(time.Second) / time.Second)
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	switch {
	case h > 0 && m == 0 && s == 0:
		return fmt.Sprintf("%s%dh", sign, h)
	case h > 0 && s == 0:
		return fmt.Sprintf("%s%dh%dm", sign, h, m)
	case h > 0:
		return fmt.Sprintf("%s%dh%dm%ds", sign, h, m, s)
	case m > 0 && s == 0:
		return fmt.Sprintf("%s%dm", sign, m)
	case m > 0:
		return fmt.Sprintf("%s%dm%ds", sign, m, s)
	default:
		return fmt.Sprintf("%s%ds", sign, sec)
	}
}

// RunWithSkew execs argv with libfaketime set so local clock matches remote.
func RunWithSkew(delta time.Duration, argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("command required after --")
	}
	so := FaketimeSO()
	if so == "" {
		return fmt.Errorf("libfaketime not found (set EREBUS_FAKETIME_SO or install libfaketime)")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"LD_PRELOAD="+so,
		"FAKETIME="+FaketimeOffset(delta),
		"FAKETIME_DONT_FAKE_MONOTONIC=1",
	)
	return cmd.Run()
}
