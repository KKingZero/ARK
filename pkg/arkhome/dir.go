package arkhome

import (
	"io"
	"os"
	"path/filepath"
)

const migrateSentinel = ".migrated-from-erebus"

// Dir is the operator data directory.
//
// The directory is always ~/.ark. ARK_HOME, then EREBUS_HOME, overrides that.
// A legacy ~/.erebus tree is copied in once when ~/.ark has no server.yaml,
// no certs/, and no ark.db. Existing files (a redirector json, for example)
// are left in place. ~/.erebus is not deleted.
func Dir() string {
	if d := os.Getenv("ARK_HOME"); d != "" {
		return d
	}
	if d := os.Getenv("EREBUS_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "ark")
	}
	ark := filepath.Join(home, ".ark")
	migrateLegacy(ark, filepath.Join(home, ".erebus"))
	return ark
}

func migrateLegacy(ark, legacy string) {
	if !dirExists(legacy) {
		return
	}
	if fileExists(filepath.Join(ark, migrateSentinel)) {
		return
	}
	if err := os.MkdirAll(ark, 0o700); err != nil {
		return
	}
	if arkHasData(ark) {
		writeSentinel(ark, "kept existing ark data\n")
		return
	}
	if err := copyTreeNoClobber(legacy, ark); err != nil {
		return
	}
	writeSentinel(ark, "copied from .erebus\n")
}

func arkHasData(ark string) bool {
	if fileExists(filepath.Join(ark, "server.yaml")) {
		return true
	}
	if dirExists(filepath.Join(ark, "certs")) {
		return true
	}
	if fileExists(filepath.Join(ark, "ark.db")) {
		return true
	}
	return false
}

func writeSentinel(ark, body string) {
	_ = os.WriteFile(filepath.Join(ark, migrateSentinel), []byte(body), 0o600)
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func copyTreeNoClobber(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			if dirExists(target) {
				return nil
			}
			mode := info.Mode().Perm()
			if mode == 0 {
				mode = 0o700
			}
			return os.MkdirAll(target, mode)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if fileExists(target) || dirExists(target) {
			return nil
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if mode == 0 {
		mode = 0o600
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
