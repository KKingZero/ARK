package arkhome

import (
	"os"
	"path/filepath"
)

// Dir is the operator data directory.
//
// New installs use ~/.ark. If that folder does not exist but a legacy
// ~/.erebus tree does, that path is kept so certs, DB, and llm.yaml still load.
// ARK_HOME (then EREBUS_HOME) overrides both.
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
	if st, err := os.Stat(ark); err == nil && st.IsDir() {
		return ark
	}
	legacy := filepath.Join(home, ".erebus")
	if st, err := os.Stat(legacy); err == nil && st.IsDir() {
		return legacy
	}
	return ark
}
