package tasks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveJailedPath resolves remotePath relative to the implant working directory.
// Absolute paths and paths that escape cwd (via ..) are rejected.
func resolveJailedPath(remotePath string) (string, error) {
	if remotePath == "" {
		return "", fmt.Errorf("path required")
	}
	if filepath.IsAbs(remotePath) {
		return "", fmt.Errorf("absolute paths not allowed")
	}

	clean := filepath.Clean(remotePath)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes working directory")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}

	cwdAbs, err := filepath.Abs(cwd)
	if err != nil {
		return "", fmt.Errorf("resolve cwd: %w", err)
	}
	cwdReal, err := filepath.EvalSymlinks(cwdAbs)
	if err != nil {
		return "", fmt.Errorf("resolve cwd symlinks: %w", err)
	}

	targetAbs, err := filepath.Abs(filepath.Join(cwdAbs, clean))
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	if info, err := os.Lstat(targetAbs); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("symlink paths not allowed")
	}

	targetReal, err := filepath.EvalSymlinks(targetAbs)
	if err != nil {
		parent := filepath.Dir(targetAbs)
		parentReal, parentErr := filepath.EvalSymlinks(parent)
		if parentErr != nil {
			return "", fmt.Errorf("resolve parent symlinks: %w", parentErr)
		}
		targetReal = filepath.Join(parentReal, filepath.Base(targetAbs))
	}

	rel, err := filepath.Rel(cwdReal, targetReal)
	if err != nil {
		return "", fmt.Errorf("path outside working directory")
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes working directory")
	}

	return targetReal, nil
}
