//go:build linux

package core

import (
	"fmt"
	"os"
	"path/filepath"
)

func replaceExecutable(executablePath, stagedPath string) (bool, error) {
	if err := os.Rename(stagedPath, executablePath); err != nil {
		return false, fmt.Errorf("atomic executable replacement failed: %w", err)
	}
	directory, err := os.Open(filepath.Dir(executablePath))
	if err != nil {
		return true, fmt.Errorf("binary replaced but executable directory could not be opened for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return true, fmt.Errorf("binary replaced but executable directory sync failed: %w", err)
	}
	return true, nil
}
