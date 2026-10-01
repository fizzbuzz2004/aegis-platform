//go:build !windows

package core

import (
	"os"
)

func secureConfigDirectory(path string) error {
	return os.Chmod(path, 0700)
}

func secureConfigFile(file *os.File) error {
	return file.Chmod(0600)
}
