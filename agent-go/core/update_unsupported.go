//go:build !linux

package core

import "fmt"

func replaceExecutable(_, _ string) (bool, error) {
	return false, fmt.Errorf("automatic executable replacement is supported only on Linux")
}
