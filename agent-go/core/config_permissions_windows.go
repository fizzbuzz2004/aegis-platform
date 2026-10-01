//go:build windows

package core

import (
	"os"

	"golang.org/x/sys/windows"
)

func secureConfigDirectory(path string) error {
	return setConfigACL(path, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)")
}

func secureConfigFile(file *os.File) error {
	return setConfigACL(file.Name(), "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)")
}

func setConfigACL(path, sddl string) error {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}
