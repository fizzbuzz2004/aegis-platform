//go:build windows

package core

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func secureConfigDirectory(path string) error {
	return setConfigACL(path, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
}

func secureConfigFile(file *os.File) error {
	return setConfigACL(file.Name(), "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)")
}

func setConfigACL(path, sddl string) error {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse ACL descriptor for %q: %w", path, err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read ACL descriptor for %q: %w", path, err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("apply ACL to %q: %w", path, err)
	}
	return nil
}
