//go:build windows

package core

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestConfigACLDescriptorsParse(t *testing.T) {
	descriptors := []struct {
		name string
		sddl string
	}{
		{name: "directory", sddl: "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"},
		{name: "file", sddl: "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)"},
	}
	for _, test := range descriptors {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatalf("SecurityDescriptorFromString() error = %v", err)
			}
			dacl, _, err := descriptor.DACL()
			if err != nil || dacl == nil {
				t.Fatalf("DACL() = (%v, error %v), want non-nil ACL", dacl, err)
			}
		})
	}
}
