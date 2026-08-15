//go:build windows

package zcode

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func validateOwner(info os.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: missing or reparse-point file", ErrUnsafeStatePath)
	}
	return nil
}

func validateOwnerPath(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("%w: cannot verify owner", ErrUnsafeStatePath)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%w: cannot verify owner", ErrUnsafeStatePath)
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("%w: cannot verify owner", ErrUnsafeStatePath)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !windows.EqualSid(owner, user.User.Sid) {
		return fmt.Errorf("%w: owner mismatch", ErrUnsafeStatePath)
	}
	return nil
}
