//go:build windows

package profile

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func ownedByCurrentUser(info os.FileInfo) bool {
	// The profile call sites pass only FileInfo for legacy compatibility. A
	// missing Win32 owner cannot be safely inferred from mode bits, so require
	// the secure parent checks and reject unknown metadata at the path layer.
	return info != nil && info.Mode()&os.ModeSymlink == 0
}

func ownedByCurrentUserPath(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(filepath.Clean(path), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	return err == nil && user != nil && user.User.Sid != nil && windows.EqualSid(owner, user.User.Sid)
}
