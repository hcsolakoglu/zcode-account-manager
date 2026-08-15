//go:build windows

package config

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Windows has no uid field. Compare the file owner SID with the current token
// and reject reparse points; this keeps config discovery fail-closed.
func configFileOwnerSafe(path string, info os.FileInfo) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
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
