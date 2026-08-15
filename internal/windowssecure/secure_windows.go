//go:build windows

// Package windowssecure contains the small ACL operations shared by the
// Windows storage backends. Windows chmod mode bits are not a substitute for
// an ACL, so sensitive files and directories get an explicit owner-only DACL.
package windowssecure

import (
	"fmt"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IsOwnerOnly reports whether path is owned by the current user and has the
// protected single-ACE DACL installed by this package.
func IsOwnerOnly(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(filepath.Clean(path), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return false
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return false
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	return err == nil && user != nil && user.User.Sid != nil &&
		windows.EqualSid(owner, user.User.Sid) && windows.EqualSid(aceSID, user.User.Sid) &&
		ace.Mask&windows.GENERIC_ALL != 0
}

// ProtectFile replaces the file DACL with an owner-only ACL. The handle is
// opened with OPEN_REPARSE_POINT so a junction or other reparse point cannot
// redirect the operation to another file.
func ProtectFile(path string) error {
	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(filepath.Clean(path)),
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a reparse point", path)
	}
	return protectHandle(handle, windows.NO_INHERITANCE)
}

// ProtectDirectory applies an owner-only ACL to a directory and marks the
// owner ACE inheritable by descendants. The directory itself is opened with
// BACKUP_SEMANTICS and still refuses reparse points.
func ProtectDirectory(path string) error {
	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(filepath.Clean(path)),
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a reparse point", path)
	}
	return protectHandle(handle, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
}

func protectHandle(handle windows.Handle, inheritance uint32) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		if err == nil {
			err = fmt.Errorf("current token has no user SID")
		}
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, nil)
	if err != nil {
		return err
	}
	err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
	runtime.KeepAlive(user)
	return err
}
