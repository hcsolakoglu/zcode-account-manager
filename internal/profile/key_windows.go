//go:build windows

package profile

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPIKeyProvider stores only a user-scoped DPAPI ciphertext. The plaintext
// profile key never enters configuration or an unprotected file. DPAPI is
// bound to the Windows user profile, so copying this file to another account
// cannot decrypt it.
type DPAPIKeyProvider struct{ Path string }

func NewDPAPIKeyProvider() *DPAPIKeyProvider {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.Getenv("APPDATA")
	}
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, "AppData", "Local")
		}
	}
	if base == "" {
		return &DPAPIKeyProvider{}
	}
	return &DPAPIKeyProvider{Path: filepath.Join(base, "zcode-auth", "master.key.dpapi")}
}
func (p *DPAPIKeyProvider) ExistingKey(context.Context) ([]byte, error) { return p.read() }
func (p *DPAPIKeyProvider) MasterKey(context.Context) ([]byte, error) {
	if p == nil {
		p = NewDPAPIKeyProvider()
	}
	if key, err := p.read(); err == nil {
		return key, nil
	}
	path := p.Path
	if path == "" {
		path = NewDPAPIKeyProvider().Path
	}
	if path == "" {
		return nil, ErrKeyUnavailable
	}
	// Never replace an existing key after a read/decrypt/ACL failure. Doing so
	// would make every profile encrypted with that key unrecoverable.
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return nil, ErrKeyUnavailable
	}
	raw := make([]byte, masterKeySize)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	protected, err := dpapiProtect(raw)
	clearBytes(raw)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, ErrKeyUnavailable
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".master-*")
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(protected)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	if err = hardenProfileFile(tmpName); err != nil {
		return nil, ErrKeyUnavailable
	}
	if err = windows.MoveFileEx(windows.StringToUTF16Ptr(filepath.Clean(tmpName)), windows.StringToUTF16Ptr(filepath.Clean(path)), windows.MOVEFILE_WRITE_THROUGH); err != nil {
		// A concurrent creator may have won the no-replace rename race.
		if key, readErr := p.read(); readErr == nil {
			return key, nil
		}
		return nil, ErrKeyUnavailable
	}
	return p.read()
}
func (p *DPAPIKeyProvider) read() ([]byte, error) {
	if p == nil {
		p = NewDPAPIKeyProvider()
	}
	path := p.Path
	if path == "" {
		path = NewDPAPIKeyProvider().Path
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !privateFilePermissions(path, info) || profileDirectoryReparse(path) || validateProfilePathOwner(path) != nil {
		return nil, ErrKeyUnavailable
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	return dpapiUnprotect(data)
}
func dpapiProtect(input []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(input)), Data: &input[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
func dpapiUnprotect(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrKeyUnavailable
	}
	in := windows.DataBlob{Size: uint32(len(input)), Data: &input[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if out.Size != masterKeySize {
		return nil, ErrInvalidKey
	}
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
