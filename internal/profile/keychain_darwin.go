//go:build darwin

package profile

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// KeychainKeyProvider uses macOS Security.framework through the `security`
// utility. Values are base64 so command-line output never carries raw key
// bytes; no filesystem fallback is permitted.
type KeychainKeyProvider struct{ Binary, Service, Account string }

var errKeychainItemNotFound = errors.New("keychain item not found")

func NewKeychainKeyProvider() *KeychainKeyProvider {
	return &KeychainKeyProvider{Binary: "/usr/bin/security", Service: "zcode-auth", Account: "master"}
}
func (p *KeychainKeyProvider) settings() (string, string, string) {
	b, s, a := "/usr/bin/security", "zcode-auth", "master"
	if p != nil {
		if p.Binary != "" {
			b = p.Binary
		}
		if p.Service != "" {
			s = p.Service
		}
		if p.Account != "" {
			a = p.Account
		}
	}
	return b, s, a
}
func (p *KeychainKeyProvider) ExistingKey(ctx context.Context) ([]byte, error) {
	key, err := p.lookup(ctx)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	return key, nil
}
func (p *KeychainKeyProvider) MasterKey(ctx context.Context) ([]byte, error) {
	key, err := p.lookup(ctx)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, errKeychainItemNotFound) {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	bounded, cancel := context.WithTimeout(ctx, secretToolTimeout)
	defer cancel()
	b, s, a := p.settings()
	raw := make([]byte, masterKeySize)
	if _, e := rand.Read(raw); e != nil {
		return nil, fmt.Errorf("generate profile encryption key: %w", e)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	defer clearBytes(raw)
	// Do not use -U: it can overwrite a key created by another process. If a
	// concurrent creator wins, read and use that winner instead.
	cmd := exec.CommandContext(bounded, b, "add-generic-password", "-a", a, "-s", s, "-w", encoded)
	if e := cmd.Run(); e != nil {
		if winner, lookupErr := p.lookup(bounded); lookupErr == nil {
			return winner, nil
		}
		return nil, ErrKeyUnavailable
	}
	return p.lookup(bounded)
}
func (p *KeychainKeyProvider) lookup(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	bounded, cancel := context.WithTimeout(ctx, secretToolTimeout)
	defer cancel()
	b, s, a := p.settings()
	cmd := exec.CommandContext(bounded, b, "find-generic-password", "-a", a, "-s", s, "-w")
	out, e := cmd.Output()
	if e != nil {
		var exitErr *exec.ExitError
		if errors.As(e, &exitErr) && exitErr.ExitCode() == 44 {
			return nil, errKeychainItemNotFound
		}
		return nil, ErrKeyUnavailable
	}
	trimmed := strings.TrimSpace(string(out))
	decoded, e := base64.StdEncoding.DecodeString(trimmed)
	if e != nil || len(decoded) != masterKeySize {
		return nil, ErrKeyUnavailable
	}
	return decoded, nil
}
