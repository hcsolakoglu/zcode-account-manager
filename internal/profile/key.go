package profile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

const masterKeySize = 32

const (
	secretToolTimeout    = 10 * time.Second
	secretToolOutputSize = 4 << 10
)

// KeyProvider supplies the key used to encrypt profile files. Implementations
// must return a 32-byte key and must not persist or log it themselves.
//
// Store uses the native platform provider by default. Tests and callers that
// already have a key should inject StaticKeyProvider (or their own
// implementation) instead of putting a key in configuration or a profile
// file.
type KeyProvider interface {
	MasterKey(context.Context) ([]byte, error)
}

// ExistingKeyProvider can check an already-initialized key without creating
// one. Doctor uses this interface so a diagnostic command never initializes a
// replacement key when Secret Service is empty or unavailable.
type ExistingKeyProvider interface {
	ExistingKey(context.Context) ([]byte, error)
}

// StaticKeyProvider is a dependency-injected key provider intended for tests
// and embedding applications that own secure key material. The key is copied
// on construction and on every lookup so callers cannot mutate provider state
// through the returned slice.
type StaticKeyProvider struct {
	key []byte
}

// NewStaticKeyProvider returns a provider for key. It rejects keys that are
// not exactly 32 bytes, which is the XChaCha20-Poly1305 key size.
func NewStaticKeyProvider(key []byte) (*StaticKeyProvider, error) {
	if len(key) != masterKeySize {
		return nil, ErrInvalidKey
	}
	return &StaticKeyProvider{key: append([]byte(nil), key...)}, nil
}

// NewTestKeyProvider creates a deterministic provider for tests. It is kept
// explicit in the API so production callers do not accidentally use a
// hard-coded key. The returned provider still copies the supplied key.
func NewTestKeyProvider(key []byte) (*StaticKeyProvider, error) {
	return NewStaticKeyProvider(key)
}

func (p *StaticKeyProvider) MasterKey(context.Context) ([]byte, error) {
	if p == nil || len(p.key) != masterKeySize {
		return nil, ErrInvalidKey
	}
	return append([]byte(nil), p.key...), nil
}

func (p *StaticKeyProvider) ExistingKey(ctx context.Context) ([]byte, error) {
	return p.MasterKey(ctx)
}

// SecretToolKeyProvider obtains the store key from GNOME Secret Service by
// invoking secret-tool. The value is stored as base64 so arbitrary random key
// bytes cannot be changed by line-oriented command I/O.
//
// The default lookup attributes are deliberately application-scoped and
// stable. A missing item is created lazily on first use.
type SecretToolKeyProvider struct {
	// Binary can override the command name for tests or distributions that
	// install secret-tool outside PATH. Empty means "secret-tool".
	Binary string
	// Application and Key are Secret Service attributes. Empty values use the
	// zcode-auth defaults.
	Application string
	Key         string
}

func NewSecretToolKeyProvider() *SecretToolKeyProvider {
	return &SecretToolKeyProvider{
		Binary:      "secret-tool",
		Application: "zcode-auth",
		Key:         "master",
	}
}

func (p *SecretToolKeyProvider) settings() (binary, application, key string) {
	binary = "secret-tool"
	application = "zcode-auth"
	key = "master"
	if p == nil {
		return
	}
	if p.Binary != "" {
		binary = p.Binary
	}
	if p.Application != "" {
		application = p.Application
	}
	if p.Key != "" {
		key = p.Key
	}
	return
}

// MasterKey looks up the existing item and creates one when Secret Service
// reports that no item exists. Command output is never included in returned
// errors because a misconfigured helper must not turn secret material into a
// diagnostic leak.
func (p *SecretToolKeyProvider) MasterKey(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	boundedCtx, cancel := context.WithTimeout(ctx, secretToolTimeout)
	defer cancel()
	ctx = boundedCtx
	binary, application, key := p.settings()
	lookup := exec.CommandContext(ctx, binary, "lookup", "application", application, "key", key)
	lookupOut, lookupErr := commandOutputLimited(lookup, secretToolOutputSize)
	if lookupErr == nil {
		decoded, err := decodeSecretToolValue(lookupOut)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// secret-tool uses exit status 1 for an absent item. Treating other
	// failures as "not found" would hide a broken Secret Service and can cause
	// multiple unrelated stores to be initialized unexpectedly.
	var exitErr *exec.ExitError
	if !errors.As(lookupErr, &exitErr) || exitErr.ExitCode() != 1 {
		return nil, ErrKeyUnavailable
	}

	keyBytes := make([]byte, masterKeySize)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		return nil, fmt.Errorf("generate profile encryption key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(keyBytes)
	defer clearBytes(keyBytes)

	store := exec.CommandContext(ctx, binary, "store", "--label=zcode-auth master key", "application", application, "key", key)
	store.Stdin = strings.NewReader(encoded + "\n")
	if err := store.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Another process may have won the first-use race and created the
		// item between our lookup and store calls.  Treat that case as a
		// successful lookup of the winner instead of surfacing a spurious
		// key-unavailable error.  The caller's outer auth lock normally
		// serializes this path, but the provider is also safe when used on
		// its own.
		winner := exec.CommandContext(ctx, binary, "lookup", "application", application, "key", key)
		winnerOut, winnerErr := commandOutputLimited(winner, secretToolOutputSize)
		if winnerErr == nil {
			decoded, decodeErr := decodeSecretToolValue(winnerOut)
			if decodeErr == nil {
				clearBytes(keyBytes)
				return decoded, nil
			}
		}
		return nil, ErrKeyUnavailable
	}

	// Verify the value after storing. This closes the first-use race where a
	// second process initializes or replaces the Secret Service item between
	// our lookup and store calls. Store callers should still hold the global
	// auth lock across Store construction and the first operation.
	verify := exec.CommandContext(ctx, binary, "lookup", "application", application, "key", key)
	verifiedOut, verifyErr := commandOutputLimited(verify, secretToolOutputSize)
	if verifyErr != nil {
		return nil, ErrKeyUnavailable
	}
	verified, verifyDecodeErr := decodeSecretToolValue(verifiedOut)
	if verifyDecodeErr != nil {
		return nil, ErrKeyUnavailable
	}
	if subtle.ConstantTimeCompare(verified, keyBytes) != 1 {
		// A concurrent creator can win after our store call.  Use the
		// authenticated value currently in Secret Service; returning an
		// error here would leave an otherwise healthy store unusable for the
		// losing initializer.
		if len(verified) != masterKeySize {
			clearBytes(verified)
			return nil, ErrKeyUnavailable
		}
		winner := append([]byte(nil), verified...)
		clearBytes(verified)
		return winner, nil
	}
	if len(verified) != masterKeySize {
		clearBytes(verified)
		return nil, ErrKeyUnavailable
	}
	clearBytes(verified)

	// Return a fresh copy because keyBytes is cleared before this method exits.
	return decodeSecretToolValue([]byte(encoded))
}

// ExistingKey performs lookup only. It never creates or replaces a Secret
// Service item and never includes helper output in an error.
func (p *SecretToolKeyProvider) ExistingKey(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	boundedCtx, cancel := context.WithTimeout(ctx, secretToolTimeout)
	defer cancel()
	binary, application, key := p.settings()
	lookup := exec.CommandContext(boundedCtx, binary, "lookup", "application", application, "key", key)
	out, err := commandOutputLimited(lookup, secretToolOutputSize)
	if err != nil {
		if boundedCtx.Err() != nil {
			return nil, boundedCtx.Err()
		}
		return nil, ErrKeyUnavailable
	}
	decoded, err := decodeSecretToolValue(out)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	return decoded, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit    int
	tooLarge bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		b.tooLarge = true
		return 0, errors.New("command output too large")
	}
	return b.Buffer.Write(p)
}

func commandOutputLimited(command *exec.Cmd, limit int) ([]byte, error) {
	var output limitedBuffer
	output.limit = limit
	command.Stdout = &output
	if err := command.Run(); err != nil || output.tooLarge {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("command output too large")
	}
	return output.Bytes(), nil
}

func decodeSecretToolValue(out []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, ErrKeyUnavailable
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		if len(decoded) != masterKeySize {
			return nil, ErrInvalidKey
		}
		return decoded, nil
	}
	// Accept an existing raw 32-byte Secret Service value for compatibility,
	// while still stripping only the conventional command-output newline.
	raw := out
	if len(raw) == masterKeySize+1 && raw[len(raw)-1] == '\n' {
		raw = raw[:masterKeySize]
	}
	if len(raw) != masterKeySize {
		return nil, ErrInvalidKey
	}
	return append([]byte(nil), raw...), nil
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
