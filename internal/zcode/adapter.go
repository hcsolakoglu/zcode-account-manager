package zcode

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"github.com/hcsolakoglu/zcode-auth/internal/model"
)

const (
	defaultWatchInterval = 250 * time.Millisecond
	defaultWatchTimeout  = 5 * time.Minute
)

var ErrWatchTimeout = errors.New("timed out waiting for authenticated zcode state")

// Adapter groups paths and the credential cipher so command code does not
// need to know ZCode's storage schema.  It never mutates live state unless a
// caller explicitly invokes one of the write/clear methods.
type Adapter struct {
	Paths  Paths
	Cipher CredentialCipher
}

// Capability describes exactly which products may share this adapter's
// state. The bundled CLI is a peer owner of the same state group; separate
// Z.ai API-key/configuration stores are intentionally outside this contract.
type Capability struct {
	StateGroup         string            `json:"state_group"`
	SchemaVersion      int               `json:"schema_version"`
	Products           []model.ProductID `json:"products"`
	RotatesTelemetry   bool              `json:"rotates_telemetry"`
	SafeDesktopRestart bool              `json:"safe_desktop_restart"`
	SafeCLIRestart     bool              `json:"safe_cli_restart"`
}

func (a Adapter) Capabilities() Capability {
	return Capability{
		StateGroup:         model.StateGroupID,
		SchemaVersion:      model.SchemaVersion,
		Products:           []model.ProductID{model.ProductDesktop, model.ProductCLI},
		RotatesTelemetry:   true,
		SafeDesktopRestart: true,
		SafeCLIRestart:     false,
	}
}

// NewAdapter creates an adapter for paths using ZCode-compatible key lookup.
func NewAdapter(paths Paths) Adapter {
	return Adapter{Paths: paths, Cipher: NewCredentialCipher()}
}

// Read returns the opaque credentials and telemetry pair.
func (a Adapter) Read() (model.SessionBundle, error) {
	return ReadState(a.Paths)
}

// Identity extracts stable account identity without returning credential
// values.  Decryption, when needed, occurs only in memory.
func (a Adapter) Identity(credentials []byte) (model.Identity, error) {
	return a.Cipher.IdentityFromCredentials(credentials)
}

// Authenticated validates both stable identity and an access/refresh/auth
// marker without exposing token data.
func (a Adapter) Authenticated(credentials []byte) (bool, error) {
	return a.Cipher.Authenticated(credentials)
}

// WatchOptions bounds login polling.  A zero value uses a conservative 250 ms
// interval and five-minute timeout.  A caller may provide a custom Cipher for
// deterministic tests or a controlled secret.
type WatchOptions struct {
	Interval time.Duration
	Timeout  time.Duration
	Cipher   CredentialCipher
}

// WaitForAuthenticated polls both state files until a valid authenticated
// credential document is observed.  Polling is deliberately bounded and
// context-cancellable; no filesystem watcher dependency is required for this
// small state file.
func (a Adapter) WaitForAuthenticated(ctx context.Context, options WatchOptions) (model.SessionBundle, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	interval := options.Interval
	if interval <= 0 {
		interval = defaultWatchInterval
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultWatchTimeout
	}
	cipher := options.Cipher
	if cipher.secret == "" {
		cipher = a.Cipher
		if cipher.secret == "" {
			cipher = NewCredentialCipher()
		}
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	try := func() (model.SessionBundle, bool, error) {
		state, err := ReadState(a.Paths)
		if err != nil {
			if retry, ok := retryableWatchError(err); ok && retry {
				return model.SessionBundle{}, false, nil
			}
			return model.SessionBundle{}, false, err
		}
		authenticated, err := cipher.Authenticated(state.Credentials)
		if err != nil {
			if retry, ok := retryableWatchError(err); ok && retry {
				return model.SessionBundle{}, false, nil
			}
			return model.SessionBundle{}, false, err
		}
		if !authenticated {
			return model.SessionBundle{}, false, nil
		}
		return state, true, nil
	}

	var candidate *model.SessionBundle
	observe := func() (model.SessionBundle, bool, error) {
		state, ready, err := try()
		if err != nil {
			return model.SessionBundle{}, false, err
		}
		if !ready {
			candidate = nil
			return model.SessionBundle{}, false, nil
		}
		if candidate != nil && bundlesEqual(*candidate, state) {
			return state, true, nil
		}
		copy := model.SessionBundle{
			Credentials:      append([]byte(nil), state.Credentials...),
			Telemetry:        append([]byte(nil), state.Telemetry...),
			TelemetryPresent: state.TelemetryPresent,
		}
		candidate = &copy
		return model.SessionBundle{}, false, nil
	}

	if state, ready, err := observe(); err != nil {
		return model.SessionBundle{}, err
	} else if ready {
		return state, nil
	}
	for {
		select {
		case <-ctx.Done():
			return model.SessionBundle{}, ctx.Err()
		case <-deadline.C:
			return model.SessionBundle{}, ErrWatchTimeout
		case <-ticker.C:
			if state, ready, err := observe(); err != nil {
				return model.SessionBundle{}, err
			} else if ready {
				return state, nil
			}
		}
	}
}

func bundlesEqual(left, right model.SessionBundle) bool {
	return left.TelemetryPresent == right.TelemetryPresent &&
		bytes.Equal(left.Credentials, right.Credentials) &&
		bytes.Equal(left.Telemetry, right.Telemetry)
}

// WaitForAuthenticated is the package-level convenience form.
func WaitForAuthenticated(ctx context.Context, paths Paths, options WatchOptions) (model.SessionBundle, error) {
	return NewAdapter(paths).WaitForAuthenticated(ctx, options)
}

func retryableWatchError(err error) (bool, bool) {
	if err == nil {
		return false, false
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrInvalidState) ||
		errors.Is(err, ErrIdentityNotFound) || errors.Is(err, ErrNotAuthenticated) ||
		errors.Is(err, ErrCredentialDecrypt) {
		return true, true
	}
	return false, false
}
