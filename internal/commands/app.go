package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/hcsolakoglu/zcode-account-manager/internal/config"
	"github.com/hcsolakoglu/zcode-account-manager/internal/model"
	zprocess "github.com/hcsolakoglu/zcode-account-manager/internal/process"
	"github.com/hcsolakoglu/zcode-account-manager/internal/profile"
	"github.com/hcsolakoglu/zcode-account-manager/internal/transaction"
	"github.com/hcsolakoglu/zcode-account-manager/internal/zcode"
)

var Version = "0.1.0"

var (
	ErrZCodeRunning     = errors.New("ZCode is currently running")
	ErrUnmanagedState   = errors.New("live account is not stored; save it before switching")
	ErrLoggedOut        = errors.New("ZCode is not currently authenticated")
	ErrDoctorUnhealthy  = errors.New("doctor found errors")
	ErrSharedStateOwner = errors.New("shared ZCode state is owned by the bundled CLI")
)

type App struct {
	Config    config.Config
	Adapter   zcode.Adapter
	Store     *profile.Store
	Engine    *transaction.Engine
	Backups   *transaction.BackupStore
	Processes zprocess.Manager
	Out       io.Writer
	ErrOut    io.Writer
	Now       func() time.Time

	Detect   func() ([]zprocess.Info, error)
	Stop     func(context.Context, zprocess.Info, zprocess.StopOptions) error
	Start    func(zprocess.StartOptions) (*os.Process, error)
	WaitAuth func(context.Context, zcode.WatchOptions) (model.SessionBundle, error)
}

// Options is the dependency-injection surface used by integration tests and
// embedders.  A zero value uses the production filesystem, Secret Service
// key provider, process scanner, and ZCode adapter derived from Config.
// Supplying Store, Engine, or Backups avoids touching a real keyring; tests
// should normally provide a profile.Store backed by a StaticKeyProvider.
type Options struct {
	Config config.Config
	Keys   profile.KeyProvider

	Adapter   zcode.Adapter
	Store     *profile.Store
	Engine    *transaction.Engine
	Backups   *transaction.BackupStore
	Processes zprocess.Manager

	Out    io.Writer
	ErrOut io.Writer
	Now    func() time.Time

	Detect   func() ([]zprocess.Info, error)
	Stop     func(context.Context, zprocess.Info, zprocess.StopOptions) error
	Start    func(zprocess.StartOptions) (*os.Process, error)
	WaitAuth func(context.Context, zcode.WatchOptions) (model.SessionBundle, error)
}

func New(cfg config.Config, keys profile.KeyProvider, out, errOut io.Writer) (*App, error) {
	return NewWithOptions(Options{Config: cfg, Keys: keys, Out: out, ErrOut: errOut})
}

// NewWithOptions creates an App while keeping construction side-effect free
// with respect to live ZCode state.  In particular, the Secret Service key is
// first requested only from a command running under the outer auth lock.
func NewWithOptions(options Options) (*App, error) {
	cfg := options.Config
	if cfg.DataDir == "" || cfg.ZCodeStateDir == "" || cfg.ZCodeExecutable == "" {
		defaults, err := config.Defaults()
		if err != nil {
			return nil, err
		}
		if cfg.DataDir == "" {
			cfg.DataDir = defaults.DataDir
		}
		if cfg.ZCodeStateDir == "" {
			cfg.ZCodeStateDir = defaults.ZCodeStateDir
		}
		if cfg.ZCodeExecutable == "" {
			cfg.ZCodeExecutable = defaults.ZCodeExecutable
		}
		if cfg.ZCodeCLIExecutable == "" {
			cfg.ZCodeCLIExecutable = defaults.ZCodeCLIExecutable
		}
		if cfg.BackupLimit == 0 {
			cfg.BackupLimit = defaults.BackupLimit
		}
		if cfg.StopTimeoutSec == 0 {
			cfg.StopTimeoutSec = defaults.StopTimeoutSec
		}
		if cfg.LoginTimeoutSec == 0 {
			cfg.LoginTimeoutSec = defaults.LoginTimeoutSec
		}
	}
	if cfg.BackupLimit <= 0 {
		cfg.BackupLimit = 10
	}
	if cfg.StopTimeoutSec <= 0 {
		cfg.StopTimeoutSec = 10
	}
	if cfg.LoginTimeoutSec <= 0 {
		cfg.LoginTimeoutSec = 300
	}
	if cfg.ZCodeCLIExecutable == "" {
		if defaults, defaultsErr := config.Defaults(); defaultsErr == nil {
			cfg.ZCodeCLIExecutable = defaults.ZCodeCLIExecutable
		}
	}
	if err := config.Validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	if options.Out == nil {
		options.Out = io.Discard
	}
	if options.ErrOut == nil {
		options.ErrOut = io.Discard
	}
	store := options.Store
	var err error
	if store == nil {
		store, err = profile.NewStore(cfg.DataDir, options.Keys)
		if err != nil {
			return nil, fmt.Errorf("initialize profile store: %w", err)
		}
	}
	paths := zcode.PathsForStateDir(cfg.ZCodeStateDir).WithExecutable(cfg.ZCodeExecutable)
	paths = paths.WithCLIExecutable(cfg.ZCodeCLIExecutable)
	adapter := options.Adapter
	if adapter.Paths.CredentialsPath == "" {
		adapter = zcode.NewAdapter(paths)
	}
	engine := options.Engine
	if engine == nil {
		engine, err = transaction.NewEngine(transaction.StatePaths{
			Credentials: adapter.Paths.CredentialsPath,
			Telemetry:   adapter.Paths.TelemetryPath,
		}, transaction.TransactionOptions{
			// The App always owns auth.lock while invoking Engine.  Leaving
			// LockPath empty is intentional: acquiring it again here would
			// deadlock on Linux flock descriptors.
			JournalPath: filepath.Join(cfg.DataDir, "live-state.journal"),
			Seal: func(data []byte) ([]byte, error) {
				return store.SealPayload("transaction-journal", data)
			},
			Open: func(data []byte) ([]byte, error) {
				return store.OpenPayload("transaction-journal", data)
			},
		})
		if err != nil {
			return nil, fmt.Errorf("initialize transaction engine: %w", err)
		}
	}
	backups := options.Backups
	if backups == nil {
		backups, err = transaction.NewBackupStore(filepath.Join(cfg.DataDir, "backups"), transaction.BackupStoreOptions{AutomaticLimit: cfg.BackupLimit})
		if err != nil {
			return nil, fmt.Errorf("initialize backup store: %w", err)
		}
	}
	manager := options.Processes
	if manager.Executable == "" {
		// Preserve an injected scanner (used by embedders and tests) while
		// filling only the production executable default.
		if manager.Scanner.ProcRoot == "" {
			manager = zprocess.NewMultiManager(cfg.ZCodeExecutable, cfg.ZCodeCLIExecutable)
		} else {
			manager.Executable = cfg.ZCodeExecutable
			if cfg.ZCodeCLIExecutable != "" {
				manager.Executables = []string{cfg.ZCodeExecutable, cfg.ZCodeCLIExecutable}
			}
		}
	}
	out := options.Out
	errOut := options.ErrOut
	now := options.Now
	if now == nil {
		now = time.Now
	}
	app := &App{
		Config: cfg, Adapter: adapter, Store: store, Engine: engine,
		Backups: backups, Processes: manager, Out: out, ErrOut: errOut,
		Now: now,
	}
	app.Detect = options.Detect
	if app.Detect == nil {
		app.Detect = manager.Detect
	}
	app.Stop = options.Stop
	if app.Stop == nil {
		app.Stop = manager.Stop
	}
	app.Start = options.Start
	if app.Start == nil {
		app.Start = manager.Start
	}
	app.WaitAuth = options.WaitAuth
	if app.WaitAuth == nil {
		app.WaitAuth = adapter.WaitForAuthenticated
	}
	return app, nil
}

func (a *App) lock(mode transaction.LockMode) (*transaction.Lock, error) {
	if a.Config.DataDir == "" {
		return nil, errors.New("profile data directory is unavailable")
	}
	if err := zcode.ValidateSensitiveDirectory(a.Config.DataDir, true); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(a.Config.DataDir, "auth.lock")
	if err := zcode.ValidateSensitivePath(lockPath, true); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(a.Config.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	if err := zcode.ValidateSensitiveDirectory(a.Config.DataDir, false); err != nil {
		return nil, err
	}
	// Validate the complete parent chain before chmod.  In particular, do not
	// chmod a symlinked data directory and only discover the substitution when
	// transaction.Acquire opens auth.lock.
	if err := zcode.ValidateSensitivePath(lockPath, true); err != nil {
		return nil, err
	}
	if err := os.Chmod(a.Config.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure data directory: %w", err)
	}
	if err := hardenCommandDirectory(a.Config.DataDir); err != nil {
		return nil, fmt.Errorf("secure data directory ACL: %w", err)
	}
	return transaction.Acquire(lockPath, mode)
}

// ensureLiveStateDir prepares the account-state parent for a first login.
// ZCode may not have created ~/.zcode/v2 yet; transaction.Engine intentionally
// refuses to invent parent directories during an atomic rename.
func (a *App) ensureLiveStateDir() error {
	dir := a.Adapter.Paths.StateDir
	if dir == "" {
		dir = filepath.Dir(a.Adapter.Paths.CredentialsPath)
	}
	if dir == "" {
		return errors.New("ZCode state directory is unavailable")
	}
	if err := zcode.ValidateSensitiveDirectory(dir, true); err != nil {
		return err
	}
	for _, path := range []string{a.Adapter.Paths.CredentialsPath, a.Adapter.Paths.TelemetryPath} {
		if err := zcode.ValidateSensitivePath(path, true); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create ZCode state directory: %w", err)
	}
	if err := zcode.ValidateSensitiveDirectory(dir, false); err != nil {
		return err
	}
	for _, path := range []string{a.Adapter.Paths.CredentialsPath, a.Adapter.Paths.TelemetryPath} {
		if err := zcode.ValidateSensitivePath(path, true); err != nil {
			return err
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure ZCode state directory: %w", err)
	}
	if err := hardenCommandDirectory(dir); err != nil {
		return fmt.Errorf("secure ZCode state directory ACL: %w", err)
	}
	return nil
}

func (a *App) running() ([]zprocess.Info, error) {
	if a.Detect == nil {
		return nil, nil
	}
	return a.Detect()
}

func (a *App) requireStopped() error {
	if err := a.checkSharedStateLock(); err != nil {
		return err
	}
	running, err := a.running()
	if err != nil {
		return fmt.Errorf("detect ZCode process: %w", err)
	}
	if len(running) != 0 {
		return ErrZCodeRunning
	}
	return nil
}

func (a *App) checkSharedStateLock() error {
	if err := zcode.CheckSharedStateLock(a.Adapter.Paths); err != nil {
		return fmt.Errorf("shared ZCode state is busy or unverifiable: %w", err)
	}
	return nil
}

// startZCode transfers ownership of the launched child to the operating
// system. The CLI does not wait for the long-running desktop process, so it
// must release the os.Process handle after a successful start.
func (a *App) startZCode() error {
	if a.Start == nil {
		return errors.New("process start is unavailable")
	}
	process, err := a.Start(zprocess.StartOptions{})
	if err != nil {
		return err
	}
	if process != nil && process.Pid > 0 {
		if err := process.Release(); err != nil {
			return fmt.Errorf("release ZCode process: %w", err)
		}
	}
	return nil
}

func (a *App) stopAll(ctx context.Context) (bool, error) {
	running, err := a.running()
	if err != nil {
		return false, fmt.Errorf("detect ZCode process: %w", err)
	}
	if len(running) == 0 {
		return false, nil
	}
	for _, process := range running {
		if process.Product == "cli" {
			return false, ErrSharedStateOwner
		}
	}
	stoppedAny := false
	for _, process := range running {
		if a.Stop == nil {
			return stoppedAny, errors.New("process stop is unavailable")
		}
		if err := a.Stop(ctx, process, zprocess.StopOptions{Timeout: time.Duration(a.Config.StopTimeoutSec) * time.Second}); err != nil {
			return stoppedAny, fmt.Errorf("stop ZCode process %d: %w", process.PID, err)
		}
		stoppedAny = true
	}
	remaining, err := a.running()
	if err != nil {
		return stoppedAny, fmt.Errorf("verify ZCode stopped: %w", err)
	}
	if len(remaining) != 0 {
		return stoppedAny, ErrZCodeRunning
	}
	return true, nil
}

func (a *App) profileForIdentity(identity model.Identity) (profile.Entry, bool, error) {
	entries, err := a.Store.List()
	if err != nil {
		return profile.Entry{}, false, err
	}
	for _, entry := range entries {
		if entry.Metadata.Provider == identity.Provider && entry.Metadata.AccountID == identity.AccountID {
			return entry, true, nil
		}
	}
	return profile.Entry{}, false, nil
}

func (a *App) readLiveOptional() (model.SessionBundle, bool, error) {
	bundle, err := a.Adapter.Read()
	if err == nil {
		return bundle, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return model.SessionBundle{}, false, err
	}
	// Adapter.Read requires credentials.json because that is the primary
	// document.  During logout and interrupted login it is possible for the
	// credentials file to be absent while telemetry-state.json still exists.
	// Read the two optional documents independently so telemetry is never
	// silently discarded from a backup or left behind by a recovery.
	if a.Adapter.Paths.CredentialsPath == "" || a.Adapter.Paths.TelemetryPath == "" {
		return model.SessionBundle{}, false, err
	}
	credentials, credentialsErr := zcode.ReadCredentials(a.Adapter.Paths.CredentialsPath)
	if credentialsErr != nil && !errors.Is(credentialsErr, os.ErrNotExist) {
		return model.SessionBundle{}, false, credentialsErr
	}
	telemetry, telemetryErr := zcode.ReadTelemetry(a.Adapter.Paths.TelemetryPath)
	if telemetryErr != nil && !errors.Is(telemetryErr, os.ErrNotExist) {
		return model.SessionBundle{}, false, telemetryErr
	}
	if errors.Is(credentialsErr, os.ErrNotExist) && errors.Is(telemetryErr, os.ErrNotExist) {
		return model.SessionBundle{}, false, nil
	}
	return model.SessionBundle{
		Credentials:      credentials,
		Telemetry:        telemetry,
		TelemetryPresent: telemetryErr == nil,
	}, true, nil
}

func (a *App) syncLive(requireManaged bool) (string, model.SessionBundle, bool, error) {
	bundle, present, err := a.readLiveOptional()
	if err != nil || !present {
		return "", bundle, present, err
	}
	if len(bundle.Credentials) == 0 {
		return "", bundle, true, ErrLoggedOut
	}
	authenticated, authErr := a.Adapter.Authenticated(bundle.Credentials)
	if authErr != nil || !authenticated {
		if authErr != nil {
			if errors.Is(authErr, zcode.ErrNotAuthenticated) || errors.Is(authErr, zcode.ErrIdentityNotFound) {
				return "", bundle, true, ErrLoggedOut
			}
			return "", model.SessionBundle{}, true, authErr
		}
		return "", model.SessionBundle{}, true, ErrLoggedOut
	}
	identity, err := a.Adapter.Identity(bundle.Credentials)
	if err != nil {
		return "", model.SessionBundle{}, true, err
	}
	entry, found, err := a.profileForIdentity(identity)
	if err != nil {
		return "", model.SessionBundle{}, true, err
	}
	if !found {
		if requireManaged {
			return "", model.SessionBundle{}, true, ErrUnmanagedState
		}
		return "", bundle, true, nil
	}
	if _, err := a.Store.SaveBundle(entry.Alias, identity, bundle); err != nil {
		return "", model.SessionBundle{}, true, err
	}
	return entry.Alias, bundle, true, nil
}

// validateProfileBundle re-runs the adapter's identity and authentication
// checks immediately before a restore/switch.  The encrypted profile store
// authenticates the envelope, but it intentionally does not know ZCode's
// credential schema or provider-specific authentication marker.
func (a *App) validateProfileBundle(item profile.Profile) error {
	if err := zcode.ValidateCredentials(item.Bundle.Credentials); err != nil {
		return fmt.Errorf("target profile credentials are invalid")
	}
	if item.Bundle.TelemetryPresent {
		if item.Bundle.Telemetry == nil || zcode.ValidateTelemetry(item.Bundle.Telemetry) != nil {
			return fmt.Errorf("target profile telemetry state is invalid")
		}
	}
	identity, err := a.Adapter.Identity(item.Bundle.Credentials)
	if err != nil {
		return fmt.Errorf("target profile identity validation failed")
	}
	if identity.Provider != item.Metadata.Provider || identity.AccountID != item.Metadata.AccountID {
		return fmt.Errorf("target profile identity validation failed")
	}
	authenticated, err := a.Adapter.Authenticated(item.Bundle.Credentials)
	if err != nil {
		return err
	}
	if !authenticated {
		return ErrLoggedOut
	}
	if !item.Bundle.TelemetryPresent && item.Bundle.Telemetry != nil {
		return fmt.Errorf("target profile telemetry state is invalid")
	}
	return nil
}
