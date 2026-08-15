package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/hcsolakoglu/zcode-account-manager/internal/model"
	"github.com/hcsolakoglu/zcode-account-manager/internal/profile"
	"github.com/hcsolakoglu/zcode-account-manager/internal/transaction"
	"github.com/hcsolakoglu/zcode-account-manager/internal/zcode"
)

type listItem struct {
	Alias        string    `json:"alias"`
	Provider     string    `json:"provider"`
	Active       bool      `json:"active"`
	HasTelemetry bool      `json:"has_telemetry"`
	LastSynced   time.Time `json:"last_synced_at"`
}

func (a *App) List(jsonOutput bool) error {
	// A pending coordinator journal means the registry and live state may not
	// describe the same account.  Recover it before presenting a snapshot so a
	// read command cannot report a half-completed switch.  The recovery path is
	// intentionally serialized with writers.
	lock, err := a.lock(transaction.Exclusive)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := a.recoverCoordinator(); err != nil {
		return err
	}
	entries, err := a.Store.List()
	if err != nil {
		return err
	}
	registry, err := a.Store.Registry()
	if err != nil {
		return err
	}
	items := make([]listItem, 0, len(entries))
	for _, entry := range entries {
		items = append(items, listItem{Alias: entry.Alias, Provider: entry.Metadata.Provider, Active: entry.Alias == registry.ActiveProfile, HasTelemetry: entry.Metadata.HasTelemetry, LastSynced: entry.Metadata.LastSynced})
	}
	if jsonOutput {
		return writeJSON(a.Out, items)
	}
	if len(items) == 0 {
		_, err = fmt.Fprintln(a.Out, "No profiles saved.")
		return err
	}
	for _, item := range items {
		marker := " "
		if item.Active {
			marker = "*"
		}
		if _, err := fmt.Fprintf(a.Out, "%s %s\t%s\n", marker, item.Alias, item.Provider); err != nil {
			return err
		}
	}
	return nil
}

type currentOutput struct {
	Authenticated bool   `json:"authenticated"`
	Alias         string `json:"alias,omitempty"`
	Provider      string `json:"provider,omitempty"`
	Managed       bool   `json:"managed"`
	HasTelemetry  bool   `json:"has_telemetry"`
}

func (a *App) Current(jsonOutput bool) error {
	lock, err := a.lock(transaction.Exclusive)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := a.recoverCoordinator(); err != nil {
		return err
	}
	bundle, present, err := a.readLiveOptional()
	if err != nil {
		return err
	}
	result := currentOutput{}
	if present && len(bundle.Credentials) != 0 {
		authenticated, authErr := a.Adapter.Authenticated(bundle.Credentials)
		if errors.Is(authErr, zcode.ErrNotAuthenticated) || errors.Is(authErr, zcode.ErrIdentityNotFound) {
			result.HasTelemetry = bundle.TelemetryPresent
			if jsonOutput {
				return writeJSON(a.Out, result)
			}
			_, err = fmt.Fprintln(a.Out, "logged out")
			return err
		}
		if authErr != nil {
			return authErr
		}
		identity, identityErr := a.Adapter.Identity(bundle.Credentials)
		if identityErr != nil {
			return identityErr
		}
		entry, found, findErr := a.profileForIdentity(identity)
		if findErr != nil {
			return findErr
		}
		result.Authenticated = authenticated
		result.Provider = identity.Provider
		result.Managed = found
		result.HasTelemetry = bundle.TelemetryPresent
		if found {
			result.Alias = entry.Alias
		}
	}
	if jsonOutput {
		return writeJSON(a.Out, result)
	}
	if !result.Authenticated {
		_, err = fmt.Fprintln(a.Out, "logged out")
	} else if result.Managed {
		_, err = fmt.Fprintf(a.Out, "%s (%s)\n", result.Alias, result.Provider)
	} else {
		_, err = fmt.Fprintf(a.Out, "unmanaged (%s)\n", result.Provider)
	}
	return err
}

func (a *App) Save(alias string, addOnly bool) error {
	lock, err := a.lock(transaction.Exclusive)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := a.recoverCoordinator(); err != nil {
		return err
	}
	if err := a.requireStopped(); err != nil {
		return err
	}
	if addOnly {
		if _, err := a.Store.Load(alias); err == nil {
			return fmt.Errorf("profile %q already exists", alias)
		} else if !errors.Is(err, profile.ErrNotFound) {
			return err
		}
	}
	bundle, present, err := a.readLiveOptional()
	if err != nil {
		return err
	}
	if !present || len(bundle.Credentials) == 0 {
		return ErrLoggedOut
	}
	authenticated, authErr := a.Adapter.Authenticated(bundle.Credentials)
	if authErr != nil {
		if errors.Is(authErr, zcode.ErrNotAuthenticated) || errors.Is(authErr, zcode.ErrIdentityNotFound) {
			return ErrLoggedOut
		}
		return authErr
	}
	if !authenticated {
		return ErrLoggedOut
	}
	identity, err := a.Adapter.Identity(bundle.Credentials)
	if err != nil {
		return err
	}
	if _, err := a.Store.SaveBundle(alias, identity, bundle); err != nil {
		return err
	}
	if err := a.Store.SetActive(alias); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.Out, "Saved profile %s.\n", alias)
	return err
}

func (a *App) Switch(ctx context.Context, alias string, restart bool) (retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	lock, err := a.lock(transaction.Exclusive)
	if err != nil {
		return err
	}
	restartNeeded := false
	restartAttempted := false
	defer func() {
		// A restart-mode switch owns the responsibility for putting the
		// desktop back after any failure that occurs after SIGTERM (for
		// example, an unmanaged live account or a backup write failure).
		// Check once more before starting so a process that survived the stop
		// timeout is never duplicated.
		if restartNeeded && !restartAttempted {
			if running, detectErr := a.running(); detectErr == nil && len(running) == 0 {
				restartAttempted = true
				if startErr := a.startZCode(); startErr != nil {
					retErr = errors.Join(retErr, fmt.Errorf("restart ZCode after failed switch: %w", startErr))
				}
			}
		}
		_ = lock.Close()
	}()
	if err := a.recoverCoordinator(); err != nil {
		return err
	}
	if err := a.checkSharedStateLock(); err != nil {
		return err
	}
	registry, err := a.Store.Registry()
	if err != nil {
		return err
	}
	if alias == "-" {
		alias = registry.PreviousProfile
		if alias == "" {
			return fmt.Errorf("no previous profile")
		}
	}
	running, err := a.running()
	if err != nil {
		return err
	}
	if len(running) != 0 && !restart {
		return ErrZCodeRunning
	}
	// Resolve and decrypt the target before stopping ZCode.  A typo or a
	// corrupt target must never leave a running desktop process stopped.
	preTarget, err := a.Store.Load(alias)
	if err != nil {
		return err
	}
	if err := a.validateProfileBundle(preTarget); err != nil {
		return err
	}
	if len(running) != 0 {
		restartNeeded, err = a.stopAll(ctx)
		if err != nil {
			return err
		}
	}
	// The process can be relaunched by another actor after stopAll's final
	// observation.  Recheck immediately before touching either live document.
	if err := a.requireStopped(); err != nil {
		return err
	}
	currentAlias, oldBundle, oldPresent, err := a.syncLive(true)
	if err != nil {
		return err
	}
	// Synchronization may have refreshed the target profile.  Load it only
	// after the live account has been captured so A -> A never restores stale
	// credentials or telemetry.
	target, err := a.Store.Load(alias)
	if err != nil {
		return err
	}
	if err := a.validateProfileBundle(target); err != nil {
		return err
	}
	backup, err := a.createBackup(transaction.Automatic, "before switch", currentAlias, oldBundle, oldPresent)
	if err != nil {
		return err
	}
	if err := a.requireStopped(); err != nil {
		return err
	}
	if err := a.applyCoordinated("switch", alias, target.Bundle, backup.ID); err != nil {
		return err
	}
	if restartNeeded {
		if err := ctx.Err(); err != nil {
			return err
		}
		restartAttempted = true
		if err := a.startZCode(); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(a.Out, "Switched to %s.\n", alias)
	return err
}

func (a *App) Remove(alias string) error {
	lock, err := a.lock(transaction.Exclusive)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := a.recoverCoordinator(); err != nil {
		return err
	}
	registry, err := a.Store.Registry()
	if err != nil {
		return err
	}
	if registry.ActiveProfile == alias {
		return fmt.Errorf("cannot remove the active profile")
	}
	if err := a.Store.Remove(alias); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.Out, "Removed profile %s.\n", alias)
	return err
}

func (a *App) Logout() error {
	lock, err := a.lock(transaction.Exclusive)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := a.recoverCoordinator(); err != nil {
		return err
	}
	if err := a.requireStopped(); err != nil {
		return err
	}
	// Logout can safely clear an unmanaged account because the exact live
	// bundle is captured in an encrypted automatic backup first.  Refusing here
	// would strand a user's only recovery path when the registry is stale.
	alias, bundle, present, err := a.syncLive(false)
	if errors.Is(err, ErrLoggedOut) {
		// Empty/partial ZCode stores are still safe to clear, but there is no
		// account identity to synchronize into a profile.
		bundle, present, err = a.readLiveOptional()
		alias = ""
	}
	if err != nil {
		return err
	}
	backup, err := a.createBackup(transaction.Automatic, "before logout", alias, bundle, present)
	if err != nil {
		return err
	}
	if err := a.requireStopped(); err != nil {
		return err
	}
	if err := a.applyCoordinated("logout", "", model.SessionBundle{}, backup.ID); err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.Out, "Logged out; saved profiles were preserved.")
	return err
}

func (a *App) Backup() error {
	lock, err := a.lock(transaction.Exclusive)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := a.recoverCoordinator(); err != nil {
		return err
	}
	if err := a.requireStopped(); err != nil {
		return err
	}
	bundle, present, err := a.readLiveOptional()
	if err != nil {
		return err
	}
	alias := ""
	if present {
		if identity, identityErr := a.Adapter.Identity(bundle.Credentials); identityErr == nil {
			if entry, found, findErr := a.profileForIdentity(identity); findErr == nil && found {
				alias = entry.Alias
			}
		}
	}
	backup, err := a.createBackup(transaction.Manual, "manual snapshot", alias, bundle, present)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.Out, backup.ID)
	return err
}

func (a *App) ListBackups(jsonOutput bool) error {
	lock, err := a.lock(transaction.Exclusive)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := a.recoverCoordinator(); err != nil {
		return err
	}
	backups, err := a.Backups.List()
	if err != nil {
		return err
	}
	if jsonOutput {
		type safeBackup struct {
			ID        string                 `json:"id"`
			Kind      transaction.BackupKind `json:"kind"`
			CreatedAt time.Time              `json:"created_at"`
			Profile   string                 `json:"profile,omitempty"`
		}
		items := make([]safeBackup, 0, len(backups))
		for _, backup := range backups {
			items = append(items, safeBackup{backup.ID, backup.Kind, backup.Metadata.CreatedAt, backup.Metadata.ProfileAlias})
		}
		return writeJSON(a.Out, items)
	}
	for _, backup := range backups {
		if _, err := fmt.Fprintf(a.Out, "%s\t%s\t%s\t%s\n", backup.ID, backup.Kind, backup.Metadata.CreatedAt.Format(time.RFC3339), backup.Metadata.ProfileAlias); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) Restore(id string) error {
	lock, err := a.lock(transaction.Exclusive)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := a.recoverCoordinator(); err != nil {
		return err
	}
	if err := a.requireStopped(); err != nil {
		return err
	}
	target, targetPresent, _, err := a.restoreBackupID(id)
	if err != nil {
		return err
	}
	newActive := ""
	if targetPresent {
		identity, err := a.Adapter.Identity(target.Credentials)
		if err != nil {
			return err
		}
		authenticated, authErr := a.Adapter.Authenticated(target.Credentials)
		if authErr != nil || !authenticated {
			if authErr != nil {
				return authErr
			}
			return ErrLoggedOut
		}
		entry, found, err := a.profileForIdentity(identity)
		if err != nil {
			return err
		}
		if found {
			newActive = entry.Alias
		}
	}
	oldAlias, oldBundle, oldPresent, err := a.syncLive(false)
	if errors.Is(err, ErrLoggedOut) {
		// Restoring a logout/telemetry-only snapshot is valid even when the
		// current live credentials are already absent.  Preserve any remaining
		// telemetry in the rollback backup before applying the requested state.
		oldBundle, oldPresent, err = a.readLiveOptional()
		oldAlias = ""
	}
	if err != nil {
		return err
	}
	rollback, err := a.createBackup(transaction.Automatic, "before restore", oldAlias, oldBundle, oldPresent)
	if err != nil {
		return err
	}
	if err := a.requireStopped(); err != nil {
		return err
	}
	if err := a.applyCoordinated("restore", newActive, target, rollback.ID); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.Out, "Restored backup %s.\n", id)
	return err
}

func (a *App) Login(ctx context.Context, alias string) error {
	lock, err := a.lock(transaction.Exclusive)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := a.recoverCoordinator(); err != nil {
		return err
	}
	if err := a.requireStopped(); err != nil {
		return err
	}
	if _, err := a.Store.Load(alias); err == nil {
		return fmt.Errorf("profile %q already exists; login collision refused", alias)
	} else if !errors.Is(err, profile.ErrNotFound) {
		return err
	}
	oldAlias, oldBundle, oldPresent, err := a.syncLive(true)
	if errors.Is(err, ErrLoggedOut) {
		oldBundle, oldPresent, err = a.readLiveOptional()
		oldAlias = ""
	}
	if err != nil {
		return err
	}
	backup, err := a.createBackup(transaction.Automatic, "before login", oldAlias, oldBundle, oldPresent)
	if err != nil {
		return err
	}
	record, err := a.beginCoordinatorWithTarget("login", alias, backup.ID, true)
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		// Restore from the durable encrypted backup, not from an in-memory
		// copy.  This is the same recovery path used after process death.
		if rollbackErr := a.rollbackCoordinator(record); rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("login rollback failed: %w", rollbackErr))
		}
		return cause
	}
	if err := a.ensureLiveStateDir(); err != nil {
		return rollback(err)
	}
	if err := a.Engine.Apply(model.SessionBundle{}); err != nil {
		return rollback(err)
	}
	if err := a.markCoordinatorLive(record); err != nil {
		return rollback(err)
	}
	if err := a.startZCode(); err != nil {
		return rollback(err)
	}
	if a.WaitAuth == nil {
		return rollback(errors.New("authentication watcher is unavailable"))
	}
	bundle, err := a.WaitAuth(ctx, zcode.WatchOptions{Timeout: time.Duration(a.Config.LoginTimeoutSec) * time.Second})
	if err != nil {
		return rollback(err)
	}
	if err := zcode.ValidateCredentials(bundle.Credentials); err != nil {
		return rollback(fmt.Errorf("captured login credentials are invalid"))
	}
	identity, err := a.Adapter.Identity(bundle.Credentials)
	if err != nil {
		return rollback(err)
	}
	authenticated, authErr := a.Adapter.Authenticated(bundle.Credentials)
	if authErr != nil {
		return rollback(authErr)
	}
	if !authenticated {
		return rollback(ErrLoggedOut)
	}
	if bundle.Telemetry == nil {
		bundle.TelemetryPresent = false
	}
	if bundle.TelemetryPresent {
		if err := zcode.ValidateTelemetry(bundle.Telemetry); err != nil {
			return rollback(fmt.Errorf("captured login telemetry is invalid"))
		}
	}
	// The watcher must return a stable pair read from the live files. Never
	// rewrite those files while the desktop process is running; verify the
	// injected/production watcher contract before persisting the profile.
	live, livePresent, err := a.readLiveOptional()
	if err != nil || !livePresent || live.TelemetryPresent != bundle.TelemetryPresent ||
		!bytes.Equal(live.Credentials, bundle.Credentials) || !bytes.Equal(live.Telemetry, bundle.Telemetry) {
		if err == nil {
			err = errors.New("authenticated ZCode state changed during capture")
		}
		return rollback(err)
	}
	if existing, found, findErr := a.profileForIdentity(identity); findErr != nil {
		return rollback(findErr)
	} else if found {
		return rollback(fmt.Errorf("account is already stored as profile %q", existing.Alias))
	}
	if _, err := a.Store.SaveBundle(alias, identity, bundle); err != nil {
		return rollback(err)
	}
	if err := a.Store.SetActivePair(alias, record.NewPrevious); err != nil {
		return rollback(err)
	}
	setCoordinatorTarget(&record, bundle)
	if err := writeCoordinator(a.coordinatorPath(), record); err != nil {
		return rollback(err)
	}
	if err := a.finishCoordinator(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.Out, "Captured login as %s.\n", alias)
	return err
}

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func (a *App) Doctor(repair, jsonOutput bool) error {
	// Recovery may have to rewrite both live documents and the registry even
	// for a read-only doctor invocation.  Take the exclusive lock for the
	// complete inspection so no command can observe the coordinator half-way
	// through repair.
	lock, err := a.lock(transaction.Exclusive)
	if err != nil {
		return err
	}
	defer lock.Close()
	initialRunning, detectErr := a.running()
	if repair && detectErr != nil {
		return fmt.Errorf("cannot verify ZCode is stopped: %w", detectErr)
	}
	if repair && len(initialRunning) != 0 {
		return fmt.Errorf("cannot repair while ZCode is running")
	}
	if repair {
		// Permission repair and temporary-file cleanup can touch the shared
		// state directory. A clean process scan is not enough when ZCode's
		// own telemetry lock is held by an owner the process scanner cannot
		// identify, so fail closed before any repair write.
		if err := a.checkSharedStateLock(); err != nil {
			return fmt.Errorf("cannot repair while shared ZCode state is owned: %w", err)
		}
	}
	pending := make([]string, 0, 3)
	for name, path := range map[string]string{
		"coordinator": a.coordinatorPath(),
		"live state":  a.Engine.JournalPath(),
		"profile":     filepath.Join(a.Config.DataDir, "profile.journal"),
	} {
		if _, statErr := os.Lstat(path); statErr == nil {
			pending = append(pending, name)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("inspect %s journal: %w", name, statErr)
		}
	}
	sort.Strings(pending)
	if repair {
		if err := a.repairPermissions(); err != nil {
			return err
		}
		if err := a.cleanupTemporaryFiles(); err != nil {
			return err
		}
		for _, path := range []string{a.Adapter.Paths.CredentialsPath, a.Adapter.Paths.TelemetryPath} {
			if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() {
				if chmodErr := repairCommandPath(path, info); chmodErr != nil {
					return chmodErr
				}
			}
		}
		if err := a.recoverCoordinator(); err != nil {
			return err
		}
	}
	checks := make([]doctorCheck, 0, 12)
	add := func(name, status, detail string) {
		checks = append(checks, doctorCheck{Name: name, Status: status, Detail: detail})
	}
	if _, err := os.Stat(a.Config.ZCodeExecutable); err == nil {
		add("ZCode installation", "OK", a.Config.ZCodeExecutable)
	} else {
		add("ZCode installation", "ERROR", "not found")
	}
	if a.Config.ZCodeCLIExecutable != "" {
		if _, err := os.Stat(a.Config.ZCodeCLIExecutable); err == nil {
			add("Bundled CLI installation", "OK", a.Config.ZCodeCLIExecutable)
		} else {
			add("Bundled CLI installation", "WARN", "not found; shared-owner detection remains fail-closed")
		}
	}
	if version, err := a.detectVersion(); err == nil {
		add("ZCode version", "OK", version)
	} else {
		add("ZCode version", "WARN", "unavailable")
	}
	add("Platform", "OK", runtime.GOOS+"/"+runtime.GOARCH)
	add("Lock", "OK", "exclusive lock acquired")
	if len(pending) == 0 {
		add("Interrupted transaction", "OK", "none")
	} else if repair {
		add("Interrupted transaction", "OK", "recovered")
	} else {
		add("Interrupted transaction", "WARN", strings.Join(pending, ", ")+"; run doctor --repair")
	}
	running, detectErr := a.running()
	if detectErr != nil {
		add("ZCode process", "ERROR", "detection failed")
	} else if len(running) == 0 {
		add("ZCode process", "OK", "stopped")
	} else {
		cliOwner := false
		for _, process := range running {
			if process.Product == "cli" {
				cliOwner = true
				break
			}
		}
		if cliOwner {
			add("ZCode process", "WARN", "bundled CLI running; mutation refused")
		} else {
			add("ZCode process", "WARN", "running")
		}
	}
	// Diagnostic key lookup is explicitly non-creating for production Secret
	// Service providers, so plain doctor cannot initialize security state.
	if keyErr := a.Store.CheckKey(context.Background()); keyErr != nil {
		add("Encryption key", "ERROR", "unavailable")
	} else {
		add("Encryption key", "OK", "available")
	}
	if bundle, present, readErr := a.readLiveOptional(); readErr == nil && present {
		if len(bundle.Credentials) == 0 {
			add("Credential file", "OK", "logged out")
			add("Active account", "OK", "logged out")
		} else if authenticated, authErr := a.Adapter.Authenticated(bundle.Credentials); authErr != nil {
			if errors.Is(authErr, zcode.ErrNotAuthenticated) || errors.Is(authErr, zcode.ErrIdentityNotFound) {
				add("Credential file", "OK", "logged out")
				add("Active account", "OK", "logged out")
			} else {
				add("Credential file", "ERROR", "invalid or unsafe")
				add("Active account", "ERROR", "unavailable")
			}
		} else if authenticated {
			add("Credential file", "OK", "authenticated")
			identity, identityErr := a.Adapter.Identity(bundle.Credentials)
			if identityErr != nil {
				add("Active account", "ERROR", "unavailable")
			} else if entry, found, findErr := a.profileForIdentity(identity); findErr != nil {
				add("Active account", "ERROR", "profile lookup failed")
			} else if found {
				add("Active account", "OK", entry.Alias)
			} else {
				add("Active account", "WARN", "unmanaged")
			}
		} else {
			add("Credential file", "OK", "logged out")
			add("Active account", "OK", "logged out")
		}
		if bundle.TelemetryPresent {
			add("Telemetry state", "OK", "present")
		} else {
			add("Telemetry state", "OK", "absent")
		}
	} else if readErr != nil {
		add("Credential file", "ERROR", "invalid or unsafe")
		add("Active account", "ERROR", "unavailable")
	} else {
		add("Credential file", "OK", "logged out")
		add("Active account", "OK", "logged out")
	}
	profileJournalPending := false
	for _, name := range pending {
		profileJournalPending = profileJournalPending || name == "profile"
	}
	if profileJournalPending && !repair {
		add("Registry", "WARN", "inspection deferred until repair")
	} else if _, registryErr := a.Store.Registry(); registryErr != nil {
		add("Registry", "ERROR", "invalid")
	} else {
		add("Registry", "OK", "valid")
	}
	var entries []profile.Entry
	var listErr error
	if profileJournalPending && !repair {
		listErr = errors.New("profile recovery pending")
	} else {
		entries, listErr = a.Store.List()
	}
	if listErr == nil {
		for _, entry := range entries {
			if _, loadErr := a.Store.Load(entry.Alias); loadErr != nil {
				listErr = loadErr
				break
			}
		}
	}
	if profileJournalPending && !repair {
		add("Profile store", "WARN", "inspection deferred until repair")
		add("Profiles", "WARN", "unavailable until repair")
	} else if listErr != nil {
		add("Profile store", "ERROR", "invalid")
		add("Profiles", "ERROR", "unavailable")
	} else {
		add("Profile store", "OK", "valid")
		add("Profiles", "OK", fmt.Sprintf("%d", len(entries)))
	}
	backups, backupErr := a.Backups.List()
	if backupErr != nil {
		add("Backups", "ERROR", "invalid")
	} else {
		add("Backups", "OK", fmt.Sprintf("%d backups", len(backups)))
	}
	for _, path := range []string{a.Config.DataDir, a.Adapter.Paths.CredentialsPath, a.Adapter.Paths.TelemetryPath} {
		if info, statErr := os.Lstat(path); statErr == nil {
			want := os.FileMode(0o600)
			if info.IsDir() {
				want = 0o700
			}
			if !commandPathSecure(path, info) {
				add("Permissions "+filepath.Base(path), "WARN", fmt.Sprintf("access is broader than owner-only (expected %04o equivalent)", want))
			}
		}
	}
	sort.SliceStable(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })
	unhealthy := false
	for _, check := range checks {
		unhealthy = unhealthy || check.Status == "ERROR"
	}
	if jsonOutput {
		if err := writeJSON(a.Out, checks); err != nil {
			return err
		}
		if unhealthy {
			return ErrDoctorUnhealthy
		}
		return nil
	}
	for _, check := range checks {
		if _, err := fmt.Fprintf(a.Out, "%-24s %-5s %s\n", check.Name, check.Status, check.Detail); err != nil {
			return err
		}
	}
	if unhealthy {
		return ErrDoctorUnhealthy
	}
	return nil
}

func (a *App) repairPermissions() error {
	for _, path := range []string{a.Config.DataDir, filepath.Join(a.Config.DataDir, "profiles"), filepath.Join(a.Config.DataDir, "backups")} {
		if info, err := os.Lstat(path); err == nil {
			if info.Mode().IsDir() || info.Mode().IsRegular() {
				if err := repairCommandPath(path, info); err != nil {
					return err
				}
			}
		}
	}
	for _, root := range []string{a.Config.DataDir, filepath.Join(a.Config.DataDir, "profiles"), filepath.Join(a.Config.DataDir, "backups")} {
		entries, err := os.ReadDir(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode().IsRegular() && !commandPathSecure(filepath.Join(root, entry.Name()), info) {
				if err := repairCommandPath(filepath.Join(root, entry.Name()), info); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// cleanupTemporaryFiles removes only temporary names emitted by this CLI's
// atomic writers.  It never scans or deletes arbitrary ZCode files.
func (a *App) cleanupTemporaryFiles() error {
	roots := []string{
		a.Config.DataDir,
		filepath.Join(a.Config.DataDir, "profiles"),
		filepath.Join(a.Config.DataDir, "backups"),
		a.Adapter.Paths.StateDir,
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		entries, err := os.ReadDir(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		removed := false
		for _, entry := range entries {
			if !isKnownTemporaryName(entry.Name()) {
				continue
			}
			path := filepath.Join(root, entry.Name())
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				// Never follow or unlink a symlink/FIFO merely because its name
				// resembles an atomic temporary.
				continue
			}
			if err := zcode.ValidateSensitivePath(path, false); err != nil {
				return err
			}
			if err := os.Remove(path); err != nil {
				return err
			}
			removed = true
		}
		if removed {
			if err := syncDirectory(root); err != nil {
				return err
			}
		}
	}
	return nil
}

func isKnownTemporaryName(name string) bool {
	return strings.HasPrefix(name, ".coordinator-") ||
		strings.HasPrefix(name, ".zcode-auth-tmp-") ||
		strings.HasPrefix(name, ".live-state.journal.tmp-") ||
		strings.HasPrefix(name, ".credentials.json.tmp-") ||
		strings.HasPrefix(name, ".telemetry-state.json.tmp-") ||
		strings.Contains(name, ".tmp-") && (strings.HasPrefix(name, ".automatic-") || strings.HasPrefix(name, ".manual-"))
}

func writeJSON(output interface{ Write([]byte) (int, error) }, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
