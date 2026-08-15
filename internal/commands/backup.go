package commands

import (
	"fmt"
	"time"

	"github.com/hcsolakoglu/zcode-auth/internal/model"
	zprocess "github.com/hcsolakoglu/zcode-auth/internal/process"
	"github.com/hcsolakoglu/zcode-auth/internal/transaction"
	"github.com/hcsolakoglu/zcode-auth/internal/zcode"
)

func (a *App) encryptBackup(bundle model.SessionBundle, credentialsPresent bool) (transaction.EncryptedSessionBundle, error) {
	payload := transaction.EncryptedSessionBundle{CredentialsPresent: credentialsPresent, TelemetryPresent: bundle.TelemetryPresent}
	var err error
	if credentialsPresent {
		payload.Credentials, err = a.Store.SealPayload("backup-credentials", bundle.Credentials)
		if err != nil {
			return transaction.EncryptedSessionBundle{}, err
		}
	}
	if bundle.TelemetryPresent {
		payload.Telemetry, err = a.Store.SealPayload("backup-telemetry", bundle.Telemetry)
		if err != nil {
			return transaction.EncryptedSessionBundle{}, err
		}
	}
	return payload, nil
}

func (a *App) decryptBackup(payload transaction.EncryptedSessionBundle) (model.SessionBundle, bool, error) {
	bundle := model.SessionBundle{TelemetryPresent: payload.TelemetryPresent}
	var err error
	if payload.CredentialsPresent {
		bundle.Credentials, err = a.Store.OpenPayload("backup-credentials", payload.Credentials)
		if err != nil {
			return model.SessionBundle{}, false, err
		}
	}
	if payload.TelemetryPresent {
		bundle.Telemetry, err = a.Store.OpenPayload("backup-telemetry", payload.Telemetry)
		if err != nil {
			return model.SessionBundle{}, false, err
		}
	}
	return bundle, payload.CredentialsPresent, nil
}

func (a *App) createBackup(kind transaction.BackupKind, reason, alias string, bundle model.SessionBundle, credentialsPresent bool) (transaction.BackupInfo, error) {
	// readLiveOptional reports presence when either live document exists.  The
	// encrypted backup payload, however, tracks credential presence separately
	// so a telemetry-only partial state remains restorable.
	credentialsPresent = credentialsPresent && bundle.Credentials != nil
	payload, err := a.encryptBackup(bundle, credentialsPresent)
	if err != nil {
		return transaction.BackupInfo{}, fmt.Errorf("encrypt backup: %w", err)
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	metadata := model.BackupMetadata{
		SchemaVersion: model.SchemaVersion,
		CreatedAt:     now().UTC(),
		Reason:        reason,
		ProfileAlias:  alias,
		CLIversion:    Version,
		Adapter:       model.DefaultAdapterMetadata(),
	}
	if credentialsPresent {
		if identity, identityErr := a.Adapter.Identity(bundle.Credentials); identityErr == nil {
			metadata.AccountID = identity.AccountID
			metadata.Provider = identity.Provider
		}
	}
	if version, versionErr := a.detectVersion(); versionErr == nil {
		metadata.ZCodeVersion = version
	}
	request := transaction.BackupRequest{Metadata: metadata, Payload: payload, Kind: kind, Manual: kind == transaction.Manual}
	backup, err := a.Backups.Create(request)
	if err != nil {
		return transaction.BackupInfo{}, err
	}
	return backup, nil
}

func (a *App) restoreBackupID(id string) (model.SessionBundle, bool, transaction.RestoredBackup, error) {
	restored, err := a.Backups.Restore(id)
	if err != nil {
		return model.SessionBundle{}, false, transaction.RestoredBackup{}, err
	}
	adapter, adapterErr := model.NormalizeAdapterMetadata(restored.Metadata.Adapter)
	if adapterErr != nil || adapter.StateGroup != model.StateGroupID {
		return model.SessionBundle{}, false, transaction.RestoredBackup{}, fmt.Errorf("backup belongs to an incompatible adapter state group")
	}
	bundle, present, err := a.decryptBackup(restored.Payload)
	if err != nil {
		return model.SessionBundle{}, false, transaction.RestoredBackup{}, fmt.Errorf("decrypt backup: %w", err)
	}
	// A telemetry-only snapshot is valid during an interrupted/logout state.
	// It must remain restorable so stale account-scoped telemetry cannot be
	// stranded merely because credentials were already removed.
	if present {
		if err := zcode.ValidateCredentials(bundle.Credentials); err != nil {
			return model.SessionBundle{}, false, transaction.RestoredBackup{}, fmt.Errorf("backup credentials are invalid")
		}
	}
	if bundle.TelemetryPresent {
		if err := zcode.ValidateTelemetry(bundle.Telemetry); err != nil {
			return model.SessionBundle{}, false, transaction.RestoredBackup{}, fmt.Errorf("backup telemetry is invalid")
		}
	}
	return bundle, present, restored, nil
}

func (a *App) detectVersion() (string, error) {
	return zprocess.Version(a.Config.ZCodeExecutable)
}
