package model

import (
	"fmt"
	"time"
)

const SchemaVersion = 1

// StateGroupID identifies the on-disk state group understood by this
// adapter.  It is deliberately narrower than a product name: the desktop
// client and its bundled CLI may share this group, while unrelated Z.ai API
// clients must not be treated as interchangeable accounts.
const StateGroupID = "zcode-v2-auth"

type ProductID string

const (
	ProductDesktop ProductID = "zcode-desktop"
	ProductCLI     ProductID = "zcode-cli"
)

// AdapterMetadata is persisted with profiles and backups so future adapters
// can refuse to mix incompatible state groups instead of guessing from an
// alias or an account id. Missing fields in pre-metadata records are migrated
// to the proven desktop state group by the profile/backup readers.
type AdapterMetadata struct {
	Product       ProductID `json:"product,omitempty"`
	StateGroup    string    `json:"state_group,omitempty"`
	SchemaVersion int       `json:"adapter_schema_version,omitempty"`
}

func DefaultAdapterMetadata() AdapterMetadata {
	return AdapterMetadata{Product: ProductDesktop, StateGroup: StateGroupID, SchemaVersion: SchemaVersion}
}

// NormalizeAdapterMetadata migrates records produced before capability
// metadata existed. Any non-zero metadata must identify this exact state
// group; product-specific stores must not be mixed silently.
func NormalizeAdapterMetadata(metadata AdapterMetadata) (AdapterMetadata, error) {
	if metadata.Product == "" && metadata.StateGroup == "" && metadata.SchemaVersion == 0 {
		return DefaultAdapterMetadata(), nil
	}
	if metadata.StateGroup != StateGroupID || metadata.SchemaVersion != SchemaVersion {
		return AdapterMetadata{}, fmt.Errorf("unsupported adapter state group %q/schema %d", metadata.StateGroup, metadata.SchemaVersion)
	}
	if metadata.Product != ProductDesktop && metadata.Product != ProductCLI {
		return AdapterMetadata{}, fmt.Errorf("unsupported adapter product %q", metadata.Product)
	}
	return metadata, nil
}

// SessionBundle is the indivisible, account-scoped state rotated during a
// switch. Both documents are kept opaque so future ZCode fields survive.
type SessionBundle struct {
	Credentials      []byte `json:"credentials"`
	Telemetry        []byte `json:"telemetry,omitempty"`
	TelemetryPresent bool   `json:"telemetry_present"`
}

type Identity struct {
	AccountID string `json:"account_id"`
	Provider  string `json:"provider"`
}

type ProfileMetadata struct {
	ProfileID    string          `json:"profile_id"`
	AccountID    string          `json:"account_id"`
	Provider     string          `json:"provider"`
	LastSynced   time.Time       `json:"last_synced_at"`
	HasTelemetry bool            `json:"has_telemetry"`
	Adapter      AdapterMetadata `json:"adapter,omitempty"`
}

type Registry struct {
	SchemaVersion   int                        `json:"schema_version"`
	ActiveProfile   string                     `json:"active_profile,omitempty"`
	PreviousProfile string                     `json:"previous_profile,omitempty"`
	Profiles        map[string]ProfileMetadata `json:"profiles"`
}

type BackupMetadata struct {
	SchemaVersion  int             `json:"schema_version"`
	ID             string          `json:"id"`
	CreatedAt      time.Time       `json:"created_at"`
	Reason         string          `json:"reason"`
	ProfileAlias   string          `json:"profile_alias,omitempty"`
	AccountID      string          `json:"account_id,omitempty"`
	Provider       string          `json:"provider,omitempty"`
	ZCodeVersion   string          `json:"zcode_version,omitempty"`
	CLIversion     string          `json:"zcode_auth_version"`
	CredentialsSHA string          `json:"credentials_sha256,omitempty"`
	TelemetrySHA   string          `json:"telemetry_sha256,omitempty"`
	Adapter        AdapterMetadata `json:"adapter,omitempty"`
}
