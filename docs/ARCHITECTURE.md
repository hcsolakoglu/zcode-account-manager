# ZCode Auth architecture

## Adapter and supported products

The adapter capability identity is `zcode-v2-auth`, schema version 1. The
supported ZCode products are the desktop client and the bundled `zcode` CLI,
but only for the shared on-host authentication group. The CLI's own database,
MCP/configuration files, API-key stores, sessions, and caches are unrelated
and are not read or changed. Profiles and backups persist this capability
metadata; records from another state group or schema are rejected. Older
records with no metadata migrate to the desktop group and retain their opaque
payloads.

Release targets follow the ZCode desktop download matrix: Linux x64 (beta),
macOS amd64/arm64, and Windows amd64/arm64. Platform backends are selected
with build tags; Windows binaries do not compile Linux `/proc`, POSIX `flock`,
or Secret Service code, and no target has a plaintext key fallback.

## Shared-state ownership

Before any mutation, commands enumerate exact desktop and bundled-CLI process
images using native process identity (PID plus start time and owner/SID), then
check `telemetry-state.lock`. Its absence is the only safe state: an existing
lock is treated as an active or unverifiable shared-state owner and ZCode is
left to perform any product-specific stale-lock cleanup. A
running desktop may be stopped only after its identity is verified and its
graceful-stop contract is available. A bundled CLI owner is never force-killed
or guessed at: commands refuse until it exits. If both products resolve to the
same executable image, the owner is treated as ambiguous/CLI and is likewise
not stopped. An existing, malformed, reparse,
foreign-owned, or otherwise unverifiable state lock is also a refusal.

These are fail-closed point-in-time gates, not a lock shared with every ZCode
credentials writer. ZCode publishes no documented cross-product exclusion
primitive for the entire credential-plus-telemetry bundle, so operators must
not launch another ZCode owner concurrently with a mutation. Automatic
restart is enabled only where the desktop owner and graceful stop can be
verified; otherwise the user closes it manually.

## Transaction boundary

`credentials.json` and `telemetry-state.json` form one account-scoped session
bundle. Every command which changes the live login state holds the exclusive
lock until both files, the encrypted profile, any backup, and the registry have
reached a consistent state.

The accepted outcomes of a switch are:

1. the previous credential and telemetry documents plus the old registry; or
2. the target credential and telemetry documents plus the new registry.

A mixture is an interrupted transaction. Its journal is retained and
the next state-aware command recovers it while holding the global lock;
plain `doctor` reports it without recovery, while `doctor --repair` performs
the recovery explicitly.

## Profile-store journal

Profile saves and removals have a separate `profile.journal` under the
application data directory. It is written atomically with mode `0600` and
fsynced before either the encrypted profile blob or `registry.json` changes.
The journal contains the old registry metadata and, when present, the old
already-encrypted profile blob; decrypted credentials and telemetry are never
written to it. A prepared journal restores both old files and removes any
newly-created profile, while a committed journal preserves the new pair and
is only cleaned up. Recovery is deliberately deferred until the first Store
operation so application construction cannot race ahead of the global
`auth.lock`. Plain `doctor` reports a pending profile journal without opening
it; `doctor --repair` recovers it while holding that lock.

## Telemetry rotation

ZCode 3.7.7 stores `deviceMid` and `lastDailyActiveDate` in
`~/.zcode/v2/telemetry-state.json`. The CLI does not interpret or merge those
fields. It preserves the complete JSON document as opaque bytes in the same
encrypted profile envelope as the credentials.

- Saving or synchronizing an account replaces that profile's telemetry copy.
- Switching restores the target profile's telemetry copy.
- If the target profile has no telemetry document, a stale live telemetry file
  is removed rather than inherited from the previous account.
- Login clears old telemetry before launch, then requires two consecutive
  identical authenticated bundle reads before capturing the new profile. It
  never rewrites those live files while ZCode is running.
- Logout backs up and synchronizes the current bundle, then removes both live
  documents.
- Backup and restore cover both documents and validate independent SHA-256
  checksums.
- Automatic backups retain the newest configured count (10 by default).
  Explicit manual backups are not removed by automatic rotation.

No telemetry identifier is printed by normal, JSON, or doctor output.

## Identity

ZCode credential values are decrypted only in memory using its installed v1
format. The account identity is the trimmed OAuth `id`, falling back to
`user_id`; the provider comes from `oauth:active_provider`. A switch or sync
aborts if identity cannot be established or conflicts with registry metadata.
The original credential bytes remain the source of truth and unknown fields
are never reconstructed.

## Sensitive storage

The profile envelope uses XChaCha20-Poly1305. Its random 256-bit master key is
stored through the native secure store: Linux Secret Service (`secret-tool`),
macOS Keychain (`security`), or Windows user-scoped DPAPI. Profile files
contain only authenticated ciphertext. POSIX uses no-follow opens and
directory fsync; Windows uses reparse-point checks, flushed temporary files,
and write-through replacement. Unexpected symlinks/reparse points, owners,
and file types are rejected.

Errors and structured output contain aliases, status, counts, timestamps, and
safe paths only. Credential contents, token material, account telemetry IDs,
authorization headers, encryption keys, and decrypted user objects are never
formatted into errors or logs.
