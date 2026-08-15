# ZCode Account Manager

`zcode-auth` is a security-focused, cross-platform Go CLI for encrypted ZCode
account profiles, transactional account switching, backup, and recovery.

> **Status:** pre-release. Linux amd64 has native runtime coverage. macOS and
> Windows artifacts cross-compile successfully but still require native-host
> integration validation before they should be described as production-proven.

The CLI keeps multiple ZCode logins encrypted and switches the active account
without modifying ZCode binaries. It targets the official
[ZCode desktop platforms](https://zcode.z.ai/en/docs/install): Linux x64
(beta), macOS Intel and Apple Silicon, and Windows x64 and ARM64. It also
detects the bundled `zcode` CLI when it shares the same host state directory.
The adapter is deliberately limited to the shared authentication-state
contract verified from the installed ZCode 3.7.7 bundle; separate Z.ai API key
or coding-helper stores are not imported or mutated.

## Features

- Encrypted, immutable-ID account profiles with aliases.
- Automatic synchronization of refreshed credentials before switching.
- Transactional A → B → A switching, including `switch -`.
- Account-scoped companion-state preservation during every switch.
- Encrypted manual and automatic backups with bounded automatic retention.
- Crash recovery, corruption checks, ownership validation, and symlink or
  reparse-point rejection.
- Native Secret Service, macOS Keychain, and Windows DPAPI key backends.
- Safe JSON output that excludes credentials and private account-state values.

## Platform validation

| Target | Build | Runtime validation | Automatic restart |
|---|---:|---:|---:|
| Linux amd64 | Yes | Native tests and smoke test | Yes, when desktop identity is unambiguous |
| macOS amd64 | Yes | Cross-compiled only | Manual close required when ambiguous |
| macOS arm64 | Yes | Cross-compiled only | Manual close required when ambiguous |
| Windows amd64 | Yes | Cross-compiled only | Manual close required |
| Windows arm64 | Yes | Cross-compiled only | Manual close required |

## Safety model

- Profiles use XChaCha20-Poly1305; the random master key lives in the native
  secure store (Linux Secret Service, macOS Keychain, or Windows user-scoped
  DPAPI) and never in the profile directory. There is no plaintext key
  fallback.
- ZCode's authentication state rotates as one account-scoped bundle. A durable
  encrypted journal recovers an interrupted multi-file change.
- Profile blob and registry updates use a separate `profile.journal` so a
  crash during save/remove recovers to one complete old-or-new profile set;
  the journal stores only encrypted profile bytes and metadata.
- Every switch first saves refreshed live credentials back to the matching
  profile.
- State-changing commands use one native advisory lock (POSIX `flock` or
  Windows byte-range locking), atomic same-volume writes, flushes, owner/type
  checks, and restrictive permissions. Reparse points/symlinks and
  unverifiable ownership are rejected.
- Before any live-state mutation, the CLI detects both desktop and bundled CLI
  owners and product locks; any existing lock fails closed. An active bundled
  CLI is never guessed at or force-killed; mutation is refused. Windows
  desktop restart is also refused when no verified graceful-shutdown protocol
  is available.
- ZCode must be stopped for a state replacement. On Linux, when the native
  process name distinguishes the observed desktop from the bundled CLI,
  `switch --restart` performs a bounded `SIGTERM`, verifies exit, switches,
  then starts ZCode again. It does not silently escalate to `SIGKILL`. On
  macOS/Windows or an ambiguous shared image, close ZCode manually; automatic
  restart fails closed rather than guessing.
- Diagnostic and JSON output omit tokens, decrypted account objects, private
  account identifiers, authorization headers, and encryption keys.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the transaction and
state-preservation invariants.

## Installation

For a tagged release, download the binary matching the target platform from
GitHub Releases and verify it from the same directory as `SHA256SUMS`:

```bash
sha256sum -c SHA256SUMS
install -m 0755 zcode-auth-linux-amd64 "$HOME/.local/bin/zcode-auth"
```

On macOS, verify with `shasum -a 256` when GNU `sha256sum` is unavailable.
Windows users can use `Get-FileHash -Algorithm SHA256` and compare the result
with the manifest.

## Build from source

Requirements are Go 1.25.8 or later. Linux requires `secret-tool` (package
`libsecret-tools` on Ubuntu/Pop!_OS); macOS uses `/usr/bin/security`; Windows
uses the built-in user-scoped DPAPI.

```bash
go build -buildvcs=false -trimpath -ldflags '-s -w' -o bin/zcode-auth ./cmd/zcode-auth
go test ./...

# Build the five advertised binary targets (Linux x64, macOS x64/arm64,
# Windows x64/arm64) and deterministic source/checksum artifacts.
make release
```

## Commands

```text
zcode-auth list [--json]
zcode-auth current [--json]

zcode-auth add <alias>
zcode-auth save <alias>
zcode-auth switch <alias> [--restart]
zcode-auth switch - [--restart]
zcode-auth remove <alias>

zcode-auth login <alias>
zcode-auth logout

zcode-auth backup
zcode-auth backups
zcode-auth restore <backup-id>

zcode-auth doctor [--repair] [--json]
```

`doctor` writes all checks before exiting; it returns a non-zero status when
any check is `ERROR`. Warnings alone do not make the command fail.

Aliases contain letters, digits, `_`, `-`, or `.` and must begin with a letter
or digit. `switch -` toggles to the previously active profile.

Typical first setup:

```bash
# With an existing ZCode login and ZCode stopped:
zcode-auth save personal

# Capture another login through ZCode's normal OAuth UI:
zcode-auth login work

zcode-auth switch personal --restart
zcode-auth switch - --restart
```

## Storage

```text
Linux:  ~/.local/share/zcode-auth/ and ~/.config/zcode-auth/config.json
macOS:  ~/Library/Application Support/zcode-auth/ (data and config)
Windows: %LOCALAPPDATA%\zcode-auth\ (data) and
         %APPDATA%\zcode-auth\config.json (config)

Application data directory:
├── registry.json
├── profiles/*.enc
├── backups/*.json
├── auth.lock
├── profile.journal
└── transaction journals
```

Automatic rollback backups retain the newest 10 by default. Manual backups
created by `zcode-auth backup` are not removed by automatic rotation.

Optional configuration keys:

```json
{
  "data_dir": "/absolute/path/to/zcode-auth-data",
  "zcode_state_dir": "/absolute/path/to/.zcode/v2",
  "zcode_executable": "/opt/ZCode/zcode",
  "zcode_cli_executable": "/absolute/path/to/.zcode/cli/zcode",
  "backup_limit": 10,
  "stop_timeout_seconds": 10,
  "login_timeout_seconds": 300
}
```

Environment overrides with the same purpose are
`ZCODE_AUTH_DATA_DIR`, `ZCODE_AUTH_ZCODE_STATE_DIR`,
`ZCODE_AUTH_ZCODE_EXECUTABLE`, `ZCODE_AUTH_ZCODE_CLI_EXECUTABLE`,
`ZCODE_AUTH_BACKUP_LIMIT`, `ZCODE_AUTH_STOP_TIMEOUT`, and
`ZCODE_AUTH_LOGIN_TIMEOUT`. `ZCODE_DATA_BASE_DIR` overrides the shared ZCode
base directory and resolves state as `<base>/v2`. These variables do not carry
encryption keys or tokens.

## Platform and shared CLI scope

The profile and backup envelopes include adapter metadata (`state_group`,
adapter schema, and product). Existing pre-metadata profiles/backups migrate
to the desktop `zcode-v2-auth` group in memory and are rewritten safely when
that profile is next saved. Records from another state group or unsupported schema are
rejected rather than mixed.

The bundled CLI is treated as another owner of the same state group for
process/lock detection. Its CLI database, commands, MCP configuration, API
keys, workspaces, logs, and caches remain outside this tool's scope. A CLI
process cannot be safely restarted by this tool, so commands refuse while it
owns shared state. If desktop and CLI resolve to the same executable image and
there is no native way to distinguish their command mode, the detector treats
the image as a CLI owner and refuses to stop it rather than guessing.

Process and product lock checks are point-in-time safety gates. Because ZCode
does not expose a documented cross-product mutation lock, an unrelated actor
could still launch it after the final check. Do not automate concurrent ZCode
launches while an account-state command is running.

## Scope

The CLI changes only ZCode's known live authentication state and its own
platform-native data/config. ZCode task databases, workspaces, settings, logs,
bot state, certificates, and caches are outside its mutation scope. Exact
state-file compatibility details are documented in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security and contributing

Never attach real ZCode state or tokens to an issue. Follow
[SECURITY.md](SECURITY.md) for vulnerability disclosure and
[CONTRIBUTING.md](CONTRIBUTING.md) for development and review requirements.

## License and attribution

Licensed under the [MIT License](LICENSE).

This is an independent project and is not affiliated with, sponsored by, or
endorsed by Z.ai or ZCode. Z.ai and ZCode names and trademarks belong to their
respective owners.
