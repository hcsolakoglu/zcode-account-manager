# Contributing

This repository is initially maintained as a private project. Collaborators
should discuss behavior or security changes in an issue before opening a large
pull request.

## Development

Use Go 1.25.8 or later, then run:

```bash
go mod verify
gofmt -w .
go test ./...
go test -race ./...
go vet ./...
```

Before changing platform code, compile every advertised target with
`make cross-build`. Native macOS and Windows behavior must not be claimed from
cross-compilation alone.

## Pull requests

- Keep changes focused and include regression tests.
- Preserve opaque credential and telemetry bytes.
- Never commit real credentials, tokens, telemetry identifiers, key material,
  machine-specific paths, or captured user data.
- Document user-visible behavior and security-boundary changes.
- Use conventional, imperative commit subjects.
- Confirm that generated binaries and `outputs/` are not committed.

Report vulnerabilities according to [SECURITY.md](SECURITY.md), not in a
regular issue or pull request.
