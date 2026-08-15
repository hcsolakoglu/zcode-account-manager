## Summary

Describe the change and its user-visible effect.

## Verification

- [ ] `gofmt` produces no changes
- [ ] `go test ./...`
- [ ] `go test -race ./...`
- [ ] `go vet ./...`
- [ ] All five release targets compile when platform code changes
- [ ] No credentials, telemetry identifiers, personal data, or local paths are included
- [ ] Documentation reflects security or compatibility changes

## Security and compatibility

Describe changes to storage, encryption, locking, process detection, recovery,
or the ZCode state contract. Write `None` if not applicable.
