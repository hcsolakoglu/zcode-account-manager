.PHONY: build test race vet cross-build release clean

VERSION ?= 0.1.0
RELEASE_DIR ?= outputs
SOURCE_ARCHIVE := $(RELEASE_DIR)/zcode-auth-source.tar.gz

build:
	@mkdir -p bin
	go build -buildvcs=false -trimpath -ldflags '-s -w' -o bin/zcode-auth ./cmd/zcode-auth

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

# Official ZCode desktop downloads document macOS Intel/Apple Silicon,
# Windows x64/ARM64, and Linux x64 beta. The bundled CLI is distributed in
# the same host-specific binary and shares only the proven v2 auth state.
cross-build:
	@mkdir -p $(RELEASE_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '-s -w -X github.com/hcsolakoglu/zcode-auth/internal/commands.Version=$(VERSION)' -o $(RELEASE_DIR)/zcode-auth-linux-amd64 ./cmd/zcode-auth
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '-s -w -X github.com/hcsolakoglu/zcode-auth/internal/commands.Version=$(VERSION)' -o $(RELEASE_DIR)/zcode-auth-darwin-amd64 ./cmd/zcode-auth
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '-s -w -X github.com/hcsolakoglu/zcode-auth/internal/commands.Version=$(VERSION)' -o $(RELEASE_DIR)/zcode-auth-darwin-arm64 ./cmd/zcode-auth
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '-s -w -X github.com/hcsolakoglu/zcode-auth/internal/commands.Version=$(VERSION)' -o $(RELEASE_DIR)/zcode-auth-windows-amd64.exe ./cmd/zcode-auth
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '-s -w -X github.com/hcsolakoglu/zcode-auth/internal/commands.Version=$(VERSION)' -o $(RELEASE_DIR)/zcode-auth-windows-arm64.exe ./cmd/zcode-auth

release: cross-build
	@mkdir -p $(RELEASE_DIR)
	@tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --mode='u+rwX,go+rX,go-w' --transform='s,^\./,zcode-auth/,' --exclude='./outputs' --exclude='./bin' --exclude='./work' --exclude='./.git' --exclude='./zcode-auth' --exclude='./zcode-auth.exe' -cf - . | gzip -n > $(SOURCE_ARCHIVE)
	@(cd $(RELEASE_DIR) && sha256sum \
		zcode-auth-linux-amd64 \
		zcode-auth-darwin-amd64 \
		zcode-auth-darwin-arm64 \
		zcode-auth-windows-amd64.exe \
		zcode-auth-windows-arm64.exe \
		zcode-auth-source.tar.gz > SHA256SUMS)

clean:
	rm -f bin/zcode-auth zcode-auth zcode-auth.exe coverage.out $(RELEASE_DIR)/zcode-auth-* $(SOURCE_ARCHIVE) $(RELEASE_DIR)/SHA256SUMS
