BINARY  := llm-gateway
PKG     := ./cmd/gateway
LDFLAGS := -s -w
GOFLAGS := -trimpath

.PHONY: all build test vet run clean release

all: vet test build

build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

run: build
	./bin/$(BINARY) -config config.json

# Static-ish binaries for the two places this actually gets deployed.
release:
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-arm64 $(PKG)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-darwin-arm64 $(PKG)

clean:
	rm -rf bin
