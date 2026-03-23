GO      ?= go
GOFLAGS ?= -trimpath -ldflags="-s -w"
BIN     := bin/kveritas
SERVER  := bin/kveritas-server
GOPATH_BIN := $(shell $(GO) env GOPATH)/bin

.PHONY: all build server deps test clean cross fmt vet

all: build server

deps:
	$(GO) mod tidy
	$(GO) mod download

build: deps
	$(GO) build $(GOFLAGS) -o $(BIN) ./cmd/kveritas

server: deps
	$(GO) build $(GOFLAGS) -o $(SERVER) ./server

test: build server
	bash tests/run_tests.sh

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

# Cross-compile for all supported platforms.
cross: deps
	GOOS=linux   GOARCH=amd64   $(GO) build $(GOFLAGS) -o dist/kveritas-linux-amd64       ./cmd/kveritas
	GOOS=linux   GOARCH=arm64   $(GO) build $(GOFLAGS) -o dist/kveritas-linux-arm64       ./cmd/kveritas
	GOOS=darwin  GOARCH=amd64   $(GO) build $(GOFLAGS) -o dist/kveritas-darwin-amd64      ./cmd/kveritas
	GOOS=darwin  GOARCH=arm64   $(GO) build $(GOFLAGS) -o dist/kveritas-darwin-arm64      ./cmd/kveritas
	GOOS=windows GOARCH=amd64   $(GO) build $(GOFLAGS) -o dist/kveritas-windows-amd64.exe ./cmd/kveritas
	GOOS=linux   GOARCH=amd64   $(GO) build $(GOFLAGS) -o dist/kveritas-server-linux-amd64 ./server
	GOOS=darwin  GOARCH=arm64   $(GO) build $(GOFLAGS) -o dist/kveritas-server-darwin-arm64 ./server

clean:
	rm -rf bin dist
