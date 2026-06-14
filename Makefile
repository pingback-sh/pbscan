BINARY ?= pbscan
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/pingback-sh/pbscan/internal/app.Version=$(VERSION) \
	-X github.com/pingback-sh/pbscan/internal/app.Commit=$(COMMIT) \
	-X github.com/pingback-sh/pbscan/internal/app.Date=$(DATE)

.PHONY: build test race vet fmt check clean install demo cross

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/pbscan

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

check: test race vet
	@test -z "$$(gofmt -l $$(find . -name '*.go' -type f))" || \
		(echo 'Go files need formatting'; gofmt -l $$(find . -name '*.go' -type f); exit 1)

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/pbscan

demo:
	go run ./examples/lab

cross:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pbscan-linux-amd64 ./cmd/pbscan
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pbscan-linux-arm64 ./cmd/pbscan
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pbscan-darwin-amd64 ./cmd/pbscan
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pbscan-darwin-arm64 ./cmd/pbscan
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pbscan-windows-amd64.exe ./cmd/pbscan

clean:
	rm -rf $(BINARY) $(BINARY).exe dist coverage.out
