VERSION ?= $(shell git describe --tags --always 2>/dev/null | sed "s/^v//" || echo dev)
BINARY := jsrelease

.PHONY: build test race windows clean data

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o $(BINARY) .

test:
	go test ./...

race:
	go test -race -cover ./...

windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o $(BINARY).exe .

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist

# Refresh the bundled data from the live sources; run before tagging a release
# so each version ships with current data. Set GITHUB_TOKEN or use
# 'jsrelease -set-key github' first.
data:
	go run . -update -data jsrelease.json
