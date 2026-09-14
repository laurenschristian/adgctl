BIN := adgctl
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOLANGCI := github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
GOSEC := github.com/securego/gosec/v2/cmd/gosec@v2.29.0
# G204: password_cmd runs through sh by design. G304: --file is user input by design. G117: the plain-text password option is documented.
GOSEC_EXCLUDE := G204,G304,G117

.PHONY: build install test cover cover-html lint fmt sec vuln hooks tidy snapshot clean

# Point git at the tracked hooks in .githooks. Run once after cloning.
hooks:
	git config core.hooksPath .githooks
	@echo "git hooks installed (.githooks)"

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .

# Install into ~/.local/bin. macOS kills a running binary overwritten in place, so remove first.
install: build
	mkdir -p $(HOME)/.local/bin
	rm -f $(HOME)/.local/bin/$(BIN)
	cp $(BIN) $(HOME)/.local/bin/$(BIN)

test:
	go test -race -shuffle=on ./...

# Tests with coverage and a no-regression floor (override MIN_COVER).
cover:
	sh scripts/coverage.sh

cover-html: cover
	go tool cover -html=coverage.out

fmt:
	gofmt -w .

lint:
	go vet ./...
	go run $(GOLANGCI) run ./...

sec:
	go run $(GOSEC) -quiet -exclude=$(GOSEC_EXCLUDE) ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

tidy:
	go mod tidy

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf $(BIN) dist/ coverage.out
