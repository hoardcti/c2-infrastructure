# Standard Makefile for hoardCTI Go repositories (GO-MAK-001 to GO-MAK-004).
# Every tool is pinned with a `tool` directive in go.mod and run with `go tool`,
# so Go and make are the only things a developer needs installed.

# Static builds by default (GO-BLD-001, GO-RST-003). The race detector needs
# cgo for its own runtime, so the test targets turn it back on.
export CGO_ENABLED := 0

# Flags shared by every test run in CI (GO-SPT-004, GO-SPT-005).
TEST_FLAGS := -race -shuffle=on -timeout=5m

.DEFAULT_GOAL := help

.PHONY: help
help: ## List the available targets.
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-12s %s\n", $$1, $$2}'

.PHONY: fmt
fmt: ## Format all Go code (gofumpt + gci).
	go tool golangci-lint fmt

.PHONY: fmt-check
fmt-check: ## Fail if any file is not formatted.
	go tool golangci-lint fmt --diff

.PHONY: lint
lint: ## Run every linter.
	go tool golangci-lint run

.PHONY: fix
fix: ## Apply go fix modernisers.
	go fix ./...

.PHONY: fix-check
fix-check: ## Fail if go fix would change anything.
	go fix -diff ./...

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum.
	go mod tidy

.PHONY: tidy-check
tidy-check: ## Fail if go.mod or go.sum are not tidy.
	go mod tidy -diff

.PHONY: generate
generate: ## Regenerate generated code.
	go generate ./...

.PHONY: generate-check
generate-check: generate ## Fail if generated code is out of date.
	git diff --exit-code

.PHONY: test
test: ## Run tests with the race detector, shuffled.
	CGO_ENABLED=1 go test $(TEST_FLAGS) ./...

.PHONY: cover
cover: ## Run tests with coverage and enforce the 100% threshold.
	CGO_ENABLED=1 go test $(TEST_FLAGS) -covermode=atomic -coverpkg=./... -coverprofile=cover.out ./...
	go tool go-test-coverage --config=.testcoverage.yml

.PHONY: vuln
vuln: ## Scan for known vulnerabilities in code we call.
	go tool govulncheck ./...

.PHONY: build
build: ## Build every command into bin/.
	go build -trimpath -ldflags="-s -w" -o bin/ ./cmd/...

.PHONY: live
live: ## Run tests against real upstream APIs (needs credentials).
	CGO_ENABLED=1 go test -race -tags live -run Live ./...

.PHONY: check
check: tidy-check fmt-check lint fix-check generate-check cover vuln build ## Run every CI check locally.

.PHONY: clean
clean: ## Remove build and coverage output.
	rm -rf bin/ cover.out
