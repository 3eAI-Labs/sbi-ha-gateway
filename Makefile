# SBI HA Gateway — developer tasks.
#
# Go targets run with GOWORK=off: a go.work in a parent directory would otherwise
# change which modules the build resolves.

export GOWORK := off

.DEFAULT_GOAL := help

.PHONY: help build vet test test-short coverage lint fmt fmt-check licenses image image-smoke run clean

help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build the gateway binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o bin/sbi-gateway ./cmd/sbi-gateway

vet: ## go vet the gateway
	go vet ./...

test: ## Run the gateway tests with the race detector
	go test -race -count=1 ./...

test-short: ## Run the tests without the slow failover-exhaustion cases
	go test -short -count=1 ./...

coverage: ## Write coverage.html
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint: ## golangci-lint when installed, go vet otherwise
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; else go vet ./...; fi

fmt: ## gofmt the tree
	gofmt -w $$(git ls-files '*.go')

fmt-check: ## Fail when a file is not gofmt'd (CI runs this)
	@out=$$(gofmt -l $$(git ls-files '*.go')); if [ -n "$$out" ]; then echo "not gofmt'd (make fmt):"; echo "$$out"; exit 1; fi

licenses: ## Check licence headers and dependency licences
	scripts/check-licenses.sh

image: ## Build the container image (gateway and licence texts) as sbi-ha-gateway:dev
	docker build -t sbi-ha-gateway:dev .

image-smoke: image ## Build the image, then start it next to a NATS server and check that it comes up healthy
	scripts/image-smoke.sh sbi-ha-gateway:dev

run: build ## Build and run the gateway with the environment's settings
	bin/sbi-gateway

clean: ## Remove build output
	rm -rf bin coverage.out coverage.html

# Targets that need files outside the public tree (see internal.mk).
-include internal.mk
