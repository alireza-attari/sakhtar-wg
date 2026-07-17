GO ?= go
GO_BIN := $(shell command -v $(GO))
GO_VERSION := 1.26.5
GOVULNCHECK_VERSION := v1.6.0
STATICCHECK_VERSION := v0.7.0
GOVULNDB ?= https://vuln.go.dev
TOOLS_DIR := $(CURDIR)/.tools/bin
FUZZ_TIME ?= 10s
PROXY_LOAD_ARTIFACT ?= proxy-load.json
FUZZ_TARGETS := FuzzClientHello FuzzHTTPHost FuzzParseCIDRLines FuzzParseRIPEPrefixes FuzzLoadConfig FuzzAggregateIPv4

.PHONY: test test-race test-integration proxy-load benchmark benchmark-smoke fuzz-smoke vet build-linux verify-release tools staticcheck vuln verify clean

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-integration:
	$(GO) test -tags=integration -count=1 ./...

proxy-load:
	$(GO) test -run='Test(Admission|GracefulDrain)' -count=1 -json ./... > $(PROXY_LOAD_ARTIFACT)
	@cat $(PROXY_LOAD_ARTIFACT)

benchmark:
	$(GO) test -run='^$$' -bench=. -benchmem -count=8 ./internal/proxy ./internal/dns ./internal/routing ./internal/routesource ./cmd/sakhtar-wg

benchmark-smoke:
	$(GO) test -run='^$$' -bench=. -benchmem -benchtime=1x ./internal/proxy ./internal/dns ./internal/routing ./internal/routesource ./cmd/sakhtar-wg

fuzz-smoke:
	@for target in $(FUZZ_TARGETS); do \
		echo "fuzzing $$target for $(FUZZ_TIME)"; \
		$(GO) test -run='^$$' -fuzz="^$$target$$" -fuzztime=$(FUZZ_TIME) -parallel=2 ./cmd/sakhtar-wg || exit 1; \
	done

vet:
	$(GO) vet ./...
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) vet ./...

build-linux:
	GO=$(GO) scripts/build-release.sh dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) test -exec=/usr/bin/true ./...
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) test -exec=/usr/bin/true ./...

verify-release: build-linux
	VERIFY_REPRODUCIBLE=1 scripts/verify-release.sh dist

tools:
	mkdir -p $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	GOBIN=$(TOOLS_DIR) $(GO) install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)

staticcheck: tools
	PATH="$(dir $(GO_BIN)):$$PATH" GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(TOOLS_DIR)/staticcheck ./...

vuln: tools
	PATH="$(dir $(GO_BIN)):$$PATH" GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(TOOLS_DIR)/govulncheck -db $(GOVULNDB) ./...

verify:
	@test "$$($(GO) env GOVERSION)" = "go$(GO_VERSION)" || \
		(echo "Go $(GO_VERSION) required; found $$($(GO) env GOVERSION)" >&2; exit 1)
	$(GO) mod verify
	$(MAKE) test test-race proxy-load benchmark-smoke vet verify-release fuzz-smoke staticcheck vuln

clean:
	rm -rf dist .tools performance-results
	rm -f $(PROXY_LOAD_ARTIFACT)
