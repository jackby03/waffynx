.PHONY: all build build-engine build-ingestor build-agent build-api build-cli build-bridge build-bootstrap clean test lint proto install dev gatecheck

APP_NAME := waffynx
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS := -s -w \
	-X github.com/jackby03/waffynx/internal/version.Version=$(VERSION) \
	-X github.com/jackby03/waffynx/internal/version.BuildTime=$(BUILD_TIME) \
	-X github.com/jackby03/waffynx/internal/version.GitCommit=$(GIT_COMMIT)

GO := go
GOFLAGS := -trimpath -ldflags "$(LDFLAGS)"
BIN_DIR := bin

# -- Nginx fork paths --
NGINX_DIR := third_party/nginx
NGINX_CONFIGURE := $(NGINX_DIR)/configure
NGINX_MAKEFILE := $(NGINX_DIR)/Makefile

# -- Open-appsec fork paths --
APPSEC_DIR := third_party/open-appsec

all: build

# ============================================================
# Build targets
# ============================================================
build: build-cli build-engine build-ingestor build-agent build-api build-bridge build-bootstrap

build-cli:
	@echo "Building waffynx CLI..."
	@$(GO) build $(GOFLAGS) -o $(BIN_DIR)/waffynx ./cmd/waffynx

build-engine:
	@echo "Building waf-engine (Envoy ext_proc + ext_authz Data Plane)..."
	@$(GO) build $(GOFLAGS) -o $(BIN_DIR)/waf-engine ./cmd/waf-engine

build-ingestor:
	@echo "Building log-ingestor (NATS JetStream -> ClickHouse)..."
	@$(GO) build $(GOFLAGS) -o $(BIN_DIR)/log-ingestor ./cmd/log-ingestor

build-agent:
	@echo "Building waf-agent..."
	@$(GO) build $(GOFLAGS) -o $(BIN_DIR)/waf-agent ./cmd/waf-agent

build-api:
	@echo "Building waf-api..."
	@$(GO) build $(GOFLAGS) -o $(BIN_DIR)/waf-api ./cmd/waf-api

build-bridge:
	@echo "Building appsec-bridge..."
	@$(GO) build $(GOFLAGS) -o $(BIN_DIR)/appsec-bridge ./cmd/appsec-bridge

build-bootstrap:
	@echo "Building waffynx-bootstrap..."
	@$(GO) build $(GOFLAGS) -o $(BIN_DIR)/waffynx-bootstrap ./cmd/waffynx-bootstrap

# ============================================================
# Third-party: nginx (pinned by submodule to an upstream release tag)
# ============================================================
# No fork. What gets compiled is decided by the --without-* flags below, not by
# deleting sources, so the tree stays identical to upstream and a CVE bump is
# `git -C $(NGINX_DIR) checkout release-X.Y.Z` plus one submodule commit. The old
# fork carried a 221-file strip and 15 hand edits, which had to be replayed on
# every release — exactly where a security update gets postponed.
.PHONY: nginx-checkout nginx-patch nginx-configure nginx-build nginx-install

nginx-checkout:
	@echo "Checking out nginx submodule..."
	@if [ ! -d "$(NGINX_DIR)/src" ]; then \
		git submodule update --init --recursive $(NGINX_DIR); \
	fi

nginx-configure:
	@echo "Configuring nginx build..."
	@cd $(NGINX_DIR) && ./auto/configure \
		--prefix=/opt/waffynx/nginx \
		--with-http_ssl_module \
		--with-http_v2_module \
		--with-http_realip_module \
		--with-http_stub_status_module \
		--without-http_charset_module \
		--without-http_gzip_module \
		--without-http_ssi_module \
		--without-http_userid_module \
		--without-http_access_module \
		--without-http_auth_basic_module \
		--without-http_mirror_module \
		--without-http_autoindex_module \
		--without-http_geo_module \
		--without-http_map_module \
		--without-http_split_clients_module \
		--without-http_referer_module \
		--without-http_fastcgi_module \
		--without-http_uwsgi_module \
		--without-http_scgi_module \
		--without-http_memcached_module \
		--without-http_limit_conn_module \
		--without-http_limit_req_module \
		--without-http_empty_gif_module \
		--without-http_browser_module \
		--without-http_upstream_hash_module \
		--without-http_upstream_ip_hash_module \
		--without-http_upstream_least_conn_module \
		--without-http_upstream_random_module \
		--without-http_upstream_zone_module \
		--without-http_upstream_keepalive_module \
		--without-mail_pop3_module \
		--without-mail_imap_module \
		--without-mail_smtp_module \
		--add-module=$(CURDIR)/modules/ngx_waffynx

nginx-build:
	@echo "Building nginx..."
	@$(MAKE) -C $(NGINX_DIR) -j$$(nproc)

nginx-install:
	@$(MAKE) -C $(NGINX_DIR) install

# The C++ open-appsec bridge used to be built here from a stripped submodule.
# It never ran: WAFFYNX_REAL_ENGINE was defined nowhere, so the compiled shim was
# a stub, and the image built appsec-bridge with CGO_ENABLED=0 while selecting the
# in-process scorer anyway. The socket interface it exposed is still supported:
# point appsec.engine: open-appsec at an engine you run yourself.

# ============================================================
# Development
# ============================================================
.PHONY: dev proto lint test cover

dev:
	@echo "Starting development environment..."
	@# Postgres and Redis are disabled as they are currently unused
	@$(GO) run ./cmd/waf-api --config configs/waffynx.yaml

proto:
	@echo "Generating protobuf code... (Requires protoc and protoc-gen-go installed)"
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pkg/proto/waffynx/v1/*.proto

lint:
	@golangci-lint run ./...

test:
	@$(GO) test -race -coverprofile=coverage.out ./...

# Coverage with cross-package instrumentation, then the per-package floors.
# `test` above does not count coverage exercised across package boundaries.
cover:
	@$(GO) test -race -coverpkg=./... -coverprofile=coverage.out ./...
	@$(GO) run ./tools/covergate -profile coverage.out

# Minimum inventories: what the gates must *observe*, not just exit 0 on.
# A green test run with an empty suite, a deleted benchmark and a corpus with no
# seeds all used to pass. Rules live in .ci/gates.json.
gatecheck:
	@mkdir -p .artifacts
	@$(GO) test -json ./... > .artifacts/go-test.json
	@$(GO) run ./tools/gatecheck tests -json .artifacts/go-test.json
	@$(GO) test -run '^$$' -bench . -benchmem -benchtime=200x ./cmd/... ./internal/... \
		> .artifacts/bench.txt
	@$(GO) run ./tools/gatecheck bench -out .artifacts/bench.txt
	@$(GO) run ./tools/gatecheck fuzz -root .

test-all:
	@echo "Running all tests..."
	@$(GO) test -race -coverprofile=coverage.out ./...

# ============================================================
# Install / release
# ============================================================
.PHONY: install install-service install-complete

install: build
	@echo "Installing waffynx to /opt/waffynx..."
	@mkdir -p /opt/waffynx/bin /opt/waffynx/config /opt/waffynx/logs
	@cp $(BIN_DIR)/* /opt/waffynx/bin/
	@cp configs/waffynx.yaml /opt/waffynx/config/

install-service:
	@cp deploy/systemd/waffynx.service /etc/systemd/system/
	@cp deploy/systemd/waf-agent.service /etc/systemd/system/
	@systemctl daemon-reload

install-complete: install install-service
	@echo ""
	@echo "============================================"
	@echo "  Waffynx installed to /opt/waffynx"
	@echo "  Run: systemctl start waffynx waf-agent"
	@echo "============================================"

# ============================================================
# Vagrant testing
# ============================================================
.PHONY: vagrant-up vagrant-provision vagrant-test vagrant-ssh vagrant-destroy vagrant-reload

vagrant-up:
	@cd vagrant && vagrant up

vagrant-provision:
	@cd vagrant && vagrant provision

vagrant-test:
	@cd vagrant && vagrant ssh -c "bash /waffynx/vagrant/test.sh"

vagrant-ssh:
	@cd vagrant && vagrant ssh

vagrant-destroy:
	@cd vagrant && vagrant destroy -f

vagrant-reload:
	@cd vagrant && vagrant reload --provision

# Full test cycle: destroy old VM, create fresh, provision, test
vagrant-full-test:
	@cd vagrant && vagrant destroy -f 2>/dev/null || true
	@cd vagrant && vagrant up
	@cd vagrant && vagrant ssh -c "bash /waffynx/vagrant/test.sh"

# ============================================================
# Docker Compose
# ============================================================
.PHONY: compose-up compose-down compose-build compose-logs compose-dev

compose-build:
	@docker compose build

compose-up:
	@docker compose up -d --build

compose-dev:
	@docker compose --profile dev up --build

compose-down:
	@docker compose --profile dev down

compose-logs:
	@docker compose logs -f waffynx

# ============================================================
# Frontend UI
# ============================================================
.PHONY: ui-install ui-build ui-dev

ui-install:
	@cd ui && npm install

ui-build:
	@cd ui && npm run build

ui-dev:
	@cd ui && npm run dev

# ============================================================
# Utilities
# ============================================================
clean:
	@rm -rf $(BIN_DIR)/
	@rm -f coverage.out coverage.html
	@if [ -f "$(NGINX_MAKEFILE)" ]; then $(MAKE) -C $(NGINX_DIR) clean; fi
