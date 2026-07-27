.PHONY: all build build-engine build-agent build-api build-cli clean test lint proto install dev

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
build: build-cli build-agent build-api

build-cli:
	@echo "Building waffynx CLI..."
	@$(GO) build $(GOFLAGS) -o $(BIN_DIR)/waffynx ./cmd/waffynx

build-agent:
	@echo "Building waf-agent..."
	@$(GO) build $(GOFLAGS) -o $(BIN_DIR)/waf-agent ./cmd/waf-agent

build-api:
	@echo "Building waf-api..."
	@$(GO) build $(GOFLAGS) -o $(BIN_DIR)/waf-api ./cmd/waf-api

# ============================================================
# Third-party: nginx fork
# ============================================================
.PHONY: nginx-checkout nginx-patch nginx-configure nginx-build nginx-install

nginx-checkout:
	@echo "Cloning nginx fork..."
	@if [ ! -d "$(NGINX_DIR)/src" ]; then \
		git submodule add https://github.com/jackby03/ngx_waffynx.git $(NGINX_DIR); \
		git submodule update --init --recursive; \
	fi

nginx-patch:
	@echo "Applying waffynx patches to nginx..."
	@cd $(NGINX_DIR) && git apply ../../patches/nginx/*.patch

nginx-configure:
	@echo "Configuring nginx build..."
	@cd $(NGINX_DIR) && ./auto/configure \
		--prefix=/opt/waffynx/nginx \
		--with-http_ssl_module \
		--with-http_v2_module \
		--with-http_v3_module \
		--with-http_realip_module \
		--with-http_stub_status_module \
		--with-stream \
		--with-stream_ssl_module \
		--without-http_fastcgi_module \
		--without-http_uwsgi_module \
		--without-http_scgi_module \
		--without-http_memcached_module \
		--add-module=$(APPSEC_DIR)/modules/nginx \
		--add-module=$(CURDIR)/modules/ngx_waffynx

nginx-build:
	@echo "Building nginx..."
	@$(MAKE) -C $(NGINX_DIR) -j$$(nproc)

nginx-install:
	@$(MAKE) -C $(NGINX_DIR) install

# ============================================================
# Development
# ============================================================
.PHONY: dev proto lint test

dev:
	@echo "Starting development environment..."
	@docker compose -f deploy/docker/docker-compose.yml up -d postgres redis
	@$(GO) run ./cmd/waf-api --config configs/waffynx.yaml

proto:
	@echo "Generating protobuf code..."
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pkg/proto/waffynx/v1/*.proto

lint:
	@golangci-lint run ./...

test:
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
# Utilities
# ============================================================
clean:
	@rm -rf $(BIN_DIR)/
	@rm -f coverage.out coverage.html
	@if [ -f "$(NGINX_MAKEFILE)" ]; then $(MAKE) -C $(NGINX_DIR) clean; fi
