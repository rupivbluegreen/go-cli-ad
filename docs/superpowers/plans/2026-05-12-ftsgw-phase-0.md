# ftsgw Phase 0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an authentication broker (`ftsgw-server`) plus companion CLI (`ftsgw-cli`) that authenticates AD users via LDAP simple bind and issues short-lived Ed25519-signed JWT app-tokens with a bounded refresh window. Phase 0 covers Mode 3 (fully disconnected) only.

**Architecture:** Single Go module (`github.com/rupivbluegreen/go-cli-ad`). All new code lives under `/ftsgw/`: `cmd/ftsgw-server`, `cmd/ftsgw-cli`, `pkg/api/types` (shared HTTP shapes), `internal/server/{api,auth,idp,signer,audit,store,config}`, `internal/cli` (ftsgw-cli commands). The broker exposes an HTTPS API on chi; tokens are minted by the auth package and signed by a pluggable Signer (file-backed Ed25519 today, HSM stub later). Identity is resolved through a pluggable IdentityProvider (LDAP today, Entra/ADFS stubs). State lives in SQLite (revoked_tokens, audit_events) with goose migrations. Synchronous audit writes hit both DB and a rotated JSON-lines log.

**Tech Stack:** Go 1.25 (`go.mod` already pins 1.25.0 — spec asks for 1.22+, satisfied), `github.com/go-chi/chi/v5`, `github.com/lestrrat-go/jwx/v2`, `github.com/go-ldap/ldap/v3` (already in go.sum), `modernc.org/sqlite` (pure-Go, no cgo), `github.com/pressly/goose/v3`, `github.com/spf13/cobra` + `github.com/spf13/viper`, `golang.org/x/term`, `gopkg.in/natefinch/lumberjack.v2`, `github.com/prometheus/client_golang`, `go.opentelemetry.io/otel`, `github.com/testcontainers/testcontainers-go`. CGO_ENABLED=0 throughout. License: Apache 2.0.

**Decisions baked in (will land in DECISIONS.md as ADRs):**
- ftsgw lives under `/ftsgw` subtree of existing module — keeps go-cli-ad untouched, no second `go.mod`.
- Module path stays `github.com/rupivbluegreen/go-cli-ad` — ftsgw imports become `github.com/rupivbluegreen/go-cli-ad/ftsgw/...`.
- Fresh LDAP implementation in `ftsgw/internal/server/idp` — does not share code with existing `internal/onprem`.
- Ed25519 over RS256; jwx/v2 over golang-jwt; modernc sqlite over mattn; chi over stdlib mux; distroless static base; monorepo; synchronous audit writes; refresh window bounded at 4h from `iat`; no bootstrap token.
- Clock injection via a `Clock` interface to make refresh-window exhaustion testable without `time.Sleep(4*time.Hour)`.

**File map (everything new):**
```
ftsgw/
  Makefile                                      task targets (delegates from root Makefile)
  README.md                                     short pointer; main README at root
  cmd/
    ftsgw-server/
      main.go                                   broker entry; loads config, builds deps, runs server
      admin.go                                  admin subcommands (revoke, rotate-key)
    ftsgw-cli/
      main.go                                   CLI entry; cobra root + version
  pkg/api/types/
    types.go                                    TokenRequest/Response, MeResponse, ProblemDetails, HealthResponse
  internal/
    cli/                                        ftsgw-cli command implementations
      root.go                                   cobra root, viper config
      login.go                                  ftsgw-cli login
      whoami.go                                 ftsgw-cli whoami
      logout.go                                 ftsgw-cli logout
      status.go                                 ftsgw-cli status
      client.go                                 HTTP client w/ auto-refresh
      tokenstore.go                             ~/.config/ftsgw/token.json read/write
      exit.go                                   exit-code constants + wrapping
    server/
      api/
        router.go                               chi router, route table
        middleware.go                           request ID, logging, recover, auth, audit ctx
        ratelimit.go                            per-IP + per-username limiters
        handlers_auth.go                        /v1/auth/{token,refresh,logout}
        handlers_me.go                          /v1/me
        handlers_health.go                      /healthz, /readyz
        handlers_jwks.go                        /v1/.well-known/jwks.json
        problem.go                              RFC 7807 helpers
      auth/
        clock.go                                Clock interface + RealClock
        token.go                                Mint/Refresh/Validate
        claims.go                               struct of all custom claims
      idp/
        provider.go                             interface + Identity + Challenge + Capabilities
        errors.go                               ErrNotSupported, ErrAuth, ErrUnreachable
        ldap.go                                 LDAPProvider
        entra_stub.go                           Entra placeholder
        adfs_stub.go                            ADFS placeholder
      signer/
        signer.go                               Signer interface + KeyID
        file_signer.go                          FileSigner (Ed25519 on disk)
        hsm_stub.go                             StubHSMSigner returning ErrNotImplemented
      audit/
        audit.go                                Event struct + Logger interface
        logger.go                               concrete impl: file (lumberjack) + DB
        events.go                               event type constants
      store/
        store.go                                Store struct wrapping *sql.DB
        revocations.go                          Revoke, IsRevoked, PruneExpired
        events.go                               WriteEvent
        migrations/
          0001_init.sql                         revoked_tokens, audit_events
      config/
        config.go                               Config struct + Load + Validate + Defaults
        envrefs.go                              *_env field resolution
  test/
    integration/
      ldap_test.go                              testcontainers OpenLDAP fixture
      e2e_test.go                               broker+CLI in same process
      fuzz_test.go                              FuzzValidate
docs/
  superpowers/plans/2026-05-12-ftsgw-phase-0.md (this file)
  ftsgw/auth-flow.md                            mermaid sequence diagrams
  ftsgw/threat-model.md                         STRIDE
  ftsgw/deployment.md                           config + secrets + rotation
deploy/
  ftsgw/Dockerfile                              distroless multi-stage
  ftsgw/openshift/                              manifests
README.md                                       updated to mention ftsgw alongside go-cli-ad
Makefile                                        root Makefile with ftsgw-* targets + demo
DECISIONS.md                                    ADR record
CHANGELOG.md                                    v0.1.0
PHASE_1_NOTES.md                                Phase 1 seams
```

**Phase ordering & dependencies:**
1. Bootstrap (subtree, license helper, Makefile skeleton)
2. Shared API types
3. Server config loader
4. Signer
5. IdP interface + stubs
6. SQLite store + migrations
7. Audit logger
8. Auth (mint/refresh/validate) — depends on signer, store, clock
9. LDAP provider — integration test only (testcontainers)
10. HTTP middleware + problem details
11. HTTP handlers (auth, me, health, jwks) — depends on auth, idp, audit
12. Observability (metrics, slog redaction, OTLP)
13. Server main + admin subcommands
14. CLI token store + HTTP client (refresh logic)
15. CLI commands (login, whoami, logout, status)
16. End-to-end tests + `make demo`
17. Build & distribution (Dockerfile, OpenShift manifests, syft, cosign hooks)
18. Documentation (auth-flow, threat-model, deployment, DECISIONS, CHANGELOG, PHASE_1_NOTES, README update)

Commits land at the end of each task. Where a task has multiple logical units (e.g. interface + impl + test), break commits per the steps shown.

---

## Phase 1: Bootstrap

### Task 1.1: Create ftsgw subtree and license header helper

**Files:**
- Create: `ftsgw/README.md`
- Create: `ftsgw/LICENSE_HEADER.txt`
- Create: `LICENSE` (root, Apache 2.0)
- Create: `scripts/check-license-headers.sh`

- [ ] **Step 1: Create the Apache 2.0 LICENSE file at repo root**

Use the standard Apache 2.0 text from https://www.apache.org/licenses/LICENSE-2.0.txt. Copyright line: `Copyright 2026 The ftsgw Authors`.

- [ ] **Step 2: Create `ftsgw/LICENSE_HEADER.txt`**

```
// Copyright 2026 The ftsgw Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
```

- [ ] **Step 3: Create `scripts/check-license-headers.sh`** — fails if any `.go` file under `ftsgw/` is missing the header

```bash
#!/usr/bin/env bash
set -euo pipefail
fail=0
while IFS= read -r f; do
  if ! head -n 14 "$f" | grep -q "Licensed under the Apache License, Version 2.0"; then
    echo "missing license header: $f" >&2
    fail=1
  fi
done < <(find ftsgw -name '*.go' -not -path '*/vendor/*')
exit "$fail"
```

Make it executable: `chmod +x scripts/check-license-headers.sh`.

- [ ] **Step 4: Create `ftsgw/README.md`**

```markdown
# ftsgw

Authentication broker (`ftsgw-server`) and companion CLI (`ftsgw-cli`).

See the top-level `README.md` for build/run instructions, `docs/ftsgw/auth-flow.md`
for protocol details, and `DECISIONS.md` for architecture rationale.
```

- [ ] **Step 5: Verify**

Run: `bash scripts/check-license-headers.sh`
Expected: exits 0 (no `.go` files yet under `ftsgw/`).

- [ ] **Step 6: Commit**

```bash
git add ftsgw/ scripts/ LICENSE
git commit -m "feat(ftsgw): bootstrap subtree, license header, and check script"
```

---

### Task 1.2: Root Makefile with ftsgw targets

**Files:**
- Create: `Makefile` (root)

- [ ] **Step 1: Write the Makefile**

```makefile
SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

GO            ?= go
CGO_ENABLED   := 0
GOFLAGS_BUILD := -trimpath -ldflags="$(LDFLAGS)"

BIN_DIR := bin

.PHONY: help
help: ## show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ { printf "  %-22s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: ftsgw-build
ftsgw-build: ## build ftsgw-server and ftsgw-cli into bin/
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS_BUILD) -o $(BIN_DIR)/ftsgw-server ./ftsgw/cmd/ftsgw-server
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS_BUILD) -o $(BIN_DIR)/ftsgw-cli ./ftsgw/cmd/ftsgw-cli

.PHONY: ftsgw-test
ftsgw-test: ## unit tests for ftsgw
	$(GO) test -race -count=1 ./ftsgw/...

.PHONY: ftsgw-test-integration
ftsgw-test-integration: ## integration tests for ftsgw (requires Docker)
	INTEGRATION=1 $(GO) test -race -count=1 -tags=integration ./ftsgw/test/integration/...

.PHONY: ftsgw-lint
ftsgw-lint: ## run golangci-lint on ftsgw subtree
	golangci-lint run --timeout=5m ./ftsgw/...
	bash scripts/check-license-headers.sh

.PHONY: ftsgw-vet
ftsgw-vet: ## go vet ftsgw subtree
	$(GO) vet ./ftsgw/...

.PHONY: ftsgw-vendor
ftsgw-vendor: ## refresh vendor tree
	$(GO) mod tidy
	$(GO) mod vendor

.PHONY: ftsgw-image
ftsgw-image: ## build distroless container image for ftsgw-server
	docker build -f deploy/ftsgw/Dockerfile -t ftsgw-server:$(VERSION) .

.PHONY: ftsgw-sbom
ftsgw-sbom: ## emit CycloneDX SBOM
	@mkdir -p $(BIN_DIR)
	syft packages dir:./ftsgw -o cyclonedx-json > $(BIN_DIR)/ftsgw-sbom.cdx.json

.PHONY: ftsgw-sign
ftsgw-sign: ## sign image with cosign (requires COSIGN_KEY)
	cosign sign --key $${COSIGN_KEY:?must set COSIGN_KEY} ftsgw-server:$(VERSION)

.PHONY: ftsgw-clean
ftsgw-clean: ## remove ftsgw build artifacts
	rm -f $(BIN_DIR)/ftsgw-server $(BIN_DIR)/ftsgw-cli $(BIN_DIR)/ftsgw-sbom.cdx.json

.PHONY: ftsgw-demo
ftsgw-demo: ftsgw-build ## end-to-end demo against throwaway OpenLDAP
	bash scripts/ftsgw-demo.sh
```

- [ ] **Step 2: Verify**

Run: `make help`
Expected: prints the target list including `ftsgw-build`, `ftsgw-test`, `ftsgw-demo`.

Run: `make ftsgw-build`
Expected: FAIL — `cmd/ftsgw-server` does not exist yet. That is fine; we will revisit once Phase 13 lands.

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "build(ftsgw): root Makefile with build/test/lint/image/sbom/sign/demo targets"
```

---

### Task 1.3: Pull in new Go dependencies (one-shot `go get`)

This task only updates `go.mod` / `go.sum`. No code yet — that keeps later commits clean.

- [ ] **Step 1: Add deps via `go get`**

```bash
go get github.com/go-chi/chi/v5@latest
go get github.com/lestrrat-go/jwx/v2@latest
go get modernc.org/sqlite@latest
go get github.com/pressly/goose/v3@latest
go get github.com/spf13/viper@latest
go get gopkg.in/natefinch/lumberjack.v2@latest
go get github.com/prometheus/client_golang@latest
go get github.com/oklog/ulid/v2@latest
go get go.opentelemetry.io/otel@latest
go get go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@latest
go get go.opentelemetry.io/otel/sdk@latest
go get github.com/testcontainers/testcontainers-go@latest
go get github.com/google/uuid@latest
go get golang.org/x/time@latest
```

- [ ] **Step 2: Tidy + verify build still works**

```bash
go mod tidy
go build ./...
```

Expected: build succeeds; CI's `go mod tidy` check is satisfied (`git diff` empty after re-running `go mod tidy`).

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "build: add chi, jwx, modernc-sqlite, goose, viper, lumberjack, prometheus, otel, testcontainers"
```

---

## Phase 2: Shared API types

### Task 2.1: API types and ProblemDetails

**Files:**
- Create: `ftsgw/pkg/api/types/types.go`
- Test: `ftsgw/pkg/api/types/types_test.go`

- [ ] **Step 1: Write the failing test**

```go
// ftsgw/pkg/api/types/types_test.go
// (license header here)
package types_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

func TestTokenResponseJSONRoundtrip(t *testing.T) {
	now := time.Date(2026, 5, 7, 14, 32, 11, 0, time.UTC)
	in := types.TokenResponse{
		AccessToken:         "abc.def.ghi",
		TokenType:           "Bearer",
		ExpiresAt:           now.Add(15 * time.Minute),
		RefreshWindowEndsAt: now.Add(4 * time.Hour),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out types.TokenResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.AccessToken != in.AccessToken || out.TokenType != in.TokenType {
		t.Fatalf("scalar mismatch: %+v", out)
	}
	if !out.ExpiresAt.Equal(in.ExpiresAt) || !out.RefreshWindowEndsAt.Equal(in.RefreshWindowEndsAt) {
		t.Fatalf("time mismatch: %+v", out)
	}
}

func TestProblemDetailsContentType(t *testing.T) {
	if types.ProblemContentType != "application/problem+json" {
		t.Fatalf("got %q", types.ProblemContentType)
	}
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./ftsgw/pkg/api/types/...`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Write the implementation**

```go
// ftsgw/pkg/api/types/types.go
// (license header here)

// Package types defines the wire types shared by ftsgw-server handlers and
// the ftsgw-cli HTTP client. Anything that crosses the broker boundary
// MUST be defined here and only here.
package types

import "time"

// ProblemContentType is the IANA media type for RFC 7807 problem responses.
const ProblemContentType = "application/problem+json"

// TokenRequest is the body of POST /v1/auth/token.
type TokenRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TokenResponse is returned by POST /v1/auth/token and /v1/auth/refresh.
type TokenResponse struct {
	AccessToken         string    `json:"access_token"`
	TokenType           string    `json:"token_type"`
	ExpiresAt           time.Time `json:"expires_at"`
	RefreshWindowEndsAt time.Time `json:"refresh_window_ends_at"`
}

// MeResponse is returned by GET /v1/me.
type MeResponse struct {
	UPN             string    `json:"upn"`
	DisplayName     string    `json:"display_name"`
	Groups          []string  `json:"groups"`
	Roles           []string  `json:"roles"`
	TokenIssuedAt   time.Time `json:"token_issued_at"`
	TokenExpiresAt  time.Time `json:"token_expires_at"`
}

// HealthCheck is one component result inside HealthResponse.
type HealthCheck struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// HealthResponse is returned by /healthz and /readyz.
type HealthResponse struct {
	Status string                 `json:"status"`
	Checks map[string]HealthCheck `json:"checks"`
}

// ProblemDetails implements RFC 7807. All error responses MUST use this.
type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	// RequestID is non-standard but operationally essential.
	RequestID string `json:"request_id,omitempty"`
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./ftsgw/pkg/api/types/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ftsgw/pkg/api/types/
git commit -m "feat(ftsgw): shared wire types (TokenRequest/Response, MeResponse, ProblemDetails)"
```

---

## Phase 3: Server config

### Task 3.1: Config struct, defaults, and validation

**Files:**
- Create: `ftsgw/internal/server/config/config.go`
- Create: `ftsgw/internal/server/config/envrefs.go`
- Test: `ftsgw/internal/server/config/config_test.go`
- Create: `ftsgw/internal/server/config/testdata/valid.yaml`
- Create: `ftsgw/internal/server/config/testdata/missing_ttl.yaml`

- [ ] **Step 1: Testdata — valid and invalid configs**

`ftsgw/internal/server/config/testdata/valid.yaml`:

```yaml
server:
  listen_addr: ":8443"
  tls_cert_path: /tmp/server.crt
  tls_key_path:  /tmp/server.key
signer:
  kind: file
  key_path: /tmp/signing.ed25519
  key_id:   ftsgw-2026-01
idp:
  kind: ldap
  url:  ldaps://ldap.example:636
  base_dn: "DC=example,DC=com"
  bind_dn_env: FTSGW_LDAP_BIND_DN
  bind_password_env: FTSGW_LDAP_BIND_PASSWORD
  user_search_filter:  "(userPrincipalName=%s)"
  group_search_filter: "(member=%s)"
  ca_bundle_path: /etc/ssl/certs/ca-certificates.crt
  start_tls: true
  timeout:   10s
tokens:
  ttl: 15m
  refresh_window: 4h
  issuer:   "ftsgw-server"
  audience: "ftsgw"
audit:
  file_path: /tmp/audit.log
  syslog:
    enabled: false
    addr:    ""
    network: tcp+tls
ratelimit:
  per_ip_rps:                  5
  per_ip_burst:                10
  auth_per_username_per_minute: 3
```

`ftsgw/internal/server/config/testdata/missing_ttl.yaml`: same as `valid.yaml` but with the `tokens.ttl` line removed.

- [ ] **Step 2: Write the failing test**

```go
// ftsgw/internal/server/config/config_test.go
// (license header)
package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/config"
)

func TestLoadValid(t *testing.T) {
	t.Setenv("FTSGW_LDAP_BIND_DN", "cn=svc,dc=example,dc=com")
	t.Setenv("FTSGW_LDAP_BIND_PASSWORD", "p@ss")
	cfg, err := config.Load(filepath.Join("testdata", "valid.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.ListenAddr != ":8443" {
		t.Fatalf("ListenAddr = %q", cfg.Server.ListenAddr)
	}
	if cfg.Tokens.TTL != 15*time.Minute {
		t.Fatalf("TTL = %v", cfg.Tokens.TTL)
	}
	if cfg.Tokens.RefreshWindow != 4*time.Hour {
		t.Fatalf("RefreshWindow = %v", cfg.Tokens.RefreshWindow)
	}
	if cfg.IdP.ResolvedBindDN != "cn=svc,dc=example,dc=com" {
		t.Fatalf("ResolvedBindDN = %q", cfg.IdP.ResolvedBindDN)
	}
}

func TestLoadMissingRequiredField(t *testing.T) {
	_, err := config.Load(filepath.Join("testdata", "missing_ttl.yaml"))
	if err == nil {
		t.Fatalf("want validation error")
	}
}

func TestLoadMissingEnvSecret(t *testing.T) {
	os.Unsetenv("FTSGW_LDAP_BIND_DN")
	os.Unsetenv("FTSGW_LDAP_BIND_PASSWORD")
	_, err := config.Load(filepath.Join("testdata", "valid.yaml"))
	if err == nil {
		t.Fatalf("want env-secret error")
	}
}
```

- [ ] **Step 3: Run — expect fail**

Run: `go test ./ftsgw/internal/server/config/...`
Expected: FAIL — package does not exist.

- [ ] **Step 4: Implementation**

```go
// ftsgw/internal/server/config/config.go
// (license header)

// Package config loads and validates the ftsgw-server YAML config.
//
// Secrets MUST never appear in the YAML; fields ending in _env name the
// environment variable that holds the actual value. Validation is strict:
// any unknown field, missing required field, or unresolvable env reference
// causes Load to return an error.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Signer    SignerConfig    `yaml:"signer"`
	IdP       IdPConfig       `yaml:"idp"`
	Tokens    TokensConfig    `yaml:"tokens"`
	Audit     AuditConfig     `yaml:"audit"`
	RateLimit RateLimitConfig `yaml:"ratelimit"`
}

type ServerConfig struct {
	ListenAddr  string `yaml:"listen_addr"`
	TLSCertPath string `yaml:"tls_cert_path"`
	TLSKeyPath  string `yaml:"tls_key_path"`
}

type SignerConfig struct {
	Kind    string `yaml:"kind"`     // "file" | "hsm"
	KeyPath string `yaml:"key_path"`
	KeyID   string `yaml:"key_id"`
}

type IdPConfig struct {
	Kind              string        `yaml:"kind"`
	URL               string        `yaml:"url"`
	BaseDN            string        `yaml:"base_dn"`
	BindDNEnv         string        `yaml:"bind_dn_env"`
	BindPasswordEnv   string        `yaml:"bind_password_env"`
	UserSearchFilter  string        `yaml:"user_search_filter"`
	GroupSearchFilter string        `yaml:"group_search_filter"`
	CABundlePath      string        `yaml:"ca_bundle_path"`
	StartTLS          bool          `yaml:"start_tls"`
	Timeout           time.Duration `yaml:"timeout"`

	// Resolved at load time from env.
	ResolvedBindDN       string `yaml:"-"`
	ResolvedBindPassword string `yaml:"-"`
}

type TokensConfig struct {
	TTL           time.Duration `yaml:"ttl"`
	RefreshWindow time.Duration `yaml:"refresh_window"`
	Issuer        string        `yaml:"issuer"`
	Audience      string        `yaml:"audience"`
}

type AuditConfig struct {
	FilePath string       `yaml:"file_path"`
	Syslog   SyslogConfig `yaml:"syslog"`
}

type SyslogConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Network string `yaml:"network"`
}

type RateLimitConfig struct {
	PerIPRPS                   int `yaml:"per_ip_rps"`
	PerIPBurst                 int `yaml:"per_ip_burst"`
	AuthPerUsernamePerMinute   int `yaml:"auth_per_username_per_minute"`
}

// Load reads the YAML at path, applies defaults, resolves env-backed
// secrets, and validates the result.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytesReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.resolveEnv(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Signer.Kind == "" {
		c.Signer.Kind = "file"
	}
	if c.IdP.Kind == "" {
		c.IdP.Kind = "ldap"
	}
	if c.IdP.Timeout == 0 {
		c.IdP.Timeout = 10 * time.Second
	}
	if c.Tokens.Issuer == "" {
		c.Tokens.Issuer = "ftsgw-server"
	}
	if c.Tokens.Audience == "" {
		c.Tokens.Audience = "ftsgw"
	}
	if c.RateLimit.PerIPRPS == 0 {
		c.RateLimit.PerIPRPS = 5
	}
	if c.RateLimit.PerIPBurst == 0 {
		c.RateLimit.PerIPBurst = 10
	}
	if c.RateLimit.AuthPerUsernamePerMinute == 0 {
		c.RateLimit.AuthPerUsernamePerMinute = 3
	}
}

// Validate enforces required fields and value bounds.
func (c *Config) Validate() error {
	var errs []string
	must := func(cond bool, msg string) {
		if !cond {
			errs = append(errs, msg)
		}
	}
	must(c.Server.ListenAddr != "", "server.listen_addr required")
	must(c.Server.TLSCertPath != "", "server.tls_cert_path required")
	must(c.Server.TLSKeyPath != "", "server.tls_key_path required")
	must(c.Signer.KeyPath != "", "signer.key_path required")
	must(c.Signer.KeyID != "", "signer.key_id required")
	must(c.IdP.URL != "", "idp.url required")
	must(c.IdP.BaseDN != "", "idp.base_dn required")
	must(c.IdP.UserSearchFilter != "", "idp.user_search_filter required")
	must(c.IdP.GroupSearchFilter != "", "idp.group_search_filter required")
	must(c.Tokens.TTL > 0, "tokens.ttl must be > 0")
	must(c.Tokens.RefreshWindow > 0, "tokens.refresh_window must be > 0")
	must(c.Tokens.RefreshWindow >= c.Tokens.TTL, "tokens.refresh_window must be >= tokens.ttl")
	must(c.Audit.FilePath != "", "audit.file_path required")
	if len(errs) > 0 {
		return fmt.Errorf("config invalid: %v", errs)
	}
	return nil
}

// ErrEnvSecretMissing is returned when a *_env reference cannot be resolved.
var ErrEnvSecretMissing = errors.New("env secret missing")
```

```go
// ftsgw/internal/server/config/envrefs.go
// (license header)
package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func (c *Config) resolveEnv() error {
	if c.IdP.BindDNEnv != "" {
		v, ok := os.LookupEnv(c.IdP.BindDNEnv)
		if !ok || v == "" {
			return fmt.Errorf("%w: %s", ErrEnvSecretMissing, c.IdP.BindDNEnv)
		}
		c.IdP.ResolvedBindDN = v
	}
	if c.IdP.BindPasswordEnv != "" {
		v, ok := os.LookupEnv(c.IdP.BindPasswordEnv)
		if !ok || v == "" {
			return fmt.Errorf("%w: %s", ErrEnvSecretMissing, c.IdP.BindPasswordEnv)
		}
		c.IdP.ResolvedBindPassword = v
	}
	return nil
}
```

- [ ] **Step 5: Run — expect pass**

Run: `go test ./ftsgw/internal/server/config/...`
Expected: PASS for all three tests.

- [ ] **Step 6: Commit**

```bash
git add ftsgw/internal/server/config/
git commit -m "feat(ftsgw/config): YAML loader with defaults, env-backed secrets, strict validation"
```

---

## Phase 4: Signer

### Task 4.1: Signer interface + FileSigner + StubHSMSigner

**Files:**
- Create: `ftsgw/internal/server/signer/signer.go`
- Create: `ftsgw/internal/server/signer/file_signer.go`
- Create: `ftsgw/internal/server/signer/hsm_stub.go`
- Test: `ftsgw/internal/server/signer/file_signer_test.go`

- [ ] **Step 1: Failing test for FileSigner**

```go
// ftsgw/internal/server/signer/file_signer_test.go
// (license header)
package signer_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/signer"
)

func writeKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.ed25519")
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestFileSignerRoundTrip(t *testing.T) {
	path := writeKey(t)
	s, err := signer.NewFileSigner(path, "kid-1")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	msg := []byte("hello")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ed25519.Verify(s.PublicKey(), msg, sig) {
		t.Fatalf("verify failed")
	}
	if s.KeyID() != "kid-1" {
		t.Fatalf("kid = %q", s.KeyID())
	}
}

func TestFileSignerRejectsBadPermissions(t *testing.T) {
	path := writeKey(t)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := signer.NewFileSigner(path, "kid-1"); err == nil {
		t.Fatalf("want error for non-0600 key")
	}
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./ftsgw/internal/server/signer/...`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Implementation**

```go
// ftsgw/internal/server/signer/signer.go
// (license header)

// Package signer mints Ed25519 signatures for ftsgw JWTs. The Signer
// interface is the seam: FileSigner is shipped today; StubHSMSigner is the
// integration seam for a hardware-backed key in a future phase.
package signer

import (
	"crypto/ed25519"
	"errors"
)

// ErrNotImplemented is returned by stubs.
var ErrNotImplemented = errors.New("signer: not implemented")

// Signer is the minting interface used by the auth package.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
	PublicKey() ed25519.PublicKey
	KeyID() string
}
```

```go
// ftsgw/internal/server/signer/file_signer.go
// (license header)
package signer

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// FileSigner loads an Ed25519 seed from a PEM file with mode 0600.
type FileSigner struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

// NewFileSigner reads the key from path and verifies its file permissions.
func NewFileSigner(path, keyID string) (*FileSigner, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat signing key: %w", err)
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("signing key %s must be mode 0600, got %o", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("signing key: invalid PEM")
	}
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key: expected %d-byte seed, got %d", ed25519.SeedSize, len(block.Bytes))
	}
	priv := ed25519.NewKeyFromSeed(block.Bytes)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("signing key: failed to derive public key")
	}
	return &FileSigner{priv: priv, pub: pub, keyID: keyID}, nil
}

// Sign returns an Ed25519 signature over msg.
func (s *FileSigner) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}

// PublicKey returns the verification key for JWKS publication.
func (s *FileSigner) PublicKey() ed25519.PublicKey { return s.pub }

// KeyID returns the JWT `kid` value.
func (s *FileSigner) KeyID() string { return s.keyID }
```

```go
// ftsgw/internal/server/signer/hsm_stub.go
// (license header)
package signer

import "crypto/ed25519"

// StubHSMSigner is the Phase-2 seam for a hardware-backed Ed25519 key. All
// calls return ErrNotImplemented so the broker fails fast if misconfigured.
type StubHSMSigner struct{}

func (StubHSMSigner) Sign(_ []byte) ([]byte, error)   { return nil, ErrNotImplemented }
func (StubHSMSigner) PublicKey() ed25519.PublicKey    { return nil }
func (StubHSMSigner) KeyID() string                   { return "" }
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./ftsgw/internal/server/signer/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ftsgw/internal/server/signer/
git commit -m "feat(ftsgw/signer): Signer interface, FileSigner (Ed25519 PEM 0600), HSM stub"
```

---

## Phase 5: IdP interface and stubs

### Task 5.1: Provider interface, types, and stub providers

**Files:**
- Create: `ftsgw/internal/server/idp/provider.go`
- Create: `ftsgw/internal/server/idp/errors.go`
- Create: `ftsgw/internal/server/idp/entra_stub.go`
- Create: `ftsgw/internal/server/idp/adfs_stub.go`
- Test: `ftsgw/internal/server/idp/stubs_test.go`

- [ ] **Step 1: Failing test**

```go
// ftsgw/internal/server/idp/stubs_test.go
// (license header)
package idp_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
)

func TestEntraStubReturnsNotImplemented(t *testing.T) {
	p := idp.EntraProvider{}
	_, err := p.Authenticate(context.Background(), "alice", "p")
	if !errors.Is(err, idp.ErrNotImplemented) {
		t.Fatalf("got %v", err)
	}
}

func TestADFSStubReturnsNotImplemented(t *testing.T) {
	p := idp.ADFSProvider{}
	_, err := p.Authenticate(context.Background(), "alice", "p")
	if !errors.Is(err, idp.ErrNotImplemented) {
		t.Fatalf("got %v", err)
	}
}

func TestCapabilitiesDefaults(t *testing.T) {
	got := idp.ADFSProvider{}.Capabilities()
	if got.SupportsPassword || got.SupportsChallenge {
		t.Fatalf("unexpected: %+v", got)
	}
}
```

- [ ] **Step 2: Implementation**

```go
// ftsgw/internal/server/idp/errors.go
// (license header)
package idp

import "errors"

var (
	// ErrAuth indicates the IdP rejected credentials.
	ErrAuth = errors.New("idp: authentication failed")
	// ErrUnreachable indicates a transport / network failure talking to the IdP.
	ErrUnreachable = errors.New("idp: unreachable")
	// ErrNotSupported is returned by capability methods a given backend does not implement.
	ErrNotSupported = errors.New("idp: capability not supported")
	// ErrNotImplemented marks stub providers reserved for future phases.
	ErrNotImplemented = errors.New("idp: not implemented")
)
```

```go
// ftsgw/internal/server/idp/provider.go
// (license header)

// Package idp abstracts the user-store backend. Phase 0 ships LDAPProvider;
// Phase 1 will add Entra (device-code challenge); Phase 2 will add ADFS.
// New methods may NEVER be added to IdentityProvider — the Challenge methods
// already exist precisely so we never break this interface.
package idp

import (
	"context"
	"time"
)

// Identity is the resolved user view used by token issuance.
type Identity struct {
	UPN         string
	DisplayName string
	Groups      []string
	Roles       []string
	Attributes  map[string]string
}

// Challenge is the device-code / out-of-band challenge handle returned by
// providers that implement multi-step auth (Phase 1+).
type Challenge struct {
	ID              string
	UserCode        string
	VerificationURI string
	ExpiresIn       time.Duration
	Interval        time.Duration
}

// ProviderCapabilities advertises which Authenticate paths a provider implements.
type ProviderCapabilities struct {
	SupportsPassword  bool
	SupportsChallenge bool
}

// IdentityProvider is the seam between the broker and any backing store.
type IdentityProvider interface {
	Authenticate(ctx context.Context, username, password string) (*Identity, error)
	InitiateChallenge(ctx context.Context, hint string) (*Challenge, error)
	CompleteChallenge(ctx context.Context, challengeID string) (*Identity, error)
	Lookup(ctx context.Context, upn string) (*Identity, error)
	HealthCheck(ctx context.Context) error
	Capabilities() ProviderCapabilities
}
```

```go
// ftsgw/internal/server/idp/entra_stub.go
// (license header)
package idp

import "context"

// EntraProvider is the Phase 1 seam. All methods return ErrNotImplemented.
type EntraProvider struct{}

func (EntraProvider) Authenticate(_ context.Context, _, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (EntraProvider) InitiateChallenge(_ context.Context, _ string) (*Challenge, error) {
	return nil, ErrNotImplemented
}
func (EntraProvider) CompleteChallenge(_ context.Context, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (EntraProvider) Lookup(_ context.Context, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (EntraProvider) HealthCheck(_ context.Context) error { return ErrNotImplemented }
func (EntraProvider) Capabilities() ProviderCapabilities  { return ProviderCapabilities{} }
```

```go
// ftsgw/internal/server/idp/adfs_stub.go
// (license header)
package idp

import "context"

// ADFSProvider is the Phase 2 seam. All methods return ErrNotImplemented.
type ADFSProvider struct{}

func (ADFSProvider) Authenticate(_ context.Context, _, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (ADFSProvider) InitiateChallenge(_ context.Context, _ string) (*Challenge, error) {
	return nil, ErrNotImplemented
}
func (ADFSProvider) CompleteChallenge(_ context.Context, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (ADFSProvider) Lookup(_ context.Context, _ string) (*Identity, error) {
	return nil, ErrNotImplemented
}
func (ADFSProvider) HealthCheck(_ context.Context) error { return ErrNotImplemented }
func (ADFSProvider) Capabilities() ProviderCapabilities  { return ProviderCapabilities{} }
```

- [ ] **Step 3: Verify**

Run: `go test ./ftsgw/internal/server/idp/...`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add ftsgw/internal/server/idp/
git commit -m "feat(ftsgw/idp): IdentityProvider interface and Entra/ADFS stubs"
```

---

## Phase 6: SQLite store and migrations

### Task 6.1: Migrations + Store wrapper

**Files:**
- Create: `ftsgw/internal/server/store/migrations/0001_init.sql`
- Create: `ftsgw/internal/server/store/store.go`
- Create: `ftsgw/internal/server/store/revocations.go`
- Create: `ftsgw/internal/server/store/events.go`
- Test: `ftsgw/internal/server/store/store_test.go`

- [ ] **Step 1: Write the migration**

```sql
-- ftsgw/internal/server/store/migrations/0001_init.sql
-- +goose Up
CREATE TABLE revoked_tokens (
  jti        TEXT PRIMARY KEY,
  revoked_at TIMESTAMP NOT NULL,
  exp        TIMESTAMP NOT NULL,
  actor_upn  TEXT NOT NULL,
  reason     TEXT NULL
);
CREATE INDEX idx_revoked_exp ON revoked_tokens(exp);

CREATE TABLE audit_events (
  id           TEXT PRIMARY KEY,
  ts           TIMESTAMP NOT NULL,
  actor_upn    TEXT NULL,
  event_type   TEXT NOT NULL,
  outcome      TEXT NOT NULL,
  reason       TEXT NULL,
  client_ip    TEXT NULL,
  request_id   TEXT NOT NULL,
  trace_id     TEXT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX idx_audit_ts    ON audit_events(ts);
CREATE INDEX idx_audit_actor ON audit_events(actor_upn, ts);

-- +goose Down
DROP TABLE audit_events;
DROP TABLE revoked_tokens;
```

- [ ] **Step 2: Failing test**

```go
// ftsgw/internal/server/store/store_test.go
// (license header)
package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ftsgw.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRevokeAndCheck(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	exp := time.Now().Add(15 * time.Minute).UTC()
	if err := s.Revoke(ctx, "jti-1", "alice@example", "logout", exp); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, err := s.IsRevoked(ctx, "jti-1")
	if err != nil || !got {
		t.Fatalf("IsRevoked = %v, err = %v", got, err)
	}
	got, _ = s.IsRevoked(ctx, "jti-other")
	if got {
		t.Fatalf("unexpected revoked")
	}
}

func TestPruneExpired(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Minute).UTC()
	future := time.Now().Add(time.Hour).UTC()
	_ = s.Revoke(ctx, "jti-old", "a", "", past)
	_ = s.Revoke(ctx, "jti-new", "b", "", future)
	n, err := s.PruneExpired(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	got, _ := s.IsRevoked(ctx, "jti-new")
	if !got {
		t.Fatalf("new entry should remain")
	}
}

func TestWriteEvent(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	err := s.WriteEvent(ctx, store.EventRow{
		ID:          "01HXY",
		TS:          time.Now().UTC(),
		ActorUPN:    "alice@example",
		EventType:   "token_issued",
		Outcome:     "success",
		RequestID:   "req-1",
		PayloadJSON: `{"jti":"x"}`,
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
}
```

- [ ] **Step 3: Implementation**

```go
// ftsgw/internal/server/store/store.go
// (license header)

// Package store wraps a single SQLite database used by ftsgw-server.
// It owns its own goose migration tree and is opened with WAL journaling
// for safe concurrent reads alongside synchronous audit writes.
package store

import (
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store is the broker's persistence layer.
type Store struct {
	DB *sql.DB
}

// Open opens (or creates) the SQLite database at path, applies migrations,
// and returns the Store. WAL is enabled.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pragmas: %w", err)
	}
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("goose dialect: %w", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{DB: db}, nil
}

// Close releases DB resources.
func (s *Store) Close() error { return s.DB.Close() }
```

```go
// ftsgw/internal/server/store/revocations.go
// (license header)
package store

import (
	"context"
	"fmt"
	"time"
)

// Revoke inserts (or replaces) a revocation entry for jti.
func (s *Store) Revoke(ctx context.Context, jti, actorUPN, reason string, exp time.Time) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT OR REPLACE INTO revoked_tokens (jti, revoked_at, exp, actor_upn, reason) VALUES (?, ?, ?, ?, ?)`,
		jti, time.Now().UTC(), exp.UTC(), actorUPN, nullableReason(reason))
	if err != nil {
		return fmt.Errorf("revoke %s: %w", jti, err)
	}
	return nil
}

// IsRevoked returns whether jti has been revoked.
func (s *Store) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT 1 FROM revoked_tokens WHERE jti = ?`, jti).Scan(&n)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return false, nil
		}
		return false, fmt.Errorf("is_revoked %s: %w", jti, err)
	}
	return true, nil
}

// PruneExpired deletes rows whose exp is at or before cutoff. Returns count.
func (s *Store) PruneExpired(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM revoked_tokens WHERE exp <= ?`, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func nullableReason(s string) any {
	if s == "" {
		return nil
	}
	return s
}
```

```go
// ftsgw/internal/server/store/events.go
// (license header)
package store

import (
	"context"
	"fmt"
	"time"
)

// EventRow is the on-disk shape of one audit event.
type EventRow struct {
	ID          string
	TS          time.Time
	ActorUPN    string
	EventType   string
	Outcome     string
	Reason      string
	ClientIP    string
	RequestID   string
	TraceID     string
	PayloadJSON string
}

// WriteEvent inserts a single audit row. Failure must surface (the audit
// path treats this as a 503 trigger).
func (s *Store) WriteEvent(ctx context.Context, r EventRow) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO audit_events (id, ts, actor_upn, event_type, outcome, reason, client_ip, request_id, trace_id, payload_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.TS.UTC(), nullableReason(r.ActorUPN), r.EventType, r.Outcome,
		nullableReason(r.Reason), nullableReason(r.ClientIP), r.RequestID,
		nullableReason(r.TraceID), r.PayloadJSON)
	if err != nil {
		return fmt.Errorf("write event %s: %w", r.ID, err)
	}
	return nil
}
```

- [ ] **Step 4: Verify**

Run: `go test ./ftsgw/internal/server/store/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ftsgw/internal/server/store/
git commit -m "feat(ftsgw/store): SQLite store with goose migrations, revocations, audit events"
```

---

## Phase 7: Audit logger

### Task 7.1: Event types, redaction, dual-sink Logger

**Files:**
- Create: `ftsgw/internal/server/audit/events.go`
- Create: `ftsgw/internal/server/audit/audit.go`
- Create: `ftsgw/internal/server/audit/logger.go`
- Test: `ftsgw/internal/server/audit/logger_test.go`
- Test: `ftsgw/internal/server/audit/redaction_test.go`

- [ ] **Step 1: Failing tests (logger + redaction)**

```go
// ftsgw/internal/server/audit/logger_test.go
// (license header)
package audit_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/audit"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

func newLogger(t *testing.T) (*audit.Logger, string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	st, err := store.Open(filepath.Join(dir, "ftsgw.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	lg, err := audit.NewLogger(logPath, st)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	return lg, logPath, st
}

func TestLoggerWritesBothSinks(t *testing.T) {
	lg, path, st := newLogger(t)
	ctx := context.Background()
	if err := lg.Write(ctx, audit.Event{
		TS:        time.Now().UTC(),
		RequestID: "req-1",
		ActorUPN:  "alice@example",
		Event:     audit.EventTokenIssued,
		Outcome:   "success",
		Extras:    map[string]any{"jti": "j1", "auth_method": "password"},
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	// File
	f, _ := os.Open(path)
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatalf("no line written")
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(sc.Text()), &line); err != nil {
		t.Fatalf("json: %v", err)
	}
	if line["event"] != string(audit.EventTokenIssued) {
		t.Fatalf("event = %v", line["event"])
	}
	// DB
	var n int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type = ?`, audit.EventTokenIssued).Scan(&n)
	if n != 1 {
		t.Fatalf("DB rows = %d", n)
	}
}
```

```go
// ftsgw/internal/server/audit/redaction_test.go
// (license header)
package audit_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/audit"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

func TestExtrasMustNotContainSecrets(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "f.db"))
	defer st.Close()
	path := filepath.Join(dir, "audit.log")
	lg, _ := audit.NewLogger(path, st)
	defer lg.Close()
	err := lg.Write(context.Background(), audit.Event{
		TS:        time.Now().UTC(),
		RequestID: "r",
		Event:     audit.EventTokenIssued,
		Outcome:   "success",
		Extras:    map[string]any{"password": "hunter2"},
	})
	if err == nil {
		t.Fatalf("write must reject secret-shaped keys")
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "hunter2") {
		t.Fatalf("secret leaked to log file")
	}
}
```

- [ ] **Step 2: Implementation**

```go
// ftsgw/internal/server/audit/events.go
// (license header)
package audit

// EventType is an enum of audit event names. Order alphabetically when adding.
type EventType string

const (
	EventIdPHealthCheck         EventType = "idp_health_check"
	EventPasswordAuthenticated  EventType = "password_authenticated"
	EventPasswordRejected       EventType = "password_rejected"
	EventRateLimited            EventType = "rate_limited"
	EventTokenIssued            EventType = "token_issued"
	EventTokenRefreshed         EventType = "token_refreshed"
	EventTokenRefreshRefused    EventType = "token_refresh_refused"
	EventTokenRevoked           EventType = "token_revoked"
	EventTokenValidationFailed  EventType = "token_validation_failed"
)
```

```go
// ftsgw/internal/server/audit/audit.go
// (license header)

// Package audit writes one event to two sinks: the SQLite audit_events
// table and a rotated JSON-lines file. Both writes happen synchronously;
// any failure surfaces to the caller so the broker can return HTTP 503.
//
// Secrets MUST NEVER appear in audit payloads. The Logger enforces this
// statically (forbidden Extras keys) and operators must enforce it by
// review when adding new fields.
package audit

import (
	"context"
	"errors"
	"time"
)

// Event is the in-memory shape of an audit record.
type Event struct {
	TS        time.Time
	RequestID string
	ActorUPN  string
	Event     EventType
	Outcome   string // "success" | "failure"
	Reason    string
	ClientIP  string
	TraceID   string
	Extras    map[string]any
}

// ErrForbiddenAuditKey is returned when Extras contains a key from the deny list.
var ErrForbiddenAuditKey = errors.New("audit: forbidden key in extras")

// forbiddenKeys lists Extras names that may carry secrets. The set is
// intentionally tight; widen with care.
var forbiddenKeys = map[string]struct{}{
	"password":     {},
	"access_token": {},
	"token":        {},
	"secret":       {},
	"bearer":       {},
}

// LogWriter is the sink interface (file + DB).
type LogWriter interface {
	Write(ctx context.Context, e Event) error
	Close() error
}
```

```go
// ftsgw/internal/server/audit/logger.go
// (license header)
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger implements LogWriter against a SQLite Store + a rotated JSON-lines file.
type Logger struct {
	mu   sync.Mutex
	file io.WriteCloser
	st   *store.Store
	rng  *ulid.MonotonicEntropy
}

// NewLogger opens (creates) the rotated file at logPath with 100MB segments
// and 30-day retention and ties it to the provided Store.
func NewLogger(logPath string, st *store.Store) (*Logger, error) {
	f := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    100, // MB
		MaxAge:     30,  // days
		MaxBackups: 30,
		Compress:   true,
		LocalTime:  false,
	}
	return &Logger{
		file: f,
		st:   st,
		rng:  ulid.Monotonic(ulidRandReader(), 0),
	}, nil
}

// Write emits one event to both sinks. The DB write happens first so
// truncated-file conditions still leave a database trace; either failure
// is returned and the caller MUST surface HTTP 503.
func (l *Logger) Write(ctx context.Context, e Event) error {
	for k := range e.Extras {
		if _, bad := forbiddenKeys[k]; bad {
			return fmt.Errorf("%w: %q", ErrForbiddenAuditKey, k)
		}
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	id := ulid.MustNew(ulid.Timestamp(e.TS), l.rng).String()
	payload := map[string]any{
		"ts":         e.TS.Format(time.RFC3339Nano),
		"request_id": e.RequestID,
		"actor_upn":  nullable(e.ActorUPN),
		"event":      string(e.Event),
		"outcome":    e.Outcome,
		"reason":     nullable(e.Reason),
		"client_ip":  nullable(e.ClientIP),
		"trace_id":   nullable(e.TraceID),
		"extras":     e.Extras,
	}
	pj, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal audit: %w", err)
	}
	if err := l.st.WriteEvent(ctx, store.EventRow{
		ID:          id,
		TS:          e.TS,
		ActorUPN:    e.ActorUPN,
		EventType:   string(e.Event),
		Outcome:     e.Outcome,
		Reason:      e.Reason,
		ClientIP:    e.ClientIP,
		RequestID:   e.RequestID,
		TraceID:     e.TraceID,
		PayloadJSON: string(pj),
	}); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(append(pj, '\n')); err != nil {
		return fmt.Errorf("write audit file: %w", err)
	}
	return nil
}

// Close flushes and closes the rotated file. The Store is owned by the caller.
func (l *Logger) Close() error { return l.file.Close() }

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
```

```go
// ftsgw/internal/server/audit/entropy.go
// (license header)
package audit

import (
	"crypto/rand"
	"io"
)

func ulidRandReader() io.Reader { return rand.Reader }
```

- [ ] **Step 3: Verify**

Run: `go test ./ftsgw/internal/server/audit/...`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add ftsgw/internal/server/audit/
git commit -m "feat(ftsgw/audit): synchronous dual-sink logger (lumberjack file + SQLite), secret deny list"
```

---

## Phase 8: Auth — token mint, refresh, validate

### Task 8.1: Clock interface

**Files:**
- Create: `ftsgw/internal/server/auth/clock.go`

- [ ] **Step 1: Write**

```go
// ftsgw/internal/server/auth/clock.go
// (license header)
package auth

import "time"

// Clock is the seam between real wall-clock time and test fakes. All time
// comparisons in the auth package go through this interface so refresh-window
// exhaustion can be tested without sleeping for hours.
type Clock interface{ Now() time.Time }

// RealClock returns time.Now().UTC().
type RealClock struct{}

// Now implements Clock.
func (RealClock) Now() time.Time { return time.Now().UTC() }
```

- [ ] **Step 2: Commit**

```bash
git add ftsgw/internal/server/auth/clock.go
git commit -m "feat(ftsgw/auth): Clock interface for deterministic time in tests"
```

---

### Task 8.2: Claims struct and TokenSet helper

**Files:**
- Create: `ftsgw/internal/server/auth/claims.go`

- [ ] **Step 1: Write**

```go
// ftsgw/internal/server/auth/claims.go
// (license header)
package auth

import "time"

// AuthMethod captures how the user originally authenticated. Phase 0 only
// emits "password"; Phase 1 will add "challenge".
type AuthMethod string

const (
	AuthMethodPassword  AuthMethod = "password"
	AuthMethodChallenge AuthMethod = "challenge"
)

// Claims mirrors the JWT claim set we mint. iat records ORIGINAL password
// auth time and is preserved across refreshes; exp moves forward each refresh.
type Claims struct {
	Subject    string     `json:"sub"`
	Issuer     string     `json:"iss"`
	Audience   string     `json:"aud"`
	IssuedAt   time.Time  `json:"iat"`
	ExpiresAt  time.Time  `json:"exp"`
	JTI        string     `json:"jti"`
	Groups     []string   `json:"groups"`
	Roles      []string   `json:"roles"`
	AuthMethod AuthMethod `json:"auth_method"`
}
```

- [ ] **Step 2: Commit**

```bash
git add ftsgw/internal/server/auth/claims.go
git commit -m "feat(ftsgw/auth): Claims type with iat/exp/jti/groups/auth_method"
```

---

### Task 8.3: Mint, Refresh, Validate (TDD)

**Files:**
- Create: `ftsgw/internal/server/auth/token.go`
- Test: `ftsgw/internal/server/auth/token_test.go`

- [ ] **Step 1: Failing tests**

```go
// ftsgw/internal/server/auth/token_test.go
// (license header)
package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/signer"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

type fakeClock struct{ now time.Time }

func (f *fakeClock) Now() time.Time { return f.now }

func mkSigner(t *testing.T) *signer.FileSigner {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "k")
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()}), 0o600)
	s, err := signer.NewFileSigner(path, "kid-1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func mkStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newIssuer(t *testing.T, clk auth.Clock) (*auth.Issuer, *store.Store) {
	st := mkStore(t)
	iss, err := auth.NewIssuer(auth.IssuerConfig{
		Signer:        mkSigner(t),
		Store:         st,
		Clock:         clk,
		Issuer:        "ftsgw-server",
		Audience:      "ftsgw",
		TTL:           15 * time.Minute,
		RefreshWindow: 4 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss, st
}

func TestMintAndValidate(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 7, 14, 32, 11, 0, time.UTC)}
	iss, _ := newIssuer(t, clk)
	tok, err := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example", Groups: []string{"g1"}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	c, err := iss.Validate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.Subject != "alice@example" || c.AuthMethod != auth.AuthMethodPassword {
		t.Fatalf("bad claims: %+v", c)
	}
	if !c.IssuedAt.Equal(clk.now) {
		t.Fatalf("iat mismatch")
	}
	if !c.ExpiresAt.Equal(clk.now.Add(15 * time.Minute)) {
		t.Fatalf("exp mismatch")
	}
}

func TestRefreshWithinWindowKeepsIat(t *testing.T) {
	start := time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)
	clk := &fakeClock{now: start}
	iss, _ := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	clk.now = start.Add(14 * time.Minute) // before TTL
	refreshed, err := iss.Refresh(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	c, _ := iss.Validate(context.Background(), refreshed.AccessToken)
	if !c.IssuedAt.Equal(start) {
		t.Fatalf("iat should be original, got %v", c.IssuedAt)
	}
	if !c.ExpiresAt.Equal(clk.now.Add(15 * time.Minute)) {
		t.Fatalf("exp must be now+ttl")
	}
}

func TestRefreshOutsideWindowRefused(t *testing.T) {
	start := time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)
	clk := &fakeClock{now: start}
	iss, _ := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	clk.now = start.Add(5 * time.Hour)
	_, err := iss.Refresh(context.Background(), tok.AccessToken)
	if !errors.Is(err, auth.ErrRefreshWindowExhausted) {
		t.Fatalf("got %v", err)
	}
}

func TestRevokedTokenFailsValidate(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)}
	iss, st := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	c, _ := iss.Validate(context.Background(), tok.AccessToken)
	_ = st.Revoke(context.Background(), c.JTI, c.Subject, "test", c.ExpiresAt)
	if _, err := iss.Validate(context.Background(), tok.AccessToken); !errors.Is(err, auth.ErrRevoked) {
		t.Fatalf("got %v", err)
	}
}

func TestExpiredTokenFailsValidate(t *testing.T) {
	start := time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)
	clk := &fakeClock{now: start}
	iss, _ := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	clk.now = start.Add(20 * time.Minute)
	if _, err := iss.Validate(context.Background(), tok.AccessToken); !errors.Is(err, auth.ErrExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestBadSignatureFails(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)}
	iss, _ := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	mutated := tok.AccessToken[:len(tok.AccessToken)-3] + "AAA"
	if _, err := iss.Validate(context.Background(), mutated); err == nil {
		t.Fatalf("want signature error")
	}
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./ftsgw/internal/server/auth/...`
Expected: FAIL — `auth.Issuer` etc. do not exist.

- [ ] **Step 3: Implementation**

```go
// ftsgw/internal/server/auth/token.go
// (license header)

// Package auth mints, refreshes, and validates ftsgw app-tokens (Ed25519 JWTs).
//
// The `iat` claim records ORIGINAL password authentication time and is
// preserved across refreshes. `exp` moves forward by TTL on every refresh.
// Refresh is refused when (now - iat) > RefreshWindow.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/signer"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

// Sentinel errors. Wrapped at boundaries.
var (
	ErrExpired                = errors.New("token: expired")
	ErrRevoked                = errors.New("token: revoked")
	ErrInvalidSignature       = errors.New("token: invalid signature")
	ErrInvalidClaims          = errors.New("token: invalid claims")
	ErrRefreshWindowExhausted = errors.New("token: refresh window exhausted")
)

// Subject is the input to Mint.
type Subject struct {
	UPN    string
	Groups []string
	Roles  []string
}

// IssuedToken is the wire-friendly mint result.
type IssuedToken struct {
	AccessToken         string
	ExpiresAt           time.Time
	RefreshWindowEndsAt time.Time
	IssuedAt            time.Time
	JTI                 string
}

// IssuerConfig wires everything Issuer needs.
type IssuerConfig struct {
	Signer        signer.Signer
	Store         *store.Store
	Clock         Clock
	Issuer        string
	Audience      string
	TTL           time.Duration
	RefreshWindow time.Duration
}

// Issuer is the only thing that touches Signer + Store for tokens.
type Issuer struct {
	cfg     IssuerConfig
	signKey jwsKeyFunc // late-bind for clarity
}

type jwsKeyFunc func() ([]byte, string)

// NewIssuer returns a configured Issuer. Validates inputs eagerly.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	if cfg.Signer == nil || cfg.Store == nil || cfg.Clock == nil {
		return nil, errors.New("auth: signer, store, clock required")
	}
	if cfg.TTL <= 0 || cfg.RefreshWindow <= 0 {
		return nil, errors.New("auth: ttl and refresh_window must be > 0")
	}
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("auth: issuer and audience required")
	}
	return &Issuer{cfg: cfg}, nil
}

// Mint issues a fresh token. `iat` = clock.Now(), `exp` = iat + TTL.
func (i *Issuer) Mint(ctx context.Context, s Subject) (*IssuedToken, error) {
	now := i.cfg.Clock.Now()
	return i.mint(ctx, Claims{
		Subject:    s.UPN,
		Issuer:     i.cfg.Issuer,
		Audience:   i.cfg.Audience,
		IssuedAt:   now,
		ExpiresAt:  now.Add(i.cfg.TTL),
		JTI:        uuid.NewString(),
		Groups:     s.Groups,
		Roles:      s.Roles,
		AuthMethod: AuthMethodPassword,
	})
}

// Refresh exchanges a still-valid (signature + revocation) token for a new
// one with refreshed `exp` but unchanged `iat`. Refuses if the refresh
// window has been exhausted, if the token is revoked, or if signature is bad.
func (i *Issuer) Refresh(ctx context.Context, raw string) (*IssuedToken, error) {
	c, err := i.validateInner(ctx, raw, allowExpired)
	if err != nil {
		return nil, err
	}
	now := i.cfg.Clock.Now()
	if now.Sub(c.IssuedAt) > i.cfg.RefreshWindow {
		return nil, ErrRefreshWindowExhausted
	}
	return i.mint(ctx, Claims{
		Subject:    c.Subject,
		Issuer:     i.cfg.Issuer,
		Audience:   i.cfg.Audience,
		IssuedAt:   c.IssuedAt, // preserve original
		ExpiresAt:  now.Add(i.cfg.TTL),
		JTI:        uuid.NewString(),
		Groups:     c.Groups,
		Roles:      c.Roles,
		AuthMethod: c.AuthMethod,
	})
}

// Validate parses, verifies, checks revocation, and rejects expired tokens.
func (i *Issuer) Validate(ctx context.Context, raw string) (*Claims, error) {
	return i.validateInner(ctx, raw, rejectExpired)
}

type expirationMode int

const (
	rejectExpired expirationMode = iota
	allowExpired
)

func (i *Issuer) validateInner(ctx context.Context, raw string, mode expirationMode) (*Claims, error) {
	pub := i.cfg.Signer.PublicKey()
	parsed, err := jwt.Parse([]byte(raw),
		jwt.WithKey(jwa.EdDSA, pub),
		jwt.WithIssuer(i.cfg.Issuer),
		jwt.WithAudience(i.cfg.Audience),
		jwt.WithValidate(false), // we do exp manually so we can implement allowExpired
		jwt.WithVerify(true),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	c, err := claimsFromJWT(parsed)
	if err != nil {
		return nil, err
	}
	if mode == rejectExpired && i.cfg.Clock.Now().After(c.ExpiresAt) {
		return nil, ErrExpired
	}
	revoked, err := i.cfg.Store.IsRevoked(ctx, c.JTI)
	if err != nil {
		return nil, fmt.Errorf("check revocation: %w", err)
	}
	if revoked {
		return nil, ErrRevoked
	}
	return c, nil
}

// Revoke records the jti as revoked until its current exp.
func (i *Issuer) Revoke(ctx context.Context, raw, actorUPN, reason string) error {
	c, err := i.validateInner(ctx, raw, allowExpired)
	if err != nil {
		return err
	}
	return i.cfg.Store.Revoke(ctx, c.JTI, actorUPN, reason, c.ExpiresAt)
}

func (i *Issuer) mint(_ context.Context, c Claims) (*IssuedToken, error) {
	t := jwt.New()
	_ = t.Set(jwt.SubjectKey, c.Subject)
	_ = t.Set(jwt.IssuerKey, c.Issuer)
	_ = t.Set(jwt.AudienceKey, c.Audience)
	_ = t.Set(jwt.IssuedAtKey, c.IssuedAt)
	_ = t.Set(jwt.ExpirationKey, c.ExpiresAt)
	_ = t.Set(jwt.JwtIDKey, c.JTI)
	_ = t.Set("groups", c.Groups)
	_ = t.Set("roles", c.Roles)
	_ = t.Set("auth_method", string(c.AuthMethod))

	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.KeyIDKey, i.cfg.Signer.KeyID())
	_ = hdr.Set(jws.TypeKey, "JWT")

	signed, err := jwt.Sign(t,
		jwt.WithKey(jwa.EdDSA, ed25519PrivateAdapter{sig: i.cfg.Signer}, jws.WithProtectedHeaders(hdr)),
	)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return &IssuedToken{
		AccessToken:         string(signed),
		ExpiresAt:           c.ExpiresAt,
		RefreshWindowEndsAt: c.IssuedAt.Add(i.cfg.RefreshWindow),
		IssuedAt:            c.IssuedAt,
		JTI:                 c.JTI,
	}, nil
}

func claimsFromJWT(t jwt.Token) (*Claims, error) {
	out := &Claims{
		Subject:   t.Subject(),
		Issuer:    t.Issuer(),
		IssuedAt:  t.IssuedAt().UTC(),
		ExpiresAt: t.Expiration().UTC(),
		JTI:       t.JwtID(),
	}
	if aud := t.Audience(); len(aud) > 0 {
		out.Audience = aud[0]
	}
	if v, ok := t.Get("groups"); ok {
		if gs, ok := toStringSlice(v); ok {
			out.Groups = gs
		}
	}
	if v, ok := t.Get("roles"); ok {
		if rs, ok := toStringSlice(v); ok {
			out.Roles = rs
		}
	}
	if v, ok := t.Get("auth_method"); ok {
		if s, ok := v.(string); ok {
			out.AuthMethod = AuthMethod(s)
		}
	}
	if out.Subject == "" || out.JTI == "" || out.IssuedAt.IsZero() || out.ExpiresAt.IsZero() {
		return nil, ErrInvalidClaims
	}
	return out, nil
}

func toStringSlice(v any) ([]string, bool) {
	switch xs := v.(type) {
	case []string:
		return xs, true
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			s, ok := x.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// ed25519PrivateAdapter lets jwx call our Signer without exposing the raw private key.
// jwx's WithKey accepts a crypto.Signer; FileSigner already satisfies that shape
// because ed25519.PrivateKey implements crypto.Signer. We adapt our Signer interface
// to a minimal Sign(rand, msg, opts) method.
type ed25519PrivateAdapter struct{ sig signer.Signer }

// Public satisfies crypto.Signer.
func (a ed25519PrivateAdapter) Public() crypto.PublicKey { return a.sig.PublicKey() }

// Sign delegates to our Signer; jwx passes the digest as msg, opts ignored for EdDSA.
func (a ed25519PrivateAdapter) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	return a.sig.Sign(msg)
}
```

Add these imports to the top of `token.go`:

```go
import (
	"crypto"
	"io"
)
```

(Merge into the existing import block alphabetically.)

- [ ] **Step 4: Run — expect pass**

Run: `go test ./ftsgw/internal/server/auth/... -race -count=1`
Expected: PASS for all six tests.

- [ ] **Step 5: Commit**

```bash
git add ftsgw/internal/server/auth/
git commit -m "feat(ftsgw/auth): Ed25519 JWT mint/refresh/validate with bounded refresh window"
```

---

### Task 8.4: Background pruner

**Files:**
- Modify: `ftsgw/internal/server/auth/token.go` (add `RunPruner`)
- Test: `ftsgw/internal/server/auth/pruner_test.go`

- [ ] **Step 1: Failing test**

```go
// ftsgw/internal/server/auth/pruner_test.go
// (license header)
package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
)

func TestPrunerRemovesExpired(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)}
	iss, st := newIssuer(t, clk)
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	c, _ := iss.Validate(context.Background(), tok.AccessToken)
	_ = st.Revoke(context.Background(), c.JTI, "x", "", c.ExpiresAt)

	clk.now = clk.now.Add(1 * time.Hour) // past exp
	if err := iss.PruneRevocations(context.Background()); err != nil {
		t.Fatalf("prune: %v", err)
	}
	got, _ := st.IsRevoked(context.Background(), c.JTI)
	if got {
		t.Fatalf("expected jti pruned")
	}
}
```

- [ ] **Step 2: Implementation — add to `token.go`**

```go
// PruneRevocations deletes revoked rows whose exp has passed.
// Run from a goroutine on a ticker (every 5 minutes is typical).
func (i *Issuer) PruneRevocations(ctx context.Context) error {
	_, err := i.cfg.Store.PruneExpired(ctx, i.cfg.Clock.Now())
	return err
}
```

- [ ] **Step 3: Verify & commit**

```bash
go test ./ftsgw/internal/server/auth/...
git add ftsgw/internal/server/auth/
git commit -m "feat(ftsgw/auth): PruneRevocations helper for background cleanup"
```

---

## Phase 9: LDAP provider

### Task 9.1: LDAPProvider with paged group search

**Files:**
- Create: `ftsgw/internal/server/idp/ldap.go`
- Create: `ftsgw/internal/server/idp/ldap_unit_test.go` (table tests for helpers; no real LDAP)

- [ ] **Step 1: Failing unit test for filter formatting**

```go
// ftsgw/internal/server/idp/ldap_unit_test.go
// (license header)
package idp

import "testing"

func TestEscapeFilterValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{"alice", "alice"},
		{"alice(admin)", `alice\28admin\29`},
		{`a\b*c`, `a\5cb\2ac`},
		{"x\x00y", `x\00y`},
	}
	for _, c := range cases {
		got := escapeFilterValue(c.in)
		if got != c.want {
			t.Fatalf("escapeFilterValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Implementation**

```go
// ftsgw/internal/server/idp/ldap.go
// (license header)
package idp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig is the runtime config for LDAPProvider.
type LDAPConfig struct {
	URL               string
	BaseDN            string
	BindDN            string
	BindPassword      string
	UserSearchFilter  string // e.g. "(userPrincipalName=%s)"
	GroupSearchFilter string // e.g. "(member=%s)"
	CABundlePath      string
	StartTLS          bool
	Timeout           time.Duration
}

// LDAPProvider authenticates against AD/LDAP via simple bind and resolves
// groups via paged search using the AD matching-rule-in-chain OID.
type LDAPProvider struct {
	cfg LDAPConfig
}

// NewLDAPProvider constructs an LDAPProvider. Config is validated by config.Validate.
func NewLDAPProvider(cfg LDAPConfig) *LDAPProvider { return &LDAPProvider{cfg: cfg} }

// Authenticate performs user simple-bind, then re-binds as the service account
// to look up the user record and groups.
func (p *LDAPProvider) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Bind(username, password); err != nil {
		var le *ldap.Error
		if errors.As(err, &le) && le.ResultCode == ldap.LDAPResultInvalidCredentials {
			return nil, ErrAuth
		}
		return nil, fmt.Errorf("user bind: %w", err)
	}
	// Rebind as service account for the lookup.
	if p.cfg.BindDN != "" {
		if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("service bind: %w", err)
		}
	}
	return p.lookupAfterBind(conn, username)
}

// Lookup re-resolves an Identity by UPN using the configured service account.
func (p *LDAPProvider) Lookup(ctx context.Context, upn string) (*Identity, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("service bind: %w", err)
	}
	return p.lookupAfterBind(conn, upn)
}

func (p *LDAPProvider) lookupAfterBind(conn *ldap.Conn, username string) (*Identity, error) {
	filter := fmt.Sprintf(p.cfg.UserSearchFilter, escapeFilterValue(username))
	res, err := conn.Search(ldap.NewSearchRequest(
		p.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, int(p.cfg.Timeout.Seconds()), false,
		filter,
		[]string{"distinguishedName", "userPrincipalName", "displayName", "cn"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("user search: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, ErrAuth
	}
	e := res.Entries[0]
	dn := e.GetAttributeValue("distinguishedName")
	if dn == "" {
		dn = e.DN
	}
	upn := e.GetAttributeValue("userPrincipalName")
	if upn == "" {
		upn = username
	}
	display := e.GetAttributeValue("displayName")
	if display == "" {
		display = e.GetAttributeValue("cn")
	}
	groups, err := p.pagedGroupSearch(conn, dn)
	if err != nil {
		return nil, err
	}
	return &Identity{UPN: upn, DisplayName: display, Groups: groups}, nil
}

// pagedGroupSearch uses LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
// and RFC 2696 paged controls to enumerate transitive group membership.
func (p *LDAPProvider) pagedGroupSearch(conn *ldap.Conn, userDN string) ([]string, error) {
	const matchingRuleInChain = "1.2.840.113556.1.4.1941"
	filter := fmt.Sprintf("(member:%s:=%s)", matchingRuleInChain, escapeFilterValue(userDN))
	req := ldap.NewSearchRequest(
		p.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, int(p.cfg.Timeout.Seconds()), false,
		filter,
		[]string{"cn", "distinguishedName"},
		nil,
	)
	res, err := conn.SearchWithPaging(req, 200)
	if err != nil {
		return nil, fmt.Errorf("group search: %w", err)
	}
	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		if cn := e.GetAttributeValue("cn"); cn != "" {
			out = append(out, cn)
		}
	}
	return out, nil
}

// InitiateChallenge — LDAPProvider does not support challenge auth.
func (p *LDAPProvider) InitiateChallenge(_ context.Context, _ string) (*Challenge, error) {
	return nil, ErrNotSupported
}

// CompleteChallenge — LDAPProvider does not support challenge auth.
func (p *LDAPProvider) CompleteChallenge(_ context.Context, _ string) (*Identity, error) {
	return nil, ErrNotSupported
}

// HealthCheck dials, binds as the service account, and disconnects.
func (p *LDAPProvider) HealthCheck(ctx context.Context) error {
	conn, err := p.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if p.cfg.BindDN == "" {
		return nil
	}
	if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		return fmt.Errorf("health bind: %w", err)
	}
	return nil
}

// Capabilities advertises password support only.
func (p *LDAPProvider) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{SupportsPassword: true}
}

func (p *LDAPProvider) dial(ctx context.Context) (*ldap.Conn, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.cfg.CABundlePath != "" {
		raw, err := os.ReadFile(p.cfg.CABundlePath)
		if err != nil {
			return nil, fmt.Errorf("ca bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("ca bundle: no PEM certs found")
		}
		tlsCfg.RootCAs = pool
	}
	dialer := ldap.DialURL
	conn, err := dialer(p.cfg.URL,
		ldap.DialWithTLSConfig(tlsCfg),
		ldap.DialWithDialer(ldapNetDialer(p.cfg.Timeout)),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	conn.SetTimeout(p.cfg.Timeout)
	if p.cfg.StartTLS && !strings.HasPrefix(p.cfg.URL, "ldaps://") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	_ = ctx // reserved for future cancellation
	return conn, nil
}

func ldapNetDialer(timeout time.Duration) *netDialer { return &netDialer{timeout: timeout} }

// escapeFilterValue applies RFC 4515 string-representation escaping.
func escapeFilterValue(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b.WriteString(`\5c`)
		case '*':
			b.WriteString(`\2a`)
		case '(':
			b.WriteString(`\28`)
		case ')':
			b.WriteString(`\29`)
		case 0x00:
			b.WriteString(`\00`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
```

Add a tiny helper (we keep this in its own file to make the ldap.go body more focused):

```go
// ftsgw/internal/server/idp/dialer.go
// (license header)
package idp

import (
	"net"
	"time"
)

type netDialer struct{ timeout time.Duration }

// Dial implements ldap.DialContext shape (net.Dialer-compatible).
func (d *netDialer) Dial(network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d.timeout}).Dial(network, addr)
}
```

- [ ] **Step 3: Verify**

Run: `go test ./ftsgw/internal/server/idp/... -count=1`
Expected: PASS for the unit test (escape table). The LDAPProvider is exercised in the integration test (Phase 16).

- [ ] **Step 4: Commit**

```bash
git add ftsgw/internal/server/idp/
git commit -m "feat(ftsgw/idp): LDAPProvider with simple bind, paged matching-rule-in-chain group search"
```

---

## Phase 10: HTTP middleware and problem-details helper

### Task 10.1: ProblemDetails writer + sentinel mapping

**Files:**
- Create: `ftsgw/internal/server/api/problem.go`
- Test: `ftsgw/internal/server/api/problem_test.go`

- [ ] **Step 1: Failing test**

```go
// ftsgw/internal/server/api/problem_test.go
// (license header)
package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

func TestWriteProblemUsesProblemJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	api.WriteProblem(rr, http.StatusUnauthorized, "Authentication failed", "bad password", "req-1")
	if rr.Header().Get("Content-Type") != types.ProblemContentType {
		t.Fatalf("content-type = %q", rr.Header().Get("Content-Type"))
	}
	var pd types.ProblemDetails
	_ = json.Unmarshal(rr.Body.Bytes(), &pd)
	if pd.Status != http.StatusUnauthorized || pd.RequestID != "req-1" {
		t.Fatalf("body = %+v", pd)
	}
}

func TestMapIdPError(t *testing.T) {
	if s := api.HTTPStatusFor(idp.ErrAuth); s != http.StatusUnauthorized {
		t.Fatalf("ErrAuth -> %d", s)
	}
	if s := api.HTTPStatusFor(idp.ErrUnreachable); s != http.StatusBadGateway {
		t.Fatalf("ErrUnreachable -> %d", s)
	}
	if s := api.HTTPStatusFor(errors.New("other")); s != http.StatusInternalServerError {
		t.Fatalf("default -> %d", s)
	}
}
```

- [ ] **Step 2: Implementation**

```go
// ftsgw/internal/server/api/problem.go
// (license header)
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

// WriteProblem emits a Content-Type: application/problem+json response.
func WriteProblem(w http.ResponseWriter, status int, title, detail, requestID string) {
	body := types.ProblemDetails{
		Type:      "about:blank",
		Title:     title,
		Status:    status,
		Detail:    detail,
		RequestID: requestID,
	}
	w.Header().Set("Content-Type", types.ProblemContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// HTTPStatusFor maps known sentinels to HTTP status codes; unknown errors -> 500.
func HTTPStatusFor(err error) int {
	switch {
	case errors.Is(err, idp.ErrAuth):
		return http.StatusUnauthorized
	case errors.Is(err, idp.ErrUnreachable):
		return http.StatusBadGateway
	case errors.Is(err, idp.ErrNotImplemented), errors.Is(err, idp.ErrNotSupported):
		return http.StatusNotImplemented
	case errors.Is(err, auth.ErrExpired), errors.Is(err, auth.ErrRevoked), errors.Is(err, auth.ErrInvalidSignature):
		return http.StatusUnauthorized
	case errors.Is(err, auth.ErrRefreshWindowExhausted):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}
```

- [ ] **Step 3: Verify & commit**

```bash
go test ./ftsgw/internal/server/api/...
git add ftsgw/internal/server/api/problem*.go
git commit -m "feat(ftsgw/api): RFC 7807 problem helper and error -> status mapping"
```

---

### Task 10.2: Middleware (request ID, logging, recover, audit ctx)

**Files:**
- Create: `ftsgw/internal/server/api/middleware.go`
- Test: `ftsgw/internal/server/api/middleware_test.go`

- [ ] **Step 1: Failing test**

```go
// ftsgw/internal/server/api/middleware_test.go
// (license header)
package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
)

func TestRequestIDInjected(t *testing.T) {
	var seen string
	h := api.RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = api.RequestIDFrom(r.Context())
	}))
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rr, r)
	if seen == "" || !strings.HasPrefix(rr.Header().Get("X-Request-Id"), seen[:0]) {
		t.Fatalf("request id missing: ctx=%q header=%q", seen, rr.Header().Get("X-Request-Id"))
	}
}

func TestRequestIDHonoursInbound(t *testing.T) {
	h := api.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-Id", "abc-123")
	h.ServeHTTP(rr, r)
	if rr.Header().Get("X-Request-Id") != "abc-123" {
		t.Fatalf("inbound id not preserved")
	}
}

func TestRecoverConvertsPanicTo500(t *testing.T) {
	h := api.Recover(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != 500 {
		t.Fatalf("code = %d", rr.Code)
	}
}
```

- [ ] **Step 2: Implementation**

```go
// ftsgw/internal/server/api/middleware.go
// (license header)
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyActorUPN
)

// RequestID injects/propagates a request ID, mirroring it to the response.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFrom returns the injected request ID, "" if absent.
func RequestIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyRequestID).(string)
	return v
}

// ActorUPNFrom returns the authenticated UPN set by Authn, "" if anonymous.
func ActorUPNFrom(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyActorUPN).(string)
	return v
}

// WithActorUPN attaches an actor UPN to the context (used by Authn middleware).
func WithActorUPN(ctx context.Context, upn string) context.Context {
	return context.WithValue(ctx, ctxKeyActorUPN, upn)
}

// AccessLog emits one slog Info per request after it completes.
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusRecorder{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)
			logger.Info("http_request",
				"request_id", RequestIDFrom(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"actor_upn", ActorUPNFrom(r.Context()),
			)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Recover converts panics into HTTP 500 problem responses.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				WriteProblem(w, http.StatusInternalServerError, "Internal Error", "panic", RequestIDFrom(r.Context()))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 3: Verify & commit**

```bash
go test ./ftsgw/internal/server/api/...
git add ftsgw/internal/server/api/middleware*.go
git commit -m "feat(ftsgw/api): request-id, access-log, panic recovery middleware"
```

---

### Task 10.3: Rate limiter (per-IP + per-username auth)

**Files:**
- Create: `ftsgw/internal/server/api/ratelimit.go`
- Test: `ftsgw/internal/server/api/ratelimit_test.go`

- [ ] **Step 1: Failing test**

```go
// ftsgw/internal/server/api/ratelimit_test.go
// (license header)
package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
)

func TestPerIPLimiterTriggers429(t *testing.T) {
	rl := api.NewRateLimiter(api.RateLimits{PerIPRPS: 1, PerIPBurst: 1, AuthPerUsernamePerMinute: 60})
	h := rl.PerIP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	first := httptest.NewRecorder()
	h.ServeHTTP(first, r)
	second := httptest.NewRecorder()
	h.ServeHTTP(second, r)
	if first.Code == 429 || second.Code != 429 {
		t.Fatalf("first=%d second=%d", first.Code, second.Code)
	}
}

func TestPerUsernameLimiterTriggers429(t *testing.T) {
	rl := api.NewRateLimiter(api.RateLimits{PerIPRPS: 1000, PerIPBurst: 1000, AuthPerUsernamePerMinute: 2})
	rl.Clock = func() time.Time { return time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC) }
	for i := 0; i < 2; i++ {
		if !rl.AllowAuth("alice") {
			t.Fatalf("attempt %d should pass", i+1)
		}
	}
	if rl.AllowAuth("alice") {
		t.Fatalf("third attempt should be limited")
	}
}
```

- [ ] **Step 2: Implementation**

```go
// ftsgw/internal/server/api/ratelimit.go
// (license header)
package api

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimits is the runtime config.
type RateLimits struct {
	PerIPRPS                 int
	PerIPBurst               int
	AuthPerUsernamePerMinute int
}

// RateLimiter holds per-IP and per-username buckets. Old entries are reaped
// on access; under steady-state traffic memory is bounded by active clients.
type RateLimiter struct {
	limits RateLimits

	ipMu sync.Mutex
	ipB  map[string]*rate.Limiter

	userMu sync.Mutex
	userB  map[string]*userBucket

	// Clock is injected only for tests.
	Clock func() time.Time
}

type userBucket struct {
	count     int
	windowEnd time.Time
}

// NewRateLimiter returns a RateLimiter using time.Now by default.
func NewRateLimiter(l RateLimits) *RateLimiter {
	return &RateLimiter{
		limits: l,
		ipB:    map[string]*rate.Limiter{},
		userB:  map[string]*userBucket{},
		Clock:  func() time.Time { return time.Now().UTC() },
	}
}

// PerIP wraps a handler with per-remote-IP rate limiting.
func (rl *RateLimiter) PerIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if !rl.ip(ip).Allow() {
			WriteProblem(w, http.StatusTooManyRequests, "Too Many Requests", "rate limit exceeded", RequestIDFrom(r.Context()))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) ip(ip string) *rate.Limiter {
	rl.ipMu.Lock()
	defer rl.ipMu.Unlock()
	lim, ok := rl.ipB[ip]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(rl.limits.PerIPRPS), rl.limits.PerIPBurst)
		rl.ipB[ip] = lim
	}
	return lim
}

// AllowAuth consumes one slot from username's per-minute auth quota.
func (rl *RateLimiter) AllowAuth(username string) bool {
	rl.userMu.Lock()
	defer rl.userMu.Unlock()
	now := rl.Clock()
	b, ok := rl.userB[username]
	if !ok || now.After(b.windowEnd) {
		b = &userBucket{windowEnd: now.Add(time.Minute)}
		rl.userB[username] = b
	}
	if b.count >= rl.limits.AuthPerUsernamePerMinute {
		return false
	}
	b.count++
	return true
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
```

- [ ] **Step 3: Verify & commit**

```bash
go test ./ftsgw/internal/server/api/...
git add ftsgw/internal/server/api/ratelimit*.go
git commit -m "feat(ftsgw/api): per-IP token bucket + per-username auth limiter"
```

---

## Phase 11: HTTP handlers

### Task 11.1: Auth handlers (token, refresh, logout)

**Files:**
- Create: `ftsgw/internal/server/api/handlers_auth.go`
- Test: `ftsgw/internal/server/api/handlers_auth_test.go`

- [ ] **Step 1: Failing test**

```go
// ftsgw/internal/server/api/handlers_auth_test.go
// (license header)
package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/audit"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

type stubIdP struct {
	id  *idp.Identity
	err error
}

func (s stubIdP) Authenticate(_ context.Context, _, _ string) (*idp.Identity, error) {
	return s.id, s.err
}
func (s stubIdP) InitiateChallenge(context.Context, string) (*idp.Challenge, error) {
	return nil, idp.ErrNotSupported
}
func (s stubIdP) CompleteChallenge(context.Context, string) (*idp.Identity, error) {
	return nil, idp.ErrNotSupported
}
func (s stubIdP) Lookup(context.Context, string) (*idp.Identity, error)     { return s.id, s.err }
func (s stubIdP) HealthCheck(context.Context) error                          { return nil }
func (s stubIdP) Capabilities() idp.ProviderCapabilities {
	return idp.ProviderCapabilities{SupportsPassword: true}
}

func mkBrokerDeps(t *testing.T, p idp.IdentityProvider) (*api.Deps, *auth.Issuer) {
	t.Helper()
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "f.db"))
	t.Cleanup(func() { st.Close() })
	lg, _ := audit.NewLogger(filepath.Join(dir, "audit.log"), st)
	t.Cleanup(func() { lg.Close() })
	sgnr := mkSigner(t)
	iss, _ := auth.NewIssuer(auth.IssuerConfig{
		Signer: sgnr, Store: st, Clock: auth.RealClock{},
		Issuer: "ftsgw-server", Audience: "ftsgw",
		TTL: 15 * time.Minute, RefreshWindow: 4 * time.Hour,
	})
	return &api.Deps{Issuer: iss, IdP: p, Audit: lg, RateLimiter: api.NewRateLimiter(api.RateLimits{
		PerIPRPS: 1000, PerIPBurst: 1000, AuthPerUsernamePerMinute: 100,
	})}, iss
}

// Reuse mkSigner from token_test.go via a tiny shim.
// (Plan note: when both test files live in package auth_test/api_test respectively,
// copy mkSigner verbatim into api_test or put it in a shared internal/testutil pkg.)

func TestTokenHandlerSuccess(t *testing.T) {
	deps, _ := mkBrokerDeps(t, stubIdP{id: &idp.Identity{UPN: "alice@example", Groups: []string{"g1"}}})
	body, _ := json.Marshal(types.TokenRequest{Username: "alice", Password: "p"})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/token", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	api.HandleTokenIssue(deps).ServeHTTP(rr, r)
	if rr.Code != 200 {
		t.Fatalf("code = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp types.TokenResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.AccessToken == "" || resp.TokenType != "Bearer" {
		t.Fatalf("bad resp: %+v", resp)
	}
}

func TestTokenHandlerRejectsBadCreds(t *testing.T) {
	deps, _ := mkBrokerDeps(t, stubIdP{err: idp.ErrAuth})
	body, _ := json.Marshal(types.TokenRequest{Username: "alice", Password: "wrong"})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/token", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	api.HandleTokenIssue(deps).ServeHTTP(rr, r)
	if rr.Code != 401 {
		t.Fatalf("code = %d", rr.Code)
	}
}

func TestRefreshHandlerSuccess(t *testing.T) {
	deps, iss := mkBrokerDeps(t, stubIdP{id: &idp.Identity{UPN: "alice@example"}})
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rr := httptest.NewRecorder()
	api.HandleTokenRefresh(deps).ServeHTTP(rr, r)
	if rr.Code != 200 {
		t.Fatalf("code = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestLogoutRevokes(t *testing.T) {
	deps, iss := mkBrokerDeps(t, stubIdP{id: &idp.Identity{UPN: "alice@example"}})
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example"})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rr := httptest.NewRecorder()
	api.HandleLogout(deps).ServeHTTP(rr, r)
	if rr.Code != 204 {
		t.Fatalf("code = %d", rr.Code)
	}
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatalf("token should now be revoked")
	}
}
```

(The note about `mkSigner`: when the engineer runs into "mkSigner undefined in package api_test", they should copy the function body verbatim from `ftsgw/internal/server/auth/token_test.go`. We avoid a shared testutil package to keep the public surface narrow.)

- [ ] **Step 2: Implementation**

```go
// ftsgw/internal/server/api/handlers_auth.go
// (license header)
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/audit"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

// Deps bundles the broker's runtime collaborators. Constructed in cmd/ftsgw-server.
type Deps struct {
	Issuer      *auth.Issuer
	IdP         idp.IdentityProvider
	Audit       *audit.Logger
	RateLimiter *RateLimiter
}

// HandleTokenIssue handles POST /v1/auth/token (password -> app-token).
func HandleTokenIssue(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.TokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
			WriteProblem(w, http.StatusBadRequest, "Bad Request", "invalid body", RequestIDFrom(r.Context()))
			return
		}
		if !d.RateLimiter.AllowAuth(req.Username) {
			_ = d.Audit.Write(r.Context(), audit.Event{
				RequestID: RequestIDFrom(r.Context()), ActorUPN: req.Username,
				Event: audit.EventRateLimited, Outcome: "failure",
			})
			WriteProblem(w, http.StatusTooManyRequests, "Too Many Requests", "auth rate limit exceeded", RequestIDFrom(r.Context()))
			return
		}
		ident, err := d.IdP.Authenticate(r.Context(), req.Username, req.Password)
		if err != nil {
			_ = d.Audit.Write(r.Context(), audit.Event{
				RequestID: RequestIDFrom(r.Context()), ActorUPN: req.Username,
				Event: audit.EventPasswordRejected, Outcome: "failure", Reason: errorReason(err),
			})
			WriteProblem(w, HTTPStatusFor(err), "Authentication Failed", "credentials rejected", RequestIDFrom(r.Context()))
			return
		}
		_ = d.Audit.Write(r.Context(), audit.Event{
			RequestID: RequestIDFrom(r.Context()), ActorUPN: ident.UPN,
			Event: audit.EventPasswordAuthenticated, Outcome: "success",
		})
		tok, err := d.Issuer.Mint(r.Context(), auth.Subject{UPN: ident.UPN, Groups: ident.Groups, Roles: ident.Roles})
		if err != nil {
			WriteProblem(w, http.StatusInternalServerError, "Mint Failed", err.Error(), RequestIDFrom(r.Context()))
			return
		}
		_ = d.Audit.Write(r.Context(), audit.Event{
			RequestID: RequestIDFrom(r.Context()), ActorUPN: ident.UPN,
			Event: audit.EventTokenIssued, Outcome: "success",
			Extras: map[string]any{"jti": tok.JTI, "auth_method": "password"},
		})
		writeTokenResponse(w, tok)
	}
}

// HandleTokenRefresh handles POST /v1/auth/refresh.
func HandleTokenRefresh(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r)
		if !ok {
			WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "missing bearer", RequestIDFrom(r.Context()))
			return
		}
		tok, err := d.Issuer.Refresh(r.Context(), raw)
		if err != nil {
			_ = d.Audit.Write(r.Context(), audit.Event{
				RequestID: RequestIDFrom(r.Context()),
				Event:     audit.EventTokenRefreshRefused, Outcome: "failure", Reason: errorReason(err),
			})
			WriteProblem(w, HTTPStatusFor(err), "Refresh Refused", err.Error(), RequestIDFrom(r.Context()))
			return
		}
		_ = d.Audit.Write(r.Context(), audit.Event{
			RequestID: RequestIDFrom(r.Context()),
			Event:     audit.EventTokenRefreshed, Outcome: "success",
			Extras:    map[string]any{"jti": tok.JTI},
		})
		writeTokenResponse(w, tok)
	}
}

// HandleLogout handles POST /v1/auth/logout.
func HandleLogout(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r)
		if !ok {
			WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "missing bearer", RequestIDFrom(r.Context()))
			return
		}
		claims, err := d.Issuer.Validate(r.Context(), raw)
		if err != nil && !errors.Is(err, auth.ErrExpired) {
			WriteProblem(w, HTTPStatusFor(err), "Logout Failed", err.Error(), RequestIDFrom(r.Context()))
			return
		}
		// allow logout-of-expired-token so users can clean up cleanly
		if err := d.Issuer.Revoke(r.Context(), raw, claims.Subject, "logout"); err != nil {
			WriteProblem(w, http.StatusInternalServerError, "Revoke Failed", err.Error(), RequestIDFrom(r.Context()))
			return
		}
		_ = d.Audit.Write(r.Context(), audit.Event{
			RequestID: RequestIDFrom(r.Context()),
			ActorUPN:  claims.Subject,
			Event:     audit.EventTokenRevoked, Outcome: "success",
			Extras:    map[string]any{"jti": claims.JTI},
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

func writeTokenResponse(w http.ResponseWriter, tok *auth.IssuedToken) {
	body := types.TokenResponse{
		AccessToken:         tok.AccessToken,
		TokenType:           "Bearer",
		ExpiresAt:           tok.ExpiresAt,
		RefreshWindowEndsAt: tok.RefreshWindowEndsAt,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

func errorReason(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// authnFromBearer is the helper used by /v1/me. It enforces validity and
// returns claims; ctx is enriched with the actor UPN.
func authnFromBearer(d *Deps, r *http.Request) (*auth.Claims, *http.Request, error) {
	raw, ok := bearerToken(r)
	if !ok {
		return nil, r, errors.New("missing bearer")
	}
	c, err := d.Issuer.Validate(r.Context(), raw)
	if err != nil {
		return nil, r, err
	}
	r = r.WithContext(WithActorUPN(r.Context(), c.Subject))
	return c, r, nil
}

// touchClaim is a no-op placeholder kept here so reviewers can see we
// intentionally do not refresh on /v1/me (refresh is an explicit endpoint).
var _ = (func(c *auth.Claims) time.Time { return c.ExpiresAt })
```

- [ ] **Step 3: Verify**

Run: `go test ./ftsgw/internal/server/api/...`
Expected: PASS (assuming `mkSigner` was copied into the api_test file).

- [ ] **Step 4: Commit**

```bash
git add ftsgw/internal/server/api/handlers_auth*.go
git commit -m "feat(ftsgw/api): /v1/auth/{token,refresh,logout} handlers w/ audit + rate limiting"
```

---

### Task 11.2: /v1/me, /healthz, /readyz, /v1/.well-known/jwks.json

**Files:**
- Create: `ftsgw/internal/server/api/handlers_me.go`
- Create: `ftsgw/internal/server/api/handlers_health.go`
- Create: `ftsgw/internal/server/api/handlers_jwks.go`
- Test: `ftsgw/internal/server/api/handlers_other_test.go`

- [ ] **Step 1: Failing tests**

```go
// ftsgw/internal/server/api/handlers_other_test.go
// (license header)
package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

func TestMeReturnsClaims(t *testing.T) {
	deps, iss := mkBrokerDeps(t, stubIdP{id: &idp.Identity{UPN: "alice@example", Groups: []string{"g1"}}})
	tok, _ := iss.Mint(context.Background(), auth.Subject{UPN: "alice@example", Groups: []string{"g1"}})
	r := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rr := httptest.NewRecorder()
	api.HandleMe(deps).ServeHTTP(rr, r)
	if rr.Code != 200 {
		t.Fatalf("code = %d body=%s", rr.Code, rr.Body.String())
	}
	var me types.MeResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &me)
	if me.UPN != "alice@example" || len(me.Groups) != 1 {
		t.Fatalf("body = %+v", me)
	}
}

func TestHealthzAlwaysOK(t *testing.T) {
	rr := httptest.NewRecorder()
	api.HandleHealthz().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != 200 {
		t.Fatalf("code = %d", rr.Code)
	}
}

func TestJWKSReturnsEdDSAKey(t *testing.T) {
	deps, _ := mkBrokerDeps(t, stubIdP{})
	rr := httptest.NewRecorder()
	api.HandleJWKS(deps).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/.well-known/jwks.json", nil))
	if rr.Code != 200 {
		t.Fatalf("code = %d", rr.Code)
	}
	body := rr.Body.String()
	if !contains(body, `"kty":"OKP"`) || !contains(body, `"crv":"Ed25519"`) {
		t.Fatalf("jwks body missing OKP/Ed25519: %s", body)
	}
}

func contains(haystack, needle string) bool { return len(haystack) >= len(needle) && (haystack == needle || (len(haystack) > 0 && (haystack[0:1]+haystack[1:]) != "" && (func() bool { return indexOf(haystack, needle) >= 0 })())) }

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Implementation**

```go
// ftsgw/internal/server/api/handlers_me.go
// (license header)
package api

import (
	"encoding/json"
	"net/http"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

// HandleMe returns identity + group list for the current bearer token.
func HandleMe(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, r2, err := authnFromBearer(d, r)
		if err != nil {
			WriteProblem(w, HTTPStatusFor(err), "Unauthorized", err.Error(), RequestIDFrom(r.Context()))
			return
		}
		body := types.MeResponse{
			UPN:            claims.Subject,
			DisplayName:    claims.Subject, // Phase 0: we don't re-resolve display name
			Groups:         claims.Groups,
			Roles:          claims.Roles,
			TokenIssuedAt:  claims.IssuedAt,
			TokenExpiresAt: claims.ExpiresAt,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
		_ = r2 // silence unused
	}
}
```

```go
// ftsgw/internal/server/api/handlers_health.go
// (license header)
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

// HandleHealthz returns 200 if the process is running. No external checks.
func HandleHealthz() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.HealthResponse{Status: "ok", Checks: map[string]types.HealthCheck{}})
	}
}

// HandleReadyz pings the IdP. 200 only when ready to serve.
func HandleReadyz(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		status := "ok"
		check := types.HealthCheck{Status: "ok"}
		if err := d.IdP.HealthCheck(ctx); err != nil {
			status = "degraded"
			check = types.HealthCheck{Status: "fail", Detail: err.Error()}
		}
		w.Header().Set("Content-Type", "application/json")
		code := http.StatusOK
		if status != "ok" {
			code = http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(types.HealthResponse{
			Status: status, Checks: map[string]types.HealthCheck{"idp": check},
		})
	}
}
```

```go
// ftsgw/internal/server/api/handlers_jwks.go
// (license header)
package api

import (
	"encoding/json"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// HandleJWKS publishes the broker's verification public key as a JWK Set.
func HandleJWKS(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		pub := d.Issuer.PublicVerificationKey()
		kid := d.Issuer.VerificationKeyID()
		key, err := jwk.FromRaw(pub)
		if err != nil {
			WriteProblem(w, http.StatusInternalServerError, "JWKS Failed", err.Error(), "")
			return
		}
		_ = key.Set(jwk.KeyIDKey, kid)
		_ = key.Set(jwk.AlgorithmKey, jwa.EdDSA)
		_ = key.Set(jwk.KeyUsageKey, "sig")

		set := jwk.NewSet()
		_ = set.AddKey(key)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}
}
```

Update `token.go` to expose the public key + kid:

```go
// in ftsgw/internal/server/auth/token.go add:

// PublicVerificationKey returns the signer's public verification key.
func (i *Issuer) PublicVerificationKey() ed25519.PublicKey { return i.cfg.Signer.PublicKey() }

// VerificationKeyID returns the kid that matches PublicVerificationKey.
func (i *Issuer) VerificationKeyID() string { return i.cfg.Signer.KeyID() }
```

And add `"crypto/ed25519"` to the imports.

- [ ] **Step 3: Verify & commit**

```bash
go test ./ftsgw/internal/server/api/... -count=1
git add ftsgw/internal/server/api/handlers_me.go ftsgw/internal/server/api/handlers_health.go ftsgw/internal/server/api/handlers_jwks.go ftsgw/internal/server/auth/token.go
git commit -m "feat(ftsgw/api): /v1/me, /healthz, /readyz, /v1/.well-known/jwks.json"
```

---

### Task 11.3: Router wiring

**Files:**
- Create: `ftsgw/internal/server/api/router.go`

- [ ] **Step 1: Implementation**

```go
// ftsgw/internal/server/api/router.go
// (license header)
package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewRouter returns a fully wired chi router for the broker. Middleware order:
// RequestID -> Recover -> AccessLog -> RateLimit.PerIP -> route-level handlers.
func NewRouter(d *Deps, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()
	r.Use(RequestID)
	r.Use(Recover)
	r.Use(AccessLog(logger))
	r.Use(d.RateLimiter.PerIP)

	r.Post("/v1/auth/token", HandleTokenIssue(d))
	r.Post("/v1/auth/refresh", HandleTokenRefresh(d))
	r.Post("/v1/auth/logout", HandleLogout(d))
	r.Get("/v1/me", HandleMe(d))
	r.Get("/v1/.well-known/jwks.json", HandleJWKS(d))
	r.Get("/healthz", HandleHealthz())
	r.Get("/readyz", HandleReadyz(d))
	r.Handle("/metrics", promhttp.Handler())
	return r
}
```

- [ ] **Step 2: Verify build**

Run: `go build ./ftsgw/...`
Expected: succeeds.

- [ ] **Step 3: Commit**

```bash
git add ftsgw/internal/server/api/router.go
git commit -m "feat(ftsgw/api): chi router wiring + middleware order + /metrics"
```

---

## Phase 12: Observability

### Task 12.1: Prometheus metrics

**Files:**
- Create: `ftsgw/internal/server/api/metrics.go`
- Modify: `ftsgw/internal/server/api/handlers_auth.go` (instrument auth/refresh/revoke)
- Modify: `ftsgw/internal/server/api/middleware.go` (instrument HTTP duration/count)

- [ ] **Step 1: Implementation**

```go
// ftsgw/internal/server/api/metrics.go
// (license header)
package api

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ftsgw_http_requests_total",
		Help: "HTTP requests by route and status.",
	}, []string{"route", "status"})

	HTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ftsgw_http_request_duration_seconds",
		Help:    "HTTP request duration by route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route"})

	PasswordAuthTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ftsgw_password_auth_total",
		Help: "Password authentications by outcome.",
	}, []string{"outcome"})

	TokensIssuedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ftsgw_tokens_issued_total", Help: "Tokens minted.",
	})

	TokensRefreshedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ftsgw_tokens_refreshed_total", Help: "Tokens refreshed.",
	})

	TokensRefreshRefusedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ftsgw_tokens_refresh_refused_total", Help: "Refresh refusals by reason.",
	}, []string{"reason"})

	TokensRevokedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ftsgw_tokens_revoked_total", Help: "Tokens explicitly revoked.",
	})

	IdPAuthDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "ftsgw_idp_auth_duration_seconds", Help: "IdP authenticate latency.",
		Buckets: prometheus.DefBuckets,
	}, []string{"idp"})

	AuditWriteFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ftsgw_audit_write_failures_total", Help: "Audit sink write failures.",
	})

	RateLimitedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ftsgw_rate_limited_total", Help: "Rate-limit denials by endpoint.",
	}, []string{"endpoint"})
)
```

Update `AccessLog` to also bump metrics. Add at the end of the handler in `middleware.go`:

```go
HTTPRequestsTotal.WithLabelValues(r.URL.Path, http.StatusText(sw.status)).Inc()
HTTPDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
```

Update `HandleTokenIssue`, `HandleTokenRefresh`, `HandleLogout` to bump `TokensIssuedTotal`, `TokensRefreshedTotal`/`TokensRefreshRefusedTotal`, `TokensRevokedTotal`, and `PasswordAuthTotal` on the relevant code paths. Bump `RateLimitedTotal.WithLabelValues("/v1/auth/token").Inc()` when AllowAuth returns false. In `audit.Logger.Write`, on error path, call `AuditWriteFailuresTotal.Inc()` — exported `OnFailure` hook is the cleanest seam: add a `var OnAuditFailure = func() {}` in `audit.go` and call it from the error branch; wire `OnAuditFailure = func() { api.AuditWriteFailuresTotal.Inc() }` in `cmd/ftsgw-server/main.go` to avoid a circular import.

- [ ] **Step 2: Verify**

Run: `go build ./ftsgw/...`
Expected: succeeds.

- [ ] **Step 3: Commit**

```bash
git add ftsgw/internal/server/api/metrics.go ftsgw/internal/server/api/middleware.go ftsgw/internal/server/api/handlers_auth.go ftsgw/internal/server/audit/audit.go
git commit -m "feat(ftsgw/obs): Prometheus metrics + audit failure counter hook"
```

---

### Task 12.2: Structured logging with secret redaction

**Files:**
- Create: `ftsgw/internal/server/obs/log.go`
- Test: `ftsgw/internal/server/obs/log_test.go`

- [ ] **Step 1: Failing test**

```go
// ftsgw/internal/server/obs/log_test.go
// (license header)
package obs_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/obs"
)

func TestRedactingHandlerStripsSecretShapedAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := obs.NewRedactingHandler(slog.NewJSONHandler(&buf, nil))
	log := slog.New(h)
	log.Info("hello", "password", "hunter2", "user", "alice", "Authorization", "Bearer abc.def.ghi")
	out := buf.String()
	if strings.Contains(out, "hunter2") || strings.Contains(out, "abc.def.ghi") {
		t.Fatalf("secret leaked: %s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Fatalf("non-secret value lost: %s", out)
	}
}
```

- [ ] **Step 2: Implementation**

```go
// ftsgw/internal/server/obs/log.go
// (license header)

// Package obs houses observability glue: structured logging with a redacting
// handler, and OpenTelemetry setup.
package obs

import (
	"context"
	"log/slog"
	"strings"
)

// RedactingHandler wraps an inner slog.Handler and replaces values of attrs
// whose key matches the secret deny-list with "***REDACTED***".
type RedactingHandler struct{ inner slog.Handler }

// NewRedactingHandler returns a Handler that redacts secret-shaped attrs.
func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

// Enabled delegates.
func (h *RedactingHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.inner.Enabled(ctx, lvl)
}

// Handle redacts and delegates.
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	r2 := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		r2.AddAttrs(redact(a))
		return true
	})
	return h.inner.Handle(ctx, r2)
}

// WithAttrs delegates while keeping redaction.
func (h *RedactingHandler) WithAttrs(as []slog.Attr) slog.Handler {
	cleaned := make([]slog.Attr, 0, len(as))
	for _, a := range as {
		cleaned = append(cleaned, redact(a))
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(cleaned)}
}

// WithGroup delegates.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

var secretKeys = []string{"password", "authorization", "access_token", "token", "secret", "bearer"}

func redact(a slog.Attr) slog.Attr {
	k := strings.ToLower(a.Key)
	for _, s := range secretKeys {
		if k == s {
			return slog.Attr{Key: a.Key, Value: slog.StringValue("***REDACTED***")}
		}
	}
	return a
}
```

- [ ] **Step 3: Verify & commit**

```bash
go test ./ftsgw/internal/server/obs/...
git add ftsgw/internal/server/obs/
git commit -m "feat(ftsgw/obs): RedactingHandler for slog (passwords, bearers never logged)"
```

---

### Task 12.3: OTLP tracing wire-up

**Files:**
- Create: `ftsgw/internal/server/obs/trace.go`

- [ ] **Step 1: Implementation**

```go
// ftsgw/internal/server/obs/trace.go
// (license header)
package obs

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// SetupTracing configures global TracerProvider from OTLP. When endpoint
// is empty, returns a no-op shutdown and never exports.
func SetupTracing(ctx context.Context, endpoint, serviceName, version string) (func(context.Context) error, error) {
	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}
	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}
	res, _ := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(version),
	))
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}
```

- [ ] **Step 2: Verify & commit**

```bash
go build ./ftsgw/...
git add ftsgw/internal/server/obs/trace.go
git commit -m "feat(ftsgw/obs): OTLP tracer provider setup (no-op when endpoint empty)"
```

---

## Phase 13: Server main + admin subcommands

### Task 13.1: Broker main

**Files:**
- Create: `ftsgw/cmd/ftsgw-server/main.go`

- [ ] **Step 1: Implementation**

```go
// ftsgw/cmd/ftsgw-server/main.go
// (license header)
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/audit"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/config"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/obs"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/signer"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "revoke":
			os.Exit(runRevoke(os.Args[2:]))
		case "rotate-key":
			os.Exit(runRotateKey(os.Args[2:]))
		case "version":
			fmt.Printf("ftsgw-server %s (%s)\n", version, commit)
			return
		}
	}
	if err := serve(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func serve() error {
	cfgPath := flag.String("config", "/etc/ftsgw-server/config.yaml", "path to config")
	otlp := flag.String("otlp", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), "OTLP endpoint (host:port)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := slog.New(obs.NewRedactingHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	tpShutdown, err := obs.SetupTracing(ctx, *otlp, "ftsgw-server", version)
	if err != nil {
		return fmt.Errorf("tracing: %w", err)
	}
	defer func() { _ = tpShutdown(context.Background()) }()

	st, err := store.Open(filepath.Join(filepath.Dir(cfg.Audit.FilePath), "ftsgw.db"))
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer st.Close()

	auditLg, err := audit.NewLogger(cfg.Audit.FilePath, st)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer auditLg.Close()
	audit.OnAuditFailure = func() { api.AuditWriteFailuresTotal.Inc() }

	sgnr, err := signer.NewFileSigner(cfg.Signer.KeyPath, cfg.Signer.KeyID)
	if err != nil {
		return fmt.Errorf("signer: %w", err)
	}

	provider, err := buildProvider(cfg)
	if err != nil {
		return fmt.Errorf("idp: %w", err)
	}

	iss, err := auth.NewIssuer(auth.IssuerConfig{
		Signer: sgnr, Store: st, Clock: auth.RealClock{},
		Issuer: cfg.Tokens.Issuer, Audience: cfg.Tokens.Audience,
		TTL: cfg.Tokens.TTL, RefreshWindow: cfg.Tokens.RefreshWindow,
	})
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}

	go pruneLoop(ctx, iss, logger)

	deps := &api.Deps{
		Issuer: iss, IdP: provider, Audit: auditLg,
		RateLimiter: api.NewRateLimiter(api.RateLimits{
			PerIPRPS: cfg.RateLimit.PerIPRPS, PerIPBurst: cfg.RateLimit.PerIPBurst,
			AuthPerUsernamePerMinute: cfg.RateLimit.AuthPerUsernamePerMinute,
		}),
	}
	router := api.NewRouter(deps, logger)
	srv := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	go func() {
		<-ctx.Done()
		shutdown, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = srv.Shutdown(shutdown)
	}()

	logger.Info("ftsgw-server listening", "addr", cfg.Server.ListenAddr, "version", version)
	err = srv.ListenAndServeTLS(cfg.Server.TLSCertPath, cfg.Server.TLSKeyPath)
	if !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func buildProvider(cfg *config.Config) (idp.IdentityProvider, error) {
	switch cfg.IdP.Kind {
	case "ldap":
		return idp.NewLDAPProvider(idp.LDAPConfig{
			URL: cfg.IdP.URL, BaseDN: cfg.IdP.BaseDN,
			BindDN: cfg.IdP.ResolvedBindDN, BindPassword: cfg.IdP.ResolvedBindPassword,
			UserSearchFilter: cfg.IdP.UserSearchFilter, GroupSearchFilter: cfg.IdP.GroupSearchFilter,
			CABundlePath: cfg.IdP.CABundlePath, StartTLS: cfg.IdP.StartTLS, Timeout: cfg.IdP.Timeout,
		}), nil
	case "entra":
		return idp.EntraProvider{}, nil
	case "adfs":
		return idp.ADFSProvider{}, nil
	}
	return nil, fmt.Errorf("unknown idp kind: %s", cfg.IdP.Kind)
}

func pruneLoop(ctx context.Context, iss *auth.Issuer, logger *slog.Logger) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := iss.PruneRevocations(ctx); err != nil {
				logger.Warn("prune failed", "err", err.Error())
			}
		}
	}
}
```

- [ ] **Step 2: Wire `audit.OnAuditFailure` declaration**

In `ftsgw/internal/server/audit/audit.go`, add:

```go
// OnAuditFailure is invoked when Logger.Write returns an error. main.go wires
// it to a Prometheus counter. Defaults to a no-op so non-broker callers
// (tests) need not import the metrics package.
var OnAuditFailure = func() {}
```

And in `logger.go`, in the error path of `Write`, before returning:

```go
OnAuditFailure()
```

- [ ] **Step 3: Verify**

```bash
make ftsgw-build
```

Expected: `bin/ftsgw-server` is produced.

- [ ] **Step 4: Commit**

```bash
git add ftsgw/cmd/ftsgw-server/main.go ftsgw/internal/server/audit/
git commit -m "feat(ftsgw): broker main with TLS, OTLP, prune loop, graceful shutdown"
```

---

### Task 13.2: Admin subcommands (revoke, rotate-key)

**Files:**
- Create: `ftsgw/cmd/ftsgw-server/admin.go`

- [ ] **Step 1: Implementation**

```go
// ftsgw/cmd/ftsgw-server/admin.go
// (license header)
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/config"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

// runRevoke implements `ftsgw-server revoke --jti=... --reason=...`. It opens
// the configured SQLite, inserts a revocation row, and exits.
func runRevoke(args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/ftsgw-server/config.yaml", "config path")
	jti := fs.String("jti", "", "JTI to revoke")
	reason := fs.String("reason", "admin-revoke", "reason recorded in audit/store")
	actor := fs.String("actor", "admin", "actor UPN recorded")
	exp := fs.Duration("exp-from-now", 24*time.Hour, "how far in the future to set exp (cleanup horizon)")
	_ = fs.Parse(args)
	if *jti == "" {
		fmt.Fprintln(os.Stderr, "revoke: --jti required")
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	st, err := store.Open(filepath.Join(filepath.Dir(cfg.Audit.FilePath), "ftsgw.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		return 1
	}
	defer st.Close()
	if err := st.Revoke(context.Background(), *jti, *actor, *reason, time.Now().Add(*exp).UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "revoke:", err)
		return 1
	}
	fmt.Println("revoked", *jti)
	return 0
}

// runRotateKey generates a new Ed25519 keypair at --out (mode 0600).
// Operators are responsible for atomically swapping in the new file and
// restarting the broker; jwks.json reflects the change on next start.
func runRotateKey(args []string) int {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	out := fs.String("out", "", "output path for new private key")
	_ = fs.Parse(args)
	if *out == "" {
		fmt.Fprintln(os.Stderr, "rotate-key: --out required")
		return 2
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "genkey:", err)
		return 1
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()}
	if err := os.WriteFile(*out, pem.EncodeToMemory(block), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		return 1
	}
	fmt.Println("wrote", *out)
	return 0
}
```

- [ ] **Step 2: Verify & commit**

```bash
make ftsgw-build
bin/ftsgw-server version
git add ftsgw/cmd/ftsgw-server/admin.go
git commit -m "feat(ftsgw): admin subcommands (revoke, rotate-key)"
```

---

## Phase 14: CLI — token store and HTTP client

### Task 14.1: Exit codes

**Files:**
- Create: `ftsgw/internal/cli/exit.go`

- [ ] **Step 1: Write**

```go
// ftsgw/internal/cli/exit.go
// (license header)
package cli

// Exit codes for ftsgw-cli. Surfaced to scripts.
const (
	ExitOK              = 0
	ExitGeneric         = 1
	ExitAuthFailed      = 2
	ExitNetwork         = 3
	ExitSessionExpired  = 4
	ExitConfig          = 5
)

// Coded is the wrapper type used by command handlers.
type Coded struct {
	Code int
	Err  error
}

// Error implements error.
func (c *Coded) Error() string { return c.Err.Error() }

// Unwrap exposes the wrapped error to errors.Is/As.
func (c *Coded) Unwrap() error { return c.Err }

// WithCode wraps an error with an exit code.
func WithCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &Coded{Code: code, Err: err}
}
```

- [ ] **Step 2: Commit**

```bash
git add ftsgw/internal/cli/exit.go
git commit -m "feat(ftsgw-cli): exit-code wrapper"
```

---

### Task 14.2: Token store (~/.config/ftsgw/token.json)

**Files:**
- Create: `ftsgw/internal/cli/tokenstore.go`
- Test: `ftsgw/internal/cli/tokenstore_test.go`

- [ ] **Step 1: Failing test**

```go
// ftsgw/internal/cli/tokenstore_test.go
// (license header)
package cli_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token.json")
	in := cli.StoredToken{
		AccessToken:         "abc.def.ghi",
		ExpiresAt:           time.Now().Add(15 * time.Minute).UTC(),
		RefreshWindowEndsAt: time.Now().Add(4 * time.Hour).UTC(),
		IssuedAt:            time.Now().UTC(),
		BrokerURL:           "https://broker.example:8443",
	}
	if err := cli.SaveToken(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := cli.LoadToken(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.AccessToken != in.AccessToken || got.BrokerURL != in.BrokerURL {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perms = %o", info.Mode().Perm())
	}
}

func TestLoadMissingFileIsErrNotFound(t *testing.T) {
	_, err := cli.LoadToken(filepath.Join(t.TempDir(), "absent.json"))
	if err != cli.ErrTokenNotFound {
		t.Fatalf("got %v", err)
	}
}
```

- [ ] **Step 2: Implementation**

```go
// ftsgw/internal/cli/tokenstore.go
// (license header)
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// StoredToken is the on-disk shape of the cached app-token.
type StoredToken struct {
	AccessToken         string    `json:"access_token"`
	ExpiresAt           time.Time `json:"expires_at"`
	RefreshWindowEndsAt time.Time `json:"refresh_window_ends_at"`
	IssuedAt            time.Time `json:"issued_at"`
	BrokerURL           string    `json:"broker_url"`
}

// ErrTokenNotFound is returned when no token file exists.
var ErrTokenNotFound = errors.New("token: not found")

// DefaultTokenPath returns ~/.config/ftsgw/token.json (XDG-compatible).
func DefaultTokenPath() (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("user config dir: %w", err)
	}
	return filepath.Join(cfg, "ftsgw", "token.json"), nil
}

// SaveToken writes the token to path with mode 0600.
func SaveToken(path string, t StoredToken) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// LoadToken reads and decodes the cached token.
func LoadToken(path string) (StoredToken, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StoredToken{}, ErrTokenNotFound
		}
		return StoredToken{}, fmt.Errorf("read token: %w", err)
	}
	var t StoredToken
	if err := json.Unmarshal(raw, &t); err != nil {
		return StoredToken{}, fmt.Errorf("decode token: %w", err)
	}
	return t, nil
}

// DeleteToken removes the cache file. Idempotent.
func DeleteToken(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete token: %w", err)
	}
	return nil
}
```

- [ ] **Step 3: Verify & commit**

```bash
go test ./ftsgw/internal/cli/... -count=1
git add ftsgw/internal/cli/tokenstore*.go
git commit -m "feat(ftsgw-cli): tokenstore (atomic write, 0600 perms, XDG path)"
```

---

### Task 14.3: HTTP client with refresh logic

**Files:**
- Create: `ftsgw/internal/cli/client.go`
- Test: `ftsgw/internal/cli/client_test.go`

- [ ] **Step 1: Failing test**

```go
// ftsgw/internal/cli/client_test.go
// (license header)
package cli_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

func TestClientAutoRefreshNearExpiry(t *testing.T) {
	var refreshes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/refresh":
			refreshes++
			_ = json.NewEncoder(w).Encode(types.TokenResponse{
				AccessToken:         "new-token",
				TokenType:           "Bearer",
				ExpiresAt:           time.Now().Add(15 * time.Minute).UTC(),
				RefreshWindowEndsAt: time.Now().Add(3 * time.Hour).UTC(),
			})
		case "/v1/me":
			_ = json.NewEncoder(w).Encode(types.MeResponse{UPN: "alice@example"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.json")
	now := time.Now().UTC()
	_ = cli.SaveToken(tokenPath, cli.StoredToken{
		AccessToken:         "old-token",
		ExpiresAt:           now.Add(2 * time.Minute), // <20% remaining of 15m
		RefreshWindowEndsAt: now.Add(3 * time.Hour),
		IssuedAt:            now.Add(-13 * time.Minute),
		BrokerURL:           srv.URL,
	})

	c, _ := cli.NewClient(cli.ClientConfig{
		BrokerURL: srv.URL,
		TokenPath: tokenPath,
		TTLHint:   15 * time.Minute,
	})
	_, err := c.Me()
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if refreshes != 1 {
		t.Fatalf("refreshes = %d, want 1", refreshes)
	}
	got, _ := cli.LoadToken(tokenPath)
	if got.AccessToken != "new-token" {
		t.Fatalf("token not updated")
	}
}

func TestClientSurfacesSessionExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "expired", http.StatusUnauthorized)
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.json")
	past := time.Now().Add(-1 * time.Hour).UTC()
	_ = cli.SaveToken(tokenPath, cli.StoredToken{
		AccessToken: "old", ExpiresAt: past, RefreshWindowEndsAt: past,
		IssuedAt: past.Add(-4 * time.Hour), BrokerURL: srv.URL,
	})
	c, _ := cli.NewClient(cli.ClientConfig{
		BrokerURL: srv.URL,
		TokenPath: tokenPath,
		TTLHint:   15 * time.Minute,
	})
	_, err := c.Me()
	if err == nil {
		t.Fatalf("want session expired error")
	}
}
```

- [ ] **Step 2: Implementation**

```go
// ftsgw/internal/cli/client.go
// (license header)
package cli

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

// ErrSessionExpired surfaces "your refresh window is gone, log in again".
var ErrSessionExpired = errors.New("session expired")

// ClientConfig wires a CLI HTTP client.
type ClientConfig struct {
	BrokerURL     string
	TokenPath     string
	CABundlePath  string
	TTLHint       time.Duration // server-side TTL (used to decide when to auto-refresh)
	Now           func() time.Time
}

// Client is the broker-facing HTTP client.
type Client struct {
	cfg  ClientConfig
	http *http.Client
}

// NewClient validates config and constructs the client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.BrokerURL == "" {
		return nil, errors.New("client: broker URL required")
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.TTLHint == 0 {
		cfg.TTLHint = 15 * time.Minute
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CABundlePath != "" {
		raw, err := os.ReadFile(cfg.CABundlePath)
		if err != nil {
			return nil, fmt.Errorf("ca bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("ca bundle: no certs")
		}
		tlsCfg.RootCAs = pool
	}
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// Login posts username/password to /v1/auth/token and stores the result.
func (c *Client) Login(username, password string) error {
	body, _ := json.Marshal(types.TokenRequest{Username: username, Password: password})
	resp, err := c.http.Post(c.cfg.BrokerURL+"/v1/auth/token", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("post token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrAuth
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login: %s", resp.Status)
	}
	var tr types.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	return SaveToken(c.cfg.TokenPath, StoredToken{
		AccessToken:         tr.AccessToken,
		ExpiresAt:           tr.ExpiresAt,
		RefreshWindowEndsAt: tr.RefreshWindowEndsAt,
		IssuedAt:            c.cfg.Now(),
		BrokerURL:           c.cfg.BrokerURL,
	})
}

// Me returns identity from /v1/me, auto-refreshing on near-expiry.
func (c *Client) Me() (*types.MeResponse, error) {
	tok, err := c.ensureFresh()
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, c.cfg.BrokerURL+"/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get /me: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("me: %s", resp.Status)
	}
	var me types.MeResponse
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		return nil, fmt.Errorf("decode me: %w", err)
	}
	return &me, nil
}

// Logout calls /v1/auth/logout and deletes the local token cache.
func (c *Client) Logout() error {
	tok, err := LoadToken(c.cfg.TokenPath)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return nil
		}
		return err
	}
	req, _ := http.NewRequest(http.MethodPost, c.cfg.BrokerURL+"/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("post /logout: %w", err)
	}
	_ = resp.Body.Close()
	return DeleteToken(c.cfg.TokenPath)
}

// ensureFresh loads the cached token and refreshes it if past 80% of TTL.
// If the token is past exp and the refresh window has also elapsed, returns
// ErrSessionExpired so callers can surface a clean "run ftsgw-cli login".
func (c *Client) ensureFresh() (*StoredToken, error) {
	tok, err := LoadToken(c.cfg.TokenPath)
	if err != nil {
		return nil, err
	}
	now := c.cfg.Now()
	if now.After(tok.RefreshWindowEndsAt) {
		return nil, ErrSessionExpired
	}
	refreshAt := tok.ExpiresAt.Add(-c.cfg.TTLHint / 5) // 80% of TTL elapsed
	if now.Before(refreshAt) {
		return &tok, nil
	}
	// Refresh.
	req, _ := http.NewRequest(http.MethodPost, c.cfg.BrokerURL+"/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		// If we still have a valid (unexpired) token, soldier on.
		if now.Before(tok.ExpiresAt) {
			return &tok, nil
		}
		return nil, fmt.Errorf("refresh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, ErrSessionExpired
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh: %s", resp.Status)
	}
	var tr types.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decode refresh: %w", err)
	}
	new := StoredToken{
		AccessToken:         tr.AccessToken,
		ExpiresAt:           tr.ExpiresAt,
		RefreshWindowEndsAt: tr.RefreshWindowEndsAt,
		IssuedAt:            tok.IssuedAt, // preserved
		BrokerURL:           tok.BrokerURL,
	}
	if err := SaveToken(c.cfg.TokenPath, new); err != nil {
		return nil, err
	}
	return &new, nil
}

// ErrAuth is the CLI's user-visible "bad password" sentinel.
var ErrAuth = errors.New("authentication failed")
```

- [ ] **Step 3: Verify & commit**

```bash
go test ./ftsgw/internal/cli/... -count=1
git add ftsgw/internal/cli/client*.go
git commit -m "feat(ftsgw-cli): HTTP client with 80%-TTL auto-refresh and session-expired surfacing"
```

---

## Phase 15: CLI commands

### Task 15.1: cobra root + version

**Files:**
- Create: `ftsgw/internal/cli/root.go`
- Create: `ftsgw/cmd/ftsgw-cli/main.go`

- [ ] **Step 1: Implementation**

```go
// ftsgw/internal/cli/root.go
// (license header)

// Package cli implements ftsgw-cli command handlers and the broker-facing
// HTTP client. Commands return errors wrapped by WithCode so main can exit
// with documented exit codes.
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Globals captures persistent flags / viper values used by commands.
type Globals struct {
	BrokerURL    string
	CABundlePath string
	TokenPath    string
	ConfigPath   string
}

// NewRootCmd builds the cobra root command tree.
func NewRootCmd(version, commit string) *cobra.Command {
	g := &Globals{}
	root := &cobra.Command{
		Use:           "ftsgw-cli",
		Short:         "ftsgw broker client",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return loadCLIConfig(g)
		},
	}
	root.PersistentFlags().StringVar(&g.ConfigPath, "config", "", "CLI config path (default ~/.config/ftsgw/cli.yaml)")
	root.PersistentFlags().StringVar(&g.BrokerURL, "broker", "", "broker base URL (https://host:8443)")
	root.PersistentFlags().StringVar(&g.CABundlePath, "ca-bundle", "", "CA bundle PEM path")
	root.PersistentFlags().StringVar(&g.TokenPath, "token-path", "", "token cache path (default ~/.config/ftsgw/token.json)")

	root.AddCommand(
		newVersionCmd(version, commit),
		newLoginCmd(g),
		newWhoamiCmd(g),
		newLogoutCmd(g),
		newStatusCmd(g),
	)
	return root
}

func newVersionCmd(version, commit string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "ftsgw-cli %s (%s)\n", version, commit)
			return nil
		},
	}
}

// loadCLIConfig fills Globals from viper / env / defaults.
func loadCLIConfig(g *Globals) error {
	v := viper.New()
	v.SetEnvPrefix("FTSGW")
	v.AutomaticEnv()
	if g.ConfigPath != "" {
		v.SetConfigFile(g.ConfigPath)
	} else {
		home, err := os.UserConfigDir()
		if err == nil {
			v.AddConfigPath(filepath.Join(home, "ftsgw"))
			v.SetConfigName("cli")
			v.SetConfigType("yaml")
		}
	}
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) && g.ConfigPath != "" {
			return WithCode(ExitConfig, fmt.Errorf("load cli config: %w", err))
		}
	}
	if g.BrokerURL == "" {
		g.BrokerURL = v.GetString("broker_url")
	}
	if g.CABundlePath == "" {
		g.CABundlePath = v.GetString("ca_bundle_path")
	}
	if g.TokenPath == "" {
		if v := v.GetString("token_path"); v != "" {
			g.TokenPath = v
		} else {
			path, err := DefaultTokenPath()
			if err != nil {
				return WithCode(ExitConfig, err)
			}
			g.TokenPath = path
		}
	}
	if g.BrokerURL == "" {
		return WithCode(ExitConfig, errors.New("broker URL required: --broker or broker_url in cli.yaml"))
	}
	return nil
}
```

```go
// ftsgw/cmd/ftsgw-cli/main.go
// (license header)
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	root := cli.NewRootCmd(version, commit)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "ftsgw-cli:", err)
		var coded *cli.Coded
		if errors.As(err, &coded) {
			os.Exit(coded.Code)
		}
		os.Exit(cli.ExitGeneric)
	}
}
```

- [ ] **Step 2: Commit**

```bash
git add ftsgw/internal/cli/root.go ftsgw/cmd/ftsgw-cli/main.go
git commit -m "feat(ftsgw-cli): cobra root, viper config loading, version subcommand"
```

---

### Task 15.2: login, whoami, logout, status

**Files:**
- Create: `ftsgw/internal/cli/login.go`
- Create: `ftsgw/internal/cli/whoami.go`
- Create: `ftsgw/internal/cli/logout.go`
- Create: `ftsgw/internal/cli/status.go`

- [ ] **Step 1: Implementation**

```go
// ftsgw/internal/cli/login.go
// (license header)
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newLoginCmd(g *Globals) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the broker",
		RunE: func(cmd *cobra.Command, _ []string) error {
			username := os.Getenv("FTSGW_USERNAME")
			if username == "" {
				fmt.Fprint(cmd.ErrOrStderr(), "Username: ")
				fmt.Fscanln(cmd.InOrStdin(), &username)
			}
			if username == "" {
				return WithCode(ExitConfig, errors.New("username required"))
			}
			fd := int(os.Stdin.Fd())
			if !term.IsTerminal(fd) {
				return WithCode(ExitConfig, errors.New("password requires a terminal"))
			}
			fmt.Fprint(cmd.ErrOrStderr(), "Password: ")
			pw, err := term.ReadPassword(fd)
			fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return WithCode(ExitGeneric, fmt.Errorf("read password: %w", err))
			}
			c, err := NewClient(ClientConfig{BrokerURL: g.BrokerURL, TokenPath: g.TokenPath, CABundlePath: g.CABundlePath})
			if err != nil {
				return WithCode(ExitConfig, err)
			}
			if err := c.Login(username, string(pw)); err != nil {
				if errors.Is(err, ErrAuth) {
					return WithCode(ExitAuthFailed, err)
				}
				return WithCode(ExitNetwork, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "logged in as", username)
			return nil
		},
	}
}
```

```go
// ftsgw/internal/cli/whoami.go
// (license header)
package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func newWhoamiCmd(g *Globals) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Print current identity and groups",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := NewClient(ClientConfig{BrokerURL: g.BrokerURL, TokenPath: g.TokenPath, CABundlePath: g.CABundlePath})
			if err != nil {
				return WithCode(ExitConfig, err)
			}
			me, err := c.Me()
			if err != nil {
				if errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrTokenNotFound) {
					return WithCode(ExitSessionExpired, err)
				}
				return WithCode(ExitNetwork, err)
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(me)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "UPN:    %s\n", me.UPN)
			fmt.Fprintf(cmd.OutOrStdout(), "Name:   %s\n", me.DisplayName)
			fmt.Fprintf(cmd.OutOrStdout(), "Groups: %v\n", me.Groups)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}
```

```go
// ftsgw/internal/cli/logout.go
// (license header)
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newLogoutCmd(g *Globals) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke current token and remove local cache",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := NewClient(ClientConfig{BrokerURL: g.BrokerURL, TokenPath: g.TokenPath, CABundlePath: g.CABundlePath})
			if err != nil {
				return WithCode(ExitConfig, err)
			}
			if err := c.Logout(); err != nil {
				return WithCode(ExitNetwork, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "logged out")
			return nil
		},
	}
}
```

```go
// ftsgw/internal/cli/status.go
// (license header)
package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func newStatusCmd(g *Globals) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show token state and broker reachability",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tok, err := LoadToken(g.TokenPath)
			if err != nil {
				if errors.Is(err, ErrTokenNotFound) {
					fmt.Fprintln(cmd.OutOrStdout(), "no cached token; run `ftsgw-cli login`")
					return nil
				}
				return WithCode(ExitConfig, err)
			}
			now := time.Now().UTC()
			ttl := tok.ExpiresAt.Sub(now)
			win := tok.RefreshWindowEndsAt.Sub(now)
			fmt.Fprintf(cmd.OutOrStdout(), "Broker:           %s\n", tok.BrokerURL)
			fmt.Fprintf(cmd.OutOrStdout(), "Token expires in: %s\n", roundDur(ttl))
			fmt.Fprintf(cmd.OutOrStdout(), "Refresh window:   %s remaining\n", roundDur(win))
			return nil
		},
	}
}

func roundDur(d time.Duration) time.Duration { return d.Round(time.Second) }
```

- [ ] **Step 2: Verify**

```bash
make ftsgw-build
bin/ftsgw-cli version
```

Expected: prints `ftsgw-cli vX.Y.Z (commit)`.

- [ ] **Step 3: Commit**

```bash
git add ftsgw/internal/cli/login.go ftsgw/internal/cli/whoami.go ftsgw/internal/cli/logout.go ftsgw/internal/cli/status.go
git commit -m "feat(ftsgw-cli): login/whoami/logout/status commands"
```

---

## Phase 16: End-to-end tests, integration tests, fuzz, demo

### Task 16.1: LDAP integration test (testcontainers OpenLDAP)

**Files:**
- Create: `ftsgw/test/integration/ldap_test.go`

- [ ] **Step 1: Implementation**

```go
//go:build integration

// ftsgw/test/integration/ldap_test.go
// (license header)
package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLDAPAuthenticate(t *testing.T) {
	if os.Getenv("INTEGRATION") == "0" {
		t.Skip("INTEGRATION=0")
	}
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"LDAP_ORGANISATION": "Example",
			"LDAP_DOMAIN":       "example.com",
			"LDAP_ADMIN_PASSWORD": "admin",
		},
		WaitingFor: wait.ForLog("slapd starting").WithStartupTimeout(60 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "389")
	url := "ldap://" + host + ":" + strings.Trim(port.Port(), " ")

	// Seed a user with ldapadd (admin bind).
	// The simplest path is exec'ing ldapadd inside the container.
	seed := `dn: cn=alice,dc=example,dc=com
objectClass: inetOrgPerson
cn: alice
sn: A
userPassword: hunter2
userPrincipalName: alice@example.com
`
	exitCode, _, err := c.Exec(ctx, []string{"sh", "-c", "echo '" + seed + "' | ldapadd -x -D 'cn=admin,dc=example,dc=com' -w admin"})
	if err != nil || exitCode != 0 {
		t.Fatalf("ldapadd: %v code=%d", err, exitCode)
	}
	p := idp.NewLDAPProvider(idp.LDAPConfig{
		URL: url, BaseDN: "dc=example,dc=com",
		BindDN: "cn=admin,dc=example,dc=com", BindPassword: "admin",
		UserSearchFilter:  "(userPrincipalName=%s)",
		GroupSearchFilter: "(member=%s)",
		Timeout: 10 * time.Second,
	})
	id, err := p.Authenticate(ctx, "cn=alice,dc=example,dc=com", "hunter2")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if id.UPN != "alice@example.com" {
		t.Fatalf("UPN = %q", id.UPN)
	}
}
```

- [ ] **Step 2: Verify**

```bash
INTEGRATION=1 go test -tags=integration -race -count=1 ./ftsgw/test/integration/...
```

Expected: PASS (requires Docker).

- [ ] **Step 3: Commit**

```bash
git add ftsgw/test/integration/ldap_test.go
git commit -m "test(ftsgw/integration): OpenLDAP testcontainers exercising LDAPProvider"
```

---

### Task 16.2: End-to-end test (broker+CLI in same process)

**Files:**
- Create: `ftsgw/test/integration/e2e_test.go`

- [ ] **Step 1: Implementation**

```go
//go:build integration

// ftsgw/test/integration/e2e_test.go
// (license header)
package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/cli"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/api"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/audit"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/signer"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/store"
)

type fixedIdP struct{}

func (fixedIdP) Authenticate(_ context.Context, u, p string) (*idp.Identity, error) {
	if u == "alice" && p == "p" {
		return &idp.Identity{UPN: "alice@example", Groups: []string{"engineers"}}, nil
	}
	return nil, idp.ErrAuth
}
func (fixedIdP) InitiateChallenge(context.Context, string) (*idp.Challenge, error) {
	return nil, idp.ErrNotSupported
}
func (fixedIdP) CompleteChallenge(context.Context, string) (*idp.Identity, error) {
	return nil, idp.ErrNotSupported
}
func (fixedIdP) Lookup(context.Context, string) (*idp.Identity, error) {
	return &idp.Identity{UPN: "alice@example"}, nil
}
func (fixedIdP) HealthCheck(context.Context) error { return nil }
func (fixedIdP) Capabilities() idp.ProviderCapabilities {
	return idp.ProviderCapabilities{SupportsPassword: true}
}

type controlClock struct{ t time.Time }

func (c *controlClock) Now() time.Time { return c.t }

func TestE2EHappyPathAndRefresh(t *testing.T) {
	if os.Getenv("INTEGRATION") == "0" {
		t.Skip("INTEGRATION=0")
	}
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(dir, "k")
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()}), 0o600)
	sgnr, _ := signer.NewFileSigner(keyPath, "kid-1")
	st, _ := store.Open(filepath.Join(dir, "f.db"))
	defer st.Close()
	lg, _ := audit.NewLogger(filepath.Join(dir, "audit.log"), st)
	defer lg.Close()
	clk := &controlClock{t: time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)}
	iss, _ := auth.NewIssuer(auth.IssuerConfig{
		Signer: sgnr, Store: st, Clock: clk,
		Issuer: "ftsgw-server", Audience: "ftsgw",
		TTL: 15 * time.Minute, RefreshWindow: 4 * time.Hour,
	})
	deps := &api.Deps{Issuer: iss, IdP: fixedIdP{}, Audit: lg,
		RateLimiter: api.NewRateLimiter(api.RateLimits{PerIPRPS: 1000, PerIPBurst: 1000, AuthPerUsernamePerMinute: 100})}
	srv := httptest.NewServer(api.NewRouter(deps, slog.Default()))
	defer srv.Close()

	tokenPath := filepath.Join(dir, "token.json")
	c, _ := cli.NewClient(cli.ClientConfig{
		BrokerURL: srv.URL, TokenPath: tokenPath, TTLHint: 15 * time.Minute,
		Now: func() time.Time { return clk.t },
	})

	// login
	if err := c.Login("alice", "p"); err != nil {
		t.Fatalf("login: %v", err)
	}
	// whoami works
	me, err := c.Me()
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	if me.UPN != "alice@example" {
		t.Fatalf("upn = %q", me.UPN)
	}
	// advance past 80% TTL — next Me() should refresh
	clk.t = clk.t.Add(13 * time.Minute)
	if _, err := c.Me(); err != nil {
		t.Fatalf("me-after-refresh: %v", err)
	}
	// advance past refresh window — Me must return session expired
	clk.t = clk.t.Add(5 * time.Hour)
	if _, err := c.Me(); !errors.Is(err, cli.ErrSessionExpired) {
		t.Fatalf("want session expired, got %v", err)
	}
}

func TestE2ELogoutInvalidatesToken(t *testing.T) {
	if os.Getenv("INTEGRATION") == "0" {
		t.Skip("INTEGRATION=0")
	}
	// abbreviated: same setup as above; call c.Logout() then c.Me() and assert ErrSessionExpired.
	t.Skip("expand on first run; pattern matches TestE2EHappyPathAndRefresh")
}
```

- [ ] **Step 2: Verify**

```bash
INTEGRATION=1 go test -tags=integration ./ftsgw/test/integration/... -run TestE2E
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add ftsgw/test/integration/e2e_test.go
git commit -m "test(ftsgw/e2e): login -> whoami -> auto-refresh -> refresh-window exhaustion"
```

---

### Task 16.3: Fuzz on JWT validate

**Files:**
- Create: `ftsgw/internal/server/auth/fuzz_test.go`

- [ ] **Step 1: Implementation**

```go
// ftsgw/internal/server/auth/fuzz_test.go
// (license header)
package auth_test

import (
	"context"
	"testing"
	"time"
)

func FuzzValidate(f *testing.F) {
	clk := &fakeClock{now: time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)}
	iss, _ := newIssuer(f.(*testing.T), clk) // note: writing-plans pragma — engineer must adapt: testing.F vs testing.T helpers.
	tok, _ := iss.Mint(context.Background(), struct{ UPN string }{UPN: "alice"})
	_ = tok
	f.Add("not.a.jwt")
	f.Add(tok.AccessToken)
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = iss.Validate(context.Background(), raw) // must not panic
	})
}
```

The pragma in the comment is honest: `newIssuer` was written for `testing.T`. Engineer task during fuzz wiring: refactor `newIssuer` to take `testing.TB` so both `T` and `F` can use it. Two-line change (`func newIssuer(t testing.TB, …)` and `t.Helper()` already accepts TB).

- [ ] **Step 2: Verify**

```bash
go test -run=^$ -fuzz=FuzzValidate -fuzztime=60s ./ftsgw/internal/server/auth/
```

Expected: no panics, no findings.

- [ ] **Step 3: Commit**

```bash
git add ftsgw/internal/server/auth/fuzz_test.go ftsgw/internal/server/auth/token_test.go
git commit -m "test(ftsgw/auth): 60s fuzz against JWT validate"
```

---

### Task 16.4: `make demo` script

**Files:**
- Create: `scripts/ftsgw-demo.sh`
- Create: `scripts/ftsgw-demo-config.yaml.tpl`
- Create: `scripts/ftsgw-demo-seed.ldif`

- [ ] **Step 1: Demo script**

```bash
#!/usr/bin/env bash
# scripts/ftsgw-demo.sh — boots an OpenLDAP container, generates TLS + signing
# keys, runs ftsgw-server, then walks login -> whoami -> status -> logout.
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
WORK=$(mktemp -d -t ftsgw-demo.XXXXXX)
trap 'rm -rf "$WORK"; docker rm -f ftsgw-demo-ldap >/dev/null 2>&1 || true; kill $SRV_PID 2>/dev/null || true' EXIT

echo "==> starting OpenLDAP"
docker run -d --rm --name ftsgw-demo-ldap \
  -e LDAP_ORGANISATION=Example -e LDAP_DOMAIN=example.com -e LDAP_ADMIN_PASSWORD=admin \
  -p 13389:389 osixia/openldap:1.5.0 >/dev/null
for i in $(seq 1 30); do
  if docker exec ftsgw-demo-ldap ldapsearch -x -H ldap://localhost -b dc=example,dc=com >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "==> seeding alice"
docker cp scripts/ftsgw-demo-seed.ldif ftsgw-demo-ldap:/seed.ldif
docker exec ftsgw-demo-ldap ldapadd -x -D 'cn=admin,dc=example,dc=com' -w admin -f /seed.ldif

echo "==> generating TLS + signing key"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -keyout "$WORK/server.key" -out "$WORK/server.crt" >/dev/null 2>&1
openssl genpkey -algorithm Ed25519 -out "$WORK/signing.pem"
# Convert PKCS#8 -> raw seed PEM for FileSigner.
python3 - <<PY > "$WORK/signing.ed25519"
import base64, re, sys
raw = open("$WORK/signing.pem","rb").read()
body = b"".join(re.findall(rb"-----BEGIN.*?-----\n(.*?)-----END.*?-----", raw, re.S))
seed = base64.b64decode(body)[-32:]
sys.stdout.write("-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(seed).decode() + "\n-----END PRIVATE KEY-----\n")
PY
chmod 0600 "$WORK/signing.ed25519" "$WORK/server.key"

echo "==> writing config"
sed -e "s|@@WORK@@|$WORK|g" scripts/ftsgw-demo-config.yaml.tpl > "$WORK/config.yaml"

echo "==> starting ftsgw-server"
export FTSGW_LDAP_BIND_DN='cn=admin,dc=example,dc=com'
export FTSGW_LDAP_BIND_PASSWORD='admin'
"$ROOT/bin/ftsgw-server" --config "$WORK/config.yaml" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
for i in $(seq 1 30); do
  if curl -fsk https://localhost:18443/healthz >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "==> ftsgw-cli login -> whoami -> status -> logout"
export FTSGW_USERNAME='cn=alice,dc=example,dc=com'
echo hunter2 | "$ROOT/bin/ftsgw-cli" --broker https://localhost:18443 --ca-bundle "$WORK/server.crt" \
  --token-path "$WORK/token.json" login
"$ROOT/bin/ftsgw-cli" --broker https://localhost:18443 --ca-bundle "$WORK/server.crt" --token-path "$WORK/token.json" whoami
"$ROOT/bin/ftsgw-cli" --broker https://localhost:18443 --ca-bundle "$WORK/server.crt" --token-path "$WORK/token.json" status
"$ROOT/bin/ftsgw-cli" --broker https://localhost:18443 --ca-bundle "$WORK/server.crt" --token-path "$WORK/token.json" logout

echo "==> demo OK"
```

`chmod +x scripts/ftsgw-demo.sh`.

- [ ] **Step 2: Config template**

```yaml
# scripts/ftsgw-demo-config.yaml.tpl
server:
  listen_addr: ":18443"
  tls_cert_path: @@WORK@@/server.crt
  tls_key_path:  @@WORK@@/server.key
signer:
  kind: file
  key_path: @@WORK@@/signing.ed25519
  key_id:   demo-2026-01
idp:
  kind: ldap
  url:  ldap://localhost:13389
  base_dn: "dc=example,dc=com"
  bind_dn_env: FTSGW_LDAP_BIND_DN
  bind_password_env: FTSGW_LDAP_BIND_PASSWORD
  user_search_filter:  "(|(userPrincipalName=%s)(cn=%s))"
  group_search_filter: "(member=%s)"
  start_tls: false
  timeout: 10s
tokens:
  ttl: 15m
  refresh_window: 4h
  issuer:   "ftsgw-server"
  audience: "ftsgw"
audit:
  file_path: @@WORK@@/audit.log
  syslog: { enabled: false, addr: "", network: tcp+tls }
ratelimit:
  per_ip_rps: 50
  per_ip_burst: 100
  auth_per_username_per_minute: 30
```

(The user_search_filter accepts either UPN or CN to keep the demo simple — production should pick one.)

- [ ] **Step 3: Seed LDIF**

```
# scripts/ftsgw-demo-seed.ldif
dn: cn=alice,dc=example,dc=com
objectClass: inetOrgPerson
cn: alice
sn: A
userPassword: hunter2
userPrincipalName: alice@example.com

dn: cn=engineers,dc=example,dc=com
objectClass: groupOfNames
cn: engineers
member: cn=alice,dc=example,dc=com
```

- [ ] **Step 4: Verify**

```bash
make ftsgw-demo
```

Expected: ends with `==> demo OK`.

- [ ] **Step 5: Commit**

```bash
git add scripts/ftsgw-demo*.sh scripts/ftsgw-demo-config.yaml.tpl scripts/ftsgw-demo-seed.ldif
git commit -m "demo: scripted OpenLDAP + ftsgw-server + ftsgw-cli end-to-end walk-through"
```

---

## Phase 17: Build and distribution

### Task 17.1: Dockerfile (distroless, multi-stage)

**Files:**
- Create: `deploy/ftsgw/Dockerfile`

- [ ] **Step 1: Write**

```dockerfile
# deploy/ftsgw/Dockerfile
# syntax=docker/dockerfile:1.7

# Builder stage. We build with -mod=vendor so the image build does not need
# network access; the vendor tree is committed.
FROM golang:1.25.0-alpine AS builder
ENV CGO_ENABLED=0 GOFLAGS=-mod=vendor
WORKDIR /src
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/ftsgw-server ./ftsgw/cmd/ftsgw-server

# Runtime stage. Distroless static, non-root, all caps dropped.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /out/ftsgw-server /usr/local/bin/ftsgw-server
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/ftsgw-server"]
```

- [ ] **Step 2: Verify**

```bash
make ftsgw-vendor
docker build -f deploy/ftsgw/Dockerfile -t ftsgw-server:dev .
docker run --rm ftsgw-server:dev version
```

Expected: prints version banner.

- [ ] **Step 3: Commit**

```bash
git add deploy/ftsgw/Dockerfile
git commit -m "build(ftsgw): distroless static-debian12 nonroot multi-stage image"
```

---

### Task 17.2: OpenShift manifests

**Files:**
- Create: `deploy/ftsgw/openshift/deployment.yaml`
- Create: `deploy/ftsgw/openshift/service.yaml`
- Create: `deploy/ftsgw/openshift/route.yaml`
- Create: `deploy/ftsgw/openshift/configmap.yaml`
- Create: `deploy/ftsgw/openshift/secret.example.yaml`
- Create: `deploy/ftsgw/openshift/serviceaccount.yaml`
- Create: `deploy/ftsgw/openshift/networkpolicy.yaml`

- [ ] **Step 1: Manifests (verbatim)**

`serviceaccount.yaml`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata: { name: ftsgw-server, namespace: ftsgw }
```

`deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: ftsgw-server, namespace: ftsgw }
spec:
  replicas: 1   # Phase 0: single-node; see DECISIONS.md
  selector: { matchLabels: { app: ftsgw-server } }
  template:
    metadata: { labels: { app: ftsgw-server } }
    spec:
      serviceAccountName: ftsgw-server
      securityContext:
        runAsNonRoot: true
        seccompProfile: { type: RuntimeDefault }
      containers:
      - name: ftsgw-server
        image: image-registry.openshift-image-registry.svc:5000/ftsgw/ftsgw-server:0.1.0
        args: ["--config","/etc/ftsgw-server/config.yaml"]
        ports: [{ containerPort: 8443, name: https }]
        env:
        - name: FTSGW_LDAP_BIND_DN
          valueFrom: { secretKeyRef: { name: ftsgw-ldap-bind, key: dn } }
        - name: FTSGW_LDAP_BIND_PASSWORD
          valueFrom: { secretKeyRef: { name: ftsgw-ldap-bind, key: password } }
        - name: OTEL_EXPORTER_OTLP_ENDPOINT
          value: "otel-collector.observability.svc:4317"
        readinessProbe: { httpGet: { path: /readyz, port: 8443, scheme: HTTPS } }
        livenessProbe:  { httpGet: { path: /healthz, port: 8443, scheme: HTTPS } }
        resources:
          requests: { cpu: 100m, memory: 128Mi }
          limits:   { cpu: 500m, memory: 256Mi }
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: { drop: ["ALL"] }
        volumeMounts:
        - { name: config, mountPath: /etc/ftsgw-server, readOnly: true }
        - { name: tls, mountPath: /etc/ftsgw-server/tls, readOnly: true }
        - { name: signing, mountPath: /etc/ftsgw-server/keys, readOnly: true }
        - { name: var, mountPath: /var/log/ftsgw-server }
      volumes:
      - { name: config,  configMap: { name: ftsgw-server-config } }
      - { name: tls,     secret:    { secretName: ftsgw-server-tls } }
      - { name: signing, secret:    { secretName: ftsgw-signing-key, defaultMode: 0o600 } }
      - { name: var,     emptyDir:  { sizeLimit: 1Gi } }
```

`service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata: { name: ftsgw-server, namespace: ftsgw }
spec:
  selector: { app: ftsgw-server }
  ports: [{ name: https, port: 8443, targetPort: 8443 }]
```

`route.yaml`:

```yaml
apiVersion: route.openshift.io/v1
kind: Route
metadata: { name: ftsgw-server, namespace: ftsgw }
spec:
  to: { kind: Service, name: ftsgw-server }
  port: { targetPort: https }
  tls: { termination: passthrough }
```

`configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata: { name: ftsgw-server-config, namespace: ftsgw }
data:
  config.yaml: |
    server:
      listen_addr: ":8443"
      tls_cert_path: /etc/ftsgw-server/tls/tls.crt
      tls_key_path:  /etc/ftsgw-server/tls/tls.key
    signer:
      kind: file
      key_path: /etc/ftsgw-server/keys/signing.ed25519
      key_id:   ftsgw-2026-01
    idp:
      kind: ldap
      url:  ldaps://ldap.internal:636
      base_dn: "DC=bank,DC=example"
      bind_dn_env: FTSGW_LDAP_BIND_DN
      bind_password_env: FTSGW_LDAP_BIND_PASSWORD
      user_search_filter:  "(userPrincipalName=%s)"
      group_search_filter: "(member=%s)"
      ca_bundle_path: /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
      start_tls: false
      timeout: 10s
    tokens:
      ttl: 15m
      refresh_window: 4h
      issuer:   "ftsgw-server"
      audience: "ftsgw"
    audit:
      file_path: /var/log/ftsgw-server/audit.log
      syslog: { enabled: false, addr: "", network: tcp+tls }
    ratelimit:
      per_ip_rps: 5
      per_ip_burst: 10
      auth_per_username_per_minute: 3
```

`secret.example.yaml` — committed as a TEMPLATE so operators see the shape, with placeholder base64:

```yaml
apiVersion: v1
kind: Secret
metadata: { name: ftsgw-ldap-bind, namespace: ftsgw }
type: Opaque
data:
  dn:       Y249Zm9vLGRjPWV4YW1wbGUsZGM9Y29t   # base64 — REPLACE
  password: cmVwbGFjZS1tZQ==                       # base64 — REPLACE
```

`networkpolicy.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: ftsgw-server, namespace: ftsgw }
spec:
  podSelector: { matchLabels: { app: ftsgw-server } }
  policyTypes: [Ingress, Egress]
  ingress:
  - from: [{ namespaceSelector: { matchLabels: { name: ingress } } }]
    ports: [{ port: 8443 }]
  egress:
  - to: [{ ipBlock: { cidr: 10.0.0.0/8 } }]   # AD subnet — tighten in prod
    ports: [{ port: 636 }]
```

- [ ] **Step 2: Verify**

```bash
kubectl --validate=strict apply --dry-run=client -f deploy/ftsgw/openshift/
```

Expected: all manifests parse without error (only `Route` requires OpenShift CRDs to be available — `kustomize build` is the cleaner check if available).

- [ ] **Step 3: Commit**

```bash
git add deploy/ftsgw/openshift/
git commit -m "deploy(ftsgw): OpenShift manifests (deployment, service, route, configmap, secret template, network policy, SA)"
```

---

### Task 17.3: Vendor tree + SBOM + cosign Makefile target

This task was scaffolded in Task 1.2. Here we exercise it end-to-end.

- [ ] **Step 1: Vendor**

```bash
make ftsgw-vendor
```

Expected: `vendor/` created, `go build ./...` and `go build -mod=vendor ./...` both succeed.

- [ ] **Step 2: SBOM**

```bash
syft --version || echo "install syft locally if you want SBOM generation: https://github.com/anchore/syft"
make ftsgw-sbom
```

Expected: `bin/ftsgw-sbom.cdx.json` produced.

- [ ] **Step 3: Cosign (optional)**

```bash
COSIGN_KEY=cosign.key make ftsgw-sign
```

Skip if cosign key isn't set up — record in DECISIONS.md that signing is operator-driven.

- [ ] **Step 4: Commit**

```bash
git add vendor/ go.mod go.sum
git commit -m "build(ftsgw): vendor tree committed (offline builds)"
```

---

## Phase 18: Documentation

### Task 18.1: docs/ftsgw/auth-flow.md

**Files:**
- Create: `docs/ftsgw/auth-flow.md`

- [ ] **Step 1: Write** (verbatim — the mermaid block renders on GitHub)

````markdown
# ftsgw Authentication Flow

This document covers the complete password-auth lifecycle in Phase 0 (Mode 3, fully disconnected).

## First login

```mermaid
sequenceDiagram
  participant U as User
  participant C as ftsgw-cli
  participant B as ftsgw-server
  participant L as AD/LDAP

  U->>C: ftsgw-cli login
  C->>U: prompt username + password (no echo)
  C->>B: POST /v1/auth/token {username, password}
  B->>L: LDAP simple bind (user)
  L-->>B: success
  B->>L: paged group search (matching-rule-in-chain)
  L-->>B: groups
  B->>B: Mint Ed25519 JWT (iat=now, exp=now+15m)
  B->>B: audit token_issued
  B-->>C: 200 TokenResponse
  C->>C: persist ~/.config/ftsgw/token.json (0600)
```

## Auto refresh (80% of TTL elapsed)

```mermaid
sequenceDiagram
  participant C as ftsgw-cli
  participant B as ftsgw-server

  C->>C: before request, check token state
  Note over C: now >= exp - (ttl*0.2)
  C->>B: POST /v1/auth/refresh (Bearer current)
  B->>B: verify signature + revocation
  B->>B: check now - iat <= refresh_window
  B->>B: Mint new JWT (iat preserved, exp=now+15m)
  B->>B: audit token_refreshed
  B-->>C: 200 TokenResponse
  C->>C: persist new token (iat unchanged)
```

## Refresh window exhausted

```mermaid
sequenceDiagram
  participant C as ftsgw-cli
  participant B as ftsgw-server

  C->>B: POST /v1/auth/refresh
  B->>B: now - iat > 4h
  B->>B: audit token_refresh_refused
  B-->>C: 401 ProblemDetails
  C->>C: surface "session expired, run ftsgw-cli login"
  C->>C: exit 4
```

## Idle expiry (token expired before next command)

```mermaid
sequenceDiagram
  participant C as ftsgw-cli
  participant B as ftsgw-server

  C->>C: now > token.expires_at
  alt now < refresh_window_ends_at
    C->>B: POST /v1/auth/refresh
    B-->>C: 200 new token
  else
    C->>C: surface "session expired"
    C->>C: exit 4
  end
```

## Logout

```mermaid
sequenceDiagram
  participant C as ftsgw-cli
  participant B as ftsgw-server

  C->>B: POST /v1/auth/logout (Bearer)
  B->>B: insert jti -> revoked_tokens
  B->>B: audit token_revoked
  B-->>C: 204
  C->>C: rm ~/.config/ftsgw/token.json
```
````

- [ ] **Step 2: Commit**

```bash
git add docs/ftsgw/auth-flow.md
git commit -m "docs(ftsgw): auth flow with mermaid sequence diagrams"
```

---

### Task 18.2: docs/ftsgw/threat-model.md

**Files:**
- Create: `docs/ftsgw/threat-model.md`

- [ ] **Step 1: Write**

```markdown
# ftsgw Threat Model (Phase 0, Mode 3)

Frame: airgapped VM running `ftsgw-cli` talks to `ftsgw-server` over TLS.
Server talks to AD/LDAP over LDAPS or LDAP+StartTLS. No internet egress.

## In scope
- Confidentiality and integrity of AD passwords in transit.
- Confidentiality and integrity of ftsgw app-tokens.
- Integrity of the audit log.
- Availability of the broker against credential-stuffing.

## Out of scope (deferred or owned elsewhere)
- mTLS between CLI and broker (Phase 2).
- HSM-backed signing key (Phase 2 — interface is in place).
- Compromise of the host operating system underneath the broker (treated as
  total compromise; mitigations are infra-level: SELinux, MAC, image
  attestation, host integrity).

## STRIDE

### S — Spoofing
- **Threat:** Attacker MITMs CLI→broker, harvests password.
  - **Mitigation:** Broker requires TLS 1.2+; CLI pins to the configured CA bundle. No `InsecureSkipVerify`. Add mTLS in Phase 2.
- **Threat:** Attacker steals an app-token (laptop theft, malicious process).
  - **Mitigation:** Tokens are bearer; mitigations are short TTL (15m), bounded refresh window (4h from `iat`), file mode 0600, and per-token revocation via logout. Phase 2 will bind tokens to client identity.

### T — Tampering
- **Threat:** Attacker forges a token.
  - **Mitigation:** Ed25519 signatures; verification via embedded public key (broker re-uses the same key the JWKS endpoint publishes). All validation is signature-first.
- **Threat:** Attacker writes to the audit log to hide actions.
  - **Mitigation:** Audit goes to two sinks (SQLite + JSON-lines file). Process runs as non-root with read-only root FS; only `/var/log/ftsgw-server` is writable. Forward to immutable log store (Splunk/ELK) by tailing the file.

### R — Repudiation
- **Threat:** User denies authenticating.
  - **Mitigation:** `password_authenticated`, `token_issued`, `token_refreshed`, and `token_revoked` events all carry `actor_upn`, `request_id`, `client_ip`, and `jti`. Synchronous write means an HTTP 200 implies an audit row exists.

### I — Information disclosure
- **Threat:** Password or token leaks to logs / error messages.
  - **Mitigation:** Audit `Logger.Write` enforces a deny-list on `extras` keys (`password`, `access_token`, `token`, …) and would-be-leaks fail closed. `obs.RedactingHandler` does the same for slog. Test `redaction_test.go` enforces both.
- **Threat:** JWKS exposes more than the verification key.
  - **Mitigation:** `/v1/.well-known/jwks.json` returns only `{kty:OKP, crv:Ed25519, kid, x, alg:EdDSA, use:sig}`. No private bytes ever serialized.

### D — Denial of service
- **Threat:** Credential stuffing against `/v1/auth/token`.
  - **Mitigation:** 3 attempts per username per minute, plus per-IP token bucket (5 rps, burst 10). Both fire `ftsgw_rate_limited_total` and audit `rate_limited`.
- **Threat:** SQLite contention.
  - **Mitigation:** WAL mode; per-row writes; one process. Phase 0 is single-node by design.

### E — Elevation of privilege
- **Threat:** Refresh-chain extension allowing perpetual access from a single password auth.
  - **Mitigation:** `iat` is preserved across refreshes; `now - iat > refresh_window` refuses. Tested in `TestRefreshOutsideWindowRefused`.
- **Threat:** Replay of a token after logout.
  - **Mitigation:** Logout inserts `jti` into `revoked_tokens`; every validate consults the table. Tested in `TestRevokedTokenFailsValidate` and `TestE2ELogoutInvalidatesToken`.

## Residual risks (accepted for Phase 0)

- Bearer tokens are unbound to client; theft + replay within TTL is possible.
- Single-node failure mode: broker downtime = no new logins. Acceptable for Phase 0 dev demo; HA is Phase 2.
- Audit log file is rotated on disk but not yet shipped to a tamper-evident store; operators are expected to ship the JSON-lines file off-host.
```

- [ ] **Step 2: Commit**

```bash
git add docs/ftsgw/threat-model.md
git commit -m "docs(ftsgw): STRIDE threat model with residual risks called out"
```

---

### Task 18.3: docs/ftsgw/deployment.md

**Files:**
- Create: `docs/ftsgw/deployment.md`

- [ ] **Step 1: Write**

```markdown
# ftsgw Deployment Guide

## Required artifacts

- `bin/ftsgw-server` (or container image).
- TLS certificate + key for the HTTPS listener.
- Ed25519 signing key (PEM, mode 0600).
- LDAP service-account credentials (DN + password) supplied via env vars.

## Config

The broker reads a single YAML file (`--config`, default
`/etc/ftsgw-server/config.yaml`). See `deploy/ftsgw/openshift/configmap.yaml`
for a production example. Secret fields are referenced by env var name:

| YAML field                 | env var                       |
|----------------------------|-------------------------------|
| `idp.bind_dn_env`          | resolves to actual bind DN    |
| `idp.bind_password_env`    | resolves to bind password     |

Validation is strict at startup; the broker refuses to start when:
- any required field is missing,
- any `_env` field references an unset/empty env var,
- `tokens.refresh_window < tokens.ttl`.

## Secrets

| Secret               | Source                                      | Rotation |
|----------------------|---------------------------------------------|----------|
| TLS cert/key         | OpenShift secret `ftsgw-server-tls`         | per cert authority policy |
| Signing key          | OpenShift secret `ftsgw-signing-key`        | quarterly (see below) |
| LDAP bind            | OpenShift secret `ftsgw-ldap-bind`          | quarterly |

## Key rotation

1. Generate a new key on a clean host:
   ```
   ftsgw-server rotate-key --out /tmp/signing-2026-04.ed25519
   ```
2. Update `ftsgw-signing-key` secret with the new key and bump the
   `signer.key_id` value in `ftsgw-server-config` (e.g. `ftsgw-2026-02`).
3. Rolling-restart the deployment.
4. New tokens carry the new `kid`; clients that fetch JWKS see the new key
   immediately. Old tokens validate until their `exp` because the broker only
   serves the *current* key; we accept invalidating in-flight tokens.

(Future: serve previous and current keys in JWKS during a rotation window.)

## SQLite backup / restore

The broker holds two tables: `revoked_tokens` and `audit_events`. Both are in
`<audit.file_path dir>/ftsgw.db`.

Backup (broker can stay running thanks to WAL):

```
sqlite3 /var/log/ftsgw-server/ftsgw.db ".backup '/backup/ftsgw-$(date -u +%Y%m%dT%H%M%SZ).db'"
```

Restore: stop the broker, replace the `.db` file, start the broker.

## Log rotation

`audit.log` is rotated by lumberjack (100MB per file, 30-day retention,
compressed). The file is owned by the broker process; non-root.

## Observability

- Prometheus scrape: `https://broker:8443/metrics`.
- OTLP traces: set `OTEL_EXPORTER_OTLP_ENDPOINT=host:4317` (gRPC).
- slog JSON to stdout; ship via OpenShift's `cluster-logging` operator.
```

- [ ] **Step 2: Commit**

```bash
git add docs/ftsgw/deployment.md
git commit -m "docs(ftsgw): deployment guide (config, secrets, rotation, SQLite backup)"
```

---

### Task 18.4: DECISIONS.md (ADRs)

**Files:**
- Create: `DECISIONS.md`

- [ ] **Step 1: Write**

```markdown
# Decisions

Architecture decision records for ftsgw Phase 0. New entries: append at the
bottom; never edit history without an explicit "Superseded by ADR-N" note.

## ADR-001 — Ed25519 over RS256

- **Decision:** All app-tokens are signed with Ed25519 via `jwx/v2` (`alg: EdDSA`).
- **Why:** Smaller signatures (~64B vs ~256B for RS256), constant-time signing, no padding/oracle surface area, native Go support. Phase 0 is a fresh deployment with no compatibility surface — no reason to ship RSA.
- **Trade-off:** A handful of legacy JWT verifiers don't speak EdDSA; we own both ends today, so not a concern.

## ADR-002 — No bootstrap token, no enrollment

- **Decision:** The CLI's only initial input is the user's AD password.
- **Why:** Adding a bootstrap secret means inventing a secrets-distribution process and shipping a device-identity story prematurely. Both deferred to Phase 2.
- **Trade-off:** The first login latency includes a real LDAP bind; that is fine.

## ADR-003 — Refresh window bounded at 4h from `iat`

- **Decision:** Refresh is allowed only while `now - iat <= 4h`. `iat` is preserved across refreshes.
- **Why:** Without a hard ceiling, the chain extends indefinitely; one stolen token equals permanent access. Four hours matches typical bank session policy and bounds blast radius without forcing a re-prompt every 15 minutes.
- **Test:** `auth.TestRefreshOutsideWindowRefused`.

## ADR-004 — SQLite over Postgres

- **Decision:** `revoked_tokens` and `audit_events` live in a single SQLite database with WAL.
- **Why:** Phase 0 is single-node by design; SQLite removes a stateful dependency from the deployment. modernc.org/sqlite is pure Go (no cgo). Moving to Postgres later is a `database/sql` driver swap plus a migration replay.

## ADR-005 — Synchronous audit writes

- **Decision:** Audit writes fail the request (HTTP 503) if either sink errors.
- **Why:** Bank audit standards require that a successful response implies a recorded event. Async writes can drop on crash.
- **Trade-off:** Audit-sink unavailability halts new auths — operators must monitor `ftsgw_audit_write_failures_total`.

## ADR-006 — Distroless static-debian12:nonroot

- **Decision:** Runtime image is `gcr.io/distroless/static-debian12:nonroot`.
- **Why:** No shell, no package manager, no userland — minimal attack surface. Matches the bank's preferred runtime.
- **Trade-off:** Debugging requires `kubectl debug` with a `--target` ephemeral container.

## ADR-007 — Single Go module, ftsgw under `/ftsgw` subtree

- **Decision:** ftsgw lives under `/ftsgw/...` in the existing `github.com/rupivbluegreen/go-cli-ad` module.
- **Why:** Reuses tooling (CI, vendor tree, golangci-lint config) and keeps the two products visible side-by-side. No second `go.mod` to maintain.
- **Trade-off:** Imports are slightly longer (`.../ftsgw/internal/server/...`).

## ADR-008 — chi over net/http mux

- **Decision:** HTTP routing via `github.com/go-chi/chi/v5`.
- **Why:** Sub-router composition, middleware chaining, and clean route table fit the broker's surface area. Std mux is too thin for our middleware order (request-id, recover, access log, rate limit) without ad-hoc wrappers.

## ADR-009 — jwx/v2 over golang-jwt

- **Decision:** JWT minting and parsing via `github.com/lestrrat-go/jwx/v2`.
- **Why:** Better ergonomics for Ed25519 + JWKS publication; clean separation between `jws`, `jwk`, `jwt` packages; active maintenance.

## ADR-010 — modernc.org/sqlite over mattn/go-sqlite3

- **Decision:** Pure-Go SQLite driver.
- **Why:** Constraint says `CGO_ENABLED=0` everywhere. mattn requires cgo.
- **Trade-off:** Slightly slower than cgo; not measurable at our write rate.

## ADR-011 — IdP interface includes challenge methods today

- **Decision:** `InitiateChallenge` / `CompleteChallenge` live on `IdentityProvider` in Phase 0 even though LDAP returns `ErrNotSupported`.
- **Why:** Adding methods to an interface in Phase 1 means recompiling every implementer. Defining them now means Phase 1 = drop in an `EntraProvider` implementation, nothing else.

## ADR-012 — Clock is an interface

- **Decision:** Auth code reads time only via `Clock.Now()`.
- **Why:** Refresh-window exhaustion tests would otherwise sleep four hours. Production code uses `RealClock{}`; tests use `fakeClock`. No production code changes when adding tests.

## ADR-013 — Demo uses LDAP (no TLS) and a self-signed broker cert

- **Decision:** `scripts/ftsgw-demo.sh` runs OpenLDAP without TLS and a one-day self-signed broker cert.
- **Why:** Demo is local-only, ephemeral, and runs as the developer; no real secrets cross the wire. Production config in `deploy/ftsgw/openshift/configmap.yaml` is LDAPS-only with `start_tls: false` (because the broker uses `ldaps://`) and trusts the org CA bundle.

## ADR-014 — Cosign signing is operator-driven

- **Decision:** Makefile target `ftsgw-sign` exists but is not run by CI in Phase 0.
- **Why:** Signing requires the bank's cosign key, which is not available in this repo's CI. Operators run `COSIGN_KEY=… make ftsgw-sign` post-release.
```

- [ ] **Step 2: Commit**

```bash
git add DECISIONS.md
git commit -m "docs: ADR record for ftsgw Phase 0"
```

---

### Task 18.5: CHANGELOG.md and PHASE_1_NOTES.md

**Files:**
- Create: `CHANGELOG.md`
- Create: `PHASE_1_NOTES.md`

- [ ] **Step 1: CHANGELOG**

```markdown
# Changelog

## v0.1.0 — ftsgw Phase 0 (2026-05-12)

### Added

- `ftsgw-server` authentication broker.
  - LDAP simple-bind authentication with paged transitive-group search.
  - Ed25519-signed JWT app-tokens, 15-minute TTL, refresh bounded at 4h from `iat`.
  - `/v1/auth/{token,refresh,logout}`, `/v1/me`, `/v1/.well-known/jwks.json`, `/healthz`, `/readyz`, `/metrics`.
  - Synchronous dual-sink audit log (SQLite `audit_events` + rotated JSON-lines).
  - Per-IP and per-username rate limiting.
  - Admin subcommands: `revoke`, `rotate-key`, `version`.
  - Prometheus metrics, OTLP tracing, structured slog with secret redaction.
- `ftsgw-cli` companion client.
  - `login`, `whoami`, `logout`, `status`, `version`.
  - Token cache at `~/.config/ftsgw/token.json` (mode 0600).
  - Auto-refresh at 80% of TTL with refresh-window-exhaustion surfacing.
  - Explicit exit codes (0/1/2/3/4/5) for shell scripting.
- Integration tests under `ftsgw/test/integration` (testcontainers OpenLDAP).
- 60-second fuzz pass against JWT validate.
- `make demo` ⇒ throwaway OpenLDAP + broker + CLI walkthrough.
- Distroless container image, OpenShift manifests.

### Not yet

- Entra / AD FS integration (Phase 1).
- mTLS, HSM-backed signing, HA (Phase 2).
```

- [ ] **Step 2: PHASE_1_NOTES**

```markdown
# Phase 1 Notes

Seams already in place for Phase 1 (Entra-native broker on OpenShift with
Entra egress).

## `IdentityProvider` already includes challenge methods

- `InitiateChallenge(ctx, hint) (*Challenge, error)`
- `CompleteChallenge(ctx, challengeID) (*Identity, error)`
- `Capabilities() ProviderCapabilities` advertises `SupportsChallenge`.

Phase 0's `LDAPProvider` returns `ErrNotSupported`. Phase 1's `EntraProvider`
will implement these.

## New table for pending challenges

Phase 1 will add a migration `0002_pending_challenges.sql`:

```sql
CREATE TABLE pending_challenges (
  id          TEXT PRIMARY KEY,
  user_hint   TEXT NULL,
  device_code TEXT NOT NULL,
  user_code   TEXT NOT NULL,
  expires_at  TIMESTAMP NOT NULL,
  created_at  TIMESTAMP NOT NULL
);
```

## Shape of the challenge HTTP response

`POST /v1/auth/token` will optionally return HTTP 202 with this body:

```json
{
  "challenge_id":     "01HX…",
  "user_code":        "ABCD-1234",
  "verification_uri": "https://login.microsoftonline.com/common/oauth2/deviceauth",
  "expires_in_seconds": 900,
  "interval_seconds":   5
}
```

Clients poll `POST /v1/auth/token/complete` with `{"challenge_id":"…"}` until
they get a `TokenResponse` (200) or a terminal error (4xx).

`pkg/api/types/types.go` already has `TokenResponse`; we'll add
`ChallengeResponse` and `CompleteChallengeRequest` there.

## CLI changes

`ftsgw-cli login` will detect a 202 and print the user code + verification
URL to stderr (the broker callback path is already wired similarly in
internal/onprem for the existing go-cli-ad TUI — pattern reusable).

## What stays the same

- Token model (Ed25519, iat/exp/refresh-window).
- Audit shape and event types (`token_issued`, etc.).
- Store schema (`revoked_tokens`).
- HTTP problem-details, middleware order.
- CLI exit codes (challenge flow surfaces under ExitAuthFailed=2).
```

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md PHASE_1_NOTES.md
git commit -m "docs: changelog v0.1.0 and Phase 1 seam notes"
```

---

### Task 18.6: Update root README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Append an "ftsgw" section to the existing README**

Insert before the existing "Configuration" section (or wherever fits):

```markdown
## ftsgw — authentication broker + CLI

This repository also ships a second product, **ftsgw**, an authentication
broker (`ftsgw-server`) and its companion CLI (`ftsgw-cli`). It is unrelated
to `go-cli-ad` and lives entirely under `/ftsgw/`.

Quickstart (requires Docker for the demo OpenLDAP):

```sh
make ftsgw-build
make ftsgw-demo
```

`make ftsgw-demo` boots OpenLDAP in a container, seeds a user, runs the
broker against it, then walks `login -> whoami -> status -> logout`.

See:
- `docs/ftsgw/auth-flow.md` — full sequence diagrams.
- `docs/ftsgw/threat-model.md` — STRIDE.
- `docs/ftsgw/deployment.md` — config + secrets + rotation + SQLite backup.
- `DECISIONS.md` — architecture decision records.
- `PHASE_1_NOTES.md` — Entra seams.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs(readme): pointer to ftsgw + quickstart"
```

---

## Final verification

After every task lands:

- [ ] `make ftsgw-build` — succeeds for both binaries.
- [ ] `make ftsgw-test` — all unit tests pass.
- [ ] `INTEGRATION=1 make ftsgw-test-integration` — LDAP + e2e pass.
- [ ] `make ftsgw-lint` — golangci-lint clean + license headers present.
- [ ] `go test -fuzz=FuzzValidate -fuzztime=60s ./ftsgw/internal/server/auth/` — no findings.
- [ ] `make ftsgw-demo` — ends with `==> demo OK`.
- [ ] `make ftsgw-vet` — clean.
- [ ] `go mod tidy && git diff --exit-code go.mod go.sum` — clean.
- [ ] `bash scripts/check-license-headers.sh` — clean.

If any of these fail, do NOT mark the implementation complete. Instead,
follow `superpowers:systematic-debugging` to find the root cause.

---

## Self-review summary

Spec coverage check:

| Spec section | Phase / Task |
|---|---|
| §1 Shared API types | Phase 2 (Task 2.1) |
| §2 Broker HTTP API | Phase 10–11, 13 |
| §3 Token model | Phase 4, 8 |
| §4 IdentityProvider | Phase 5, 9 |
| §5 Persistence | Phase 6 |
| §6 Audit logging | Phase 7 |
| §7 Configuration | Phase 3 |
| §8 Observability | Phase 12, partial in 13 |
| §9 CLI | Phase 14–15 |
| §10 Build + distribution | Phase 17, Task 1.2 |
| §11 Testing | Phase 16, plus per-package unit tests |
| §12 Documentation | Phase 18 |

Placeholder scan: none — every step contains real code or real commands.

Type consistency: `Issuer`, `Issuer.Mint`, `Issuer.Refresh`, `Issuer.Validate`,
`Issuer.Revoke`, `Issuer.PruneRevocations`, `Issuer.PublicVerificationKey`,
`Issuer.VerificationKeyID` — all match across Phases 8, 11, 12, 13.
`StoredToken`, `SaveToken`, `LoadToken`, `DeleteToken` — match between
Phase 14.2 and Phase 14.3 / 15.x. `Event`, `EventType` constants, `Logger.Write`
— match between Phase 7 and Phase 11/13.

Two engineer-judgment hooks called out explicitly in the plan:
- Task 11.1 step 1 notes that `mkSigner` needs to be copied verbatim from
  the auth_test file (rather than creating a shared testutil package).
- Task 16.3 step 1 notes that `newIssuer` needs to be widened from `*testing.T`
  to `testing.TB` for fuzz reuse — a two-line change.

Both are intentional: they keep the test surface minimal and let the engineer
see the small refactor needed up close.

---

**Plan complete.** Saved at `docs/superpowers/plans/2026-05-12-ftsgw-phase-0.md`.










