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
	defer func() { _ = st.Close() }()

	auditLg, err := audit.NewLogger(cfg.Audit.FilePath, st)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer func() { _ = auditLg.Close() }()
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
