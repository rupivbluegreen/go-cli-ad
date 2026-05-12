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
	PerIPRPS                 int `yaml:"per_ip_rps"`
	PerIPBurst               int `yaml:"per_ip_burst"`
	AuthPerUsernamePerMinute int `yaml:"auth_per_username_per_minute"`
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
