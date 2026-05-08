package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Onprem OnpremConfig `yaml:"onprem"`
	Azure  AzureConfig  `yaml:"azure"`
}

type OnpremConfig struct {
	Server     string `yaml:"server"`
	BaseDN     string `yaml:"base_dn"`
	Username   string `yaml:"username,omitempty"`
	BindFormat string `yaml:"bind_format,omitempty"`
}

type AzureConfig struct {
	TenantID string `yaml:"tenant_id"`
	ClientID string `yaml:"client_id"`
}

const (
	BindFormatUPN       = "upn"
	BindFormatDownLevel = "down_level"

	DefaultAzureClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
	DefaultAzureTenantID = "common"
)

var ErrNotFound = errors.New("config file not found")

func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating user config dir: %w", err)
	}
	return filepath.Join(dir, "go-cli-ad", "config.yaml"), nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Onprem.BindFormat == "" {
		c.Onprem.BindFormat = BindFormatUPN
	}
	if c.Azure.TenantID == "" {
		c.Azure.TenantID = DefaultAzureTenantID
	}
	if c.Azure.ClientID == "" {
		c.Azure.ClientID = DefaultAzureClientID
	}
}
