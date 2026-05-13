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
	"golang.org/x/term"
)

// Globals captures persistent flags / viper values used by commands.
type Globals struct {
	BrokerURL    string
	CABundlePath string
	TokenPath    string
	ConfigPath   string
}

// tuiRunner is wired by package main when the TUI subpackage is available.
// Keeping it as a package-level hook avoids an import cycle between
// internal/cli and internal/cli/tui (which depends on this package).
var tuiRunner func(g *Globals) error

// SetTUIRunner registers the function that launches the Bubble Tea TUI.
// Called once from package main during program startup.
func SetTUIRunner(fn func(*Globals) error) { tuiRunner = fn }

// NewRootCmd builds the cobra root command tree.
func NewRootCmd(version, commit string) *cobra.Command {
	g := &Globals{}
	root := &cobra.Command{
		Use:           "ftsgw-cli",
		Short:         "ftsgw broker client",
		Long:          "ftsgw-cli is the companion client for the ftsgw broker.\n\nRun with no arguments on a TTY to launch the Bubble Tea TUI.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Name() == "version" {
				return nil
			}
			// The root command's own RunE may launch the TUI on a TTY; tolerate
			// a missing broker URL here and let the TUI surface it instead.
			if cmd.Name() == "ftsgw-cli" {
				_ = loadCLIConfig(g)
				return nil
			}
			return loadCLIConfig(g)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tuiRunner != nil && term.IsTerminal(int(os.Stdout.Fd())) {
				return tuiRunner(g)
			}
			return cmd.Help()
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
		if vp := v.GetString("token_path"); vp != "" {
			g.TokenPath = vp
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
