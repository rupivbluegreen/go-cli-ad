package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/rupivbluegreen/rogi-cli/internal/config"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage rogi-cli configuration",
	}
	cmd.AddCommand(newConfigInitCmd())
	return cmd
}

func newConfigInitCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := globals.configPath
			if path == "" {
				p, err := config.DefaultPath()
				if err != nil {
					return withCode(ExitConfig, err)
				}
				path = p
			}
			if err := config.WriteStarter(path, force); err != nil {
				if errors.Is(err, config.ErrAlreadyExists) {
					return withCode(ExitConfig,
						fmt.Errorf("%s already exists; pass --force to overwrite", path))
				}
				return withCode(ExitConfig, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote starter config to %s\n", path)
			fmt.Fprintln(cmd.OutOrStdout(), "Edit it to point at your AD server and Azure tenant, then run 'rogi-cli onprem login' or 'rogi-cli azure login'.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing config")
	return cmd
}

// loadConfig resolves the path (flag or default) and loads the config.
func loadConfig() (*config.Config, string, error) {
	path := globals.configPath
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return nil, "", withCode(ExitConfig, err)
		}
		path = p
	}
	cfg, err := config.Load(path)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return nil, path, withCode(ExitConfig,
				fmt.Errorf("config file not found at %s — run 'rogi-cli config init'", path))
		}
		return nil, path, withCode(ExitConfig, err)
	}
	return cfg, path, nil
}
