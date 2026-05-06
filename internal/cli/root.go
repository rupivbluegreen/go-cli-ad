package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type globalOpts struct {
	configPath string
	jsonOut    bool
}

var globals globalOpts

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rogi-cli",
		Short: "Authenticate against Active Directory and list your roles",
		Long: `rogi-cli authenticates against on-premises Active Directory (LDAP)
or Azure AD / Entra ID, then prints the groups and roles you belong to.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.PersistentFlags().StringVar(&globals.configPath, "config", "",
		"path to config file (default: ~/.config/rogi-cli/config.yaml)")
	cmd.PersistentFlags().BoolVar(&globals.jsonOut, "json", false,
		"output results as JSON")

	cmd.AddCommand(newConfigCmd())
	cmd.AddCommand(newOnpremCmd())
	cmd.AddCommand(newAzureCmd())

	return cmd
}

func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		var coded *codedError
		if errors.As(err, &coded) {
			os.Exit(coded.code)
		}
		os.Exit(1)
	}
}
