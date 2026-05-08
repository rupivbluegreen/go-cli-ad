package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/rupivbluegreen/go-cli-ad/internal/tui"
)

type globalOpts struct {
	configPath string
	jsonOut    bool
}

var globals globalOpts

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "go-cli-ad",
		Short: "Authenticate against Active Directory and list your roles",
		Long: `go-cli-ad authenticates against on-premises Active Directory (LDAP)
or Azure AD / Entra ID, then prints the groups and roles you belong to.

Run with no arguments on a TTY to launch the Bubble Tea TUI.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if term.IsTerminal(int(os.Stdout.Fd())) {
				return tui.Run(globals.configPath)
			}
			return cmd.Help()
		},
	}

	cmd.PersistentFlags().StringVar(&globals.configPath, "config", "",
		"path to config file (default: ~/.config/go-cli-ad/config.yaml)")
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
