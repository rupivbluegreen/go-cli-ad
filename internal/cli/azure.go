package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/spf13/cobra"
	"github.com/rupivbluegreen/rogi-cli/internal/azure"
	"github.com/rupivbluegreen/rogi-cli/internal/output"
)

func newAzureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "azure",
		Short: "Authenticate against Azure AD / Entra ID via device code flow",
	}
	cmd.AddCommand(newAzureLoginCmd())
	cmd.AddCommand(newAzureRolesCmd())
	return cmd
}

func newAzureLoginCmd() *cobra.Command {
	var transitive bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Run device code flow and list your roles + groups",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAzureLogin(cmd, transitive)
		},
	}
	cmd.Flags().BoolVar(&transitive, "transitive", false, "expand nested group memberships")
	return cmd
}

func newAzureRolesCmd() *cobra.Command {
	var transitive bool
	cmd := &cobra.Command{
		Use:   "roles",
		Short: "List your Azure roles + groups using the cached token",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAzureRoles(cmd, transitive)
		},
	}
	cmd.Flags().BoolVar(&transitive, "transitive", false, "expand nested group memberships")
	return cmd
}

func runAzureLogin(cmd *cobra.Command, transitive bool) error {
	cfg, _, err := loadConfig()
	if err != nil {
		return err
	}
	cachePath, err := azure.TokenCachePath()
	if err != nil {
		return withCode(ExitConfig, err)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	cred, cached, err := azure.DeviceCodeLogin(ctx, cfg.Azure.TenantID, cfg.Azure.ClientID, func(message string) {
		fmt.Fprintln(cmd.ErrOrStderr(), message)
	})
	if err != nil {
		return withCode(ExitToken, err)
	}
	if err := azure.SaveToken(cachePath, cached); err != nil {
		// Non-fatal: we have a working credential in-memory.
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not cache token: %v\n", err)
	}

	return queryAndRender(ctx, cmd, cred, transitive)
}

func runAzureRoles(cmd *cobra.Command, transitive bool) error {
	cachePath, err := azure.TokenCachePath()
	if err != nil {
		return withCode(ExitConfig, err)
	}
	t, err := azure.LoadToken(cachePath)
	if err != nil {
		if errors.Is(err, azure.ErrNoCachedToken) || errors.Is(err, azure.ErrTokenExpired) {
			return withCode(ExitToken, err)
		}
		return withCode(ExitConfig, err)
	}
	cred := azure.CredentialFromCache(t)
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return queryAndRender(ctx, cmd, cred, transitive)
}

func queryAndRender(ctx context.Context, cmd *cobra.Command, cred azcore.TokenCredential, transitive bool) error {
	client, err := azure.NewClient(cred)
	if err != nil {
		return withCode(ExitNetwork, err)
	}
	me, err := azure.Me(ctx, client)
	if err != nil {
		return withCode(ExitQuery, err)
	}
	memberships, err := azure.MemberOf(ctx, client, transitive)
	if err != nil {
		return withCode(ExitQuery, err)
	}
	r := output.Result{AuthenticatedAs: firstNonEmpty(me.UPN, me.DisplayName)}
	for _, m := range memberships {
		r.Memberships = append(r.Memberships, output.Membership{
			Type: output.MembershipType(m.Type),
			Name: m.DisplayName,
			ID:   m.ID,
		})
	}
	return render(cmd.OutOrStdout(), r)
}
