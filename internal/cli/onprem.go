package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/rupivbluegreen/rogi-cli/internal/onprem"
	"github.com/rupivbluegreen/rogi-cli/internal/output"
	"golang.org/x/term"
)

type onpremFlags struct {
	server             string
	baseDN             string
	username           string
	passwordStdin      bool
	insecureSkipVerify bool
	noNested           bool
}

func newOnpremCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "onprem",
		Short: "Authenticate against on-premises Active Directory",
	}
	cmd.AddCommand(newOnpremLoginCmd())
	return cmd
}

func newOnpremLoginCmd() *cobra.Command {
	var f onpremFlags
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Bind to AD and list your group memberships",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOnpremLogin(cmd, &f)
		},
	}
	cmd.Flags().StringVar(&f.server, "server", "", "LDAP server URL (overrides config)")
	cmd.Flags().StringVar(&f.baseDN, "base-dn", "", "search base DN (overrides config)")
	cmd.Flags().StringVar(&f.username, "username", "", "username (overrides config and $USER)")
	cmd.Flags().BoolVar(&f.passwordStdin, "password-stdin", false, "read password from stdin instead of prompting")
	cmd.Flags().BoolVar(&f.insecureSkipVerify, "insecure-skip-verify", false, "skip TLS certificate verification (LDAPS)")
	cmd.Flags().BoolVar(&f.noNested, "no-nested", false, "don't expand nested group memberships")
	return cmd
}

func runOnpremLogin(cmd *cobra.Command, f *onpremFlags) error {
	cfg, _, err := loadConfig()
	if err != nil {
		return err
	}

	server := firstNonEmpty(f.server, cfg.Onprem.Server)
	baseDN := firstNonEmpty(f.baseDN, cfg.Onprem.BaseDN)
	username := firstNonEmpty(f.username, cfg.Onprem.Username, os.Getenv("USER"))

	if server == "" {
		return withCode(ExitConfig, errors.New("no LDAP server configured (set onprem.server in config or pass --server)"))
	}
	if baseDN == "" {
		return withCode(ExitConfig, errors.New("no base DN configured (set onprem.base_dn in config or pass --base-dn)"))
	}
	if username == "" {
		return withCode(ExitConfig, errors.New("no username available (pass --username or set $USER)"))
	}

	password, err := readPassword(cmd.InOrStdin(), cmd.ErrOrStderr(), f.passwordStdin, username)
	if err != nil {
		return withCode(ExitConfig, err)
	}

	client, err := onprem.Dial(onprem.DialOptions{
		Server:             server,
		BaseDN:             baseDN,
		InsecureSkipVerify: f.insecureSkipVerify,
	})
	if err != nil {
		if errors.Is(err, onprem.ErrUnreachable) {
			return withCode(ExitNetwork, err)
		}
		return withCode(ExitNetwork, err)
	}
	defer client.Close()

	if err := client.Bind(username, password, cfg.Onprem.BindFormat, baseDN); err != nil {
		if errors.Is(err, onprem.ErrInvalidCredentials) {
			return withCode(ExitAuth, errors.New("bind failed: invalid credentials"))
		}
		return withCode(ExitAuth, err)
	}

	userDN, err := client.LookupUser(strings.TrimSuffix(strings.Split(username, "@")[0], `\`))
	if err != nil {
		// Fallback for down-level form: strip leading "DOMAIN\"
		if i := strings.Index(username, `\`); i >= 0 {
			userDN, err = client.LookupUser(username[i+1:])
		}
		if err != nil {
			return withCode(ExitQuery, err)
		}
	}

	groups, err := client.Groups(userDN, !f.noNested)
	if err != nil {
		return withCode(ExitQuery, err)
	}

	result := output.Result{AuthenticatedAs: userDN}
	for _, g := range groups {
		result.Memberships = append(result.Memberships, output.Membership{
			Type: output.TypeGroup,
			Name: g.CN,
			ID:   g.DN,
		})
	}

	return render(cmd.OutOrStdout(), result)
}

// readPassword resolves the password from stdin, env, or interactive prompt.
func readPassword(in io.Reader, errOut io.Writer, stdinFlag bool, username string) (string, error) {
	if envPass := os.Getenv("ROGI_PASSWORD"); envPass != "" {
		return envPass, nil
	}
	if stdinFlag {
		data, err := io.ReadAll(in)
		if err != nil {
			return "", fmt.Errorf("reading password from stdin: %w", err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	// Interactive prompt — only works when stderr is a TTY (we use stderr so
	// stdout stays clean for piping).
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("password required: pipe with --password-stdin or set ROGI_PASSWORD")
	}
	fmt.Fprintf(errOut, "Password for %s: ", username)
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(errOut)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return string(pw), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func render(w io.Writer, r output.Result) error {
	if globals.jsonOut {
		return output.RenderJSON(w, r)
	}
	return output.RenderText(w, r)
}

