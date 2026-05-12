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

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newLoginCmd(g *Globals) *cobra.Command {
	var passwordStdin bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the broker",
		RunE: func(cmd *cobra.Command, _ []string) error {
			username := os.Getenv("FTSGW_USERNAME")
			if username == "" {
				fmt.Fprint(cmd.ErrOrStderr(), "Username: ")
				_, _ = fmt.Fscanln(cmd.InOrStdin(), &username)
			}
			if username == "" {
				return WithCode(ExitConfig, errors.New("username required"))
			}
			pw, err := readPassword(cmd, passwordStdin)
			if err != nil {
				return err
			}
			c, err := NewClient(ClientConfig{BrokerURL: g.BrokerURL, TokenPath: g.TokenPath, CABundlePath: g.CABundlePath})
			if err != nil {
				return WithCode(ExitConfig, err)
			}
			if err := c.Login(username, pw); err != nil {
				if errors.Is(err, ErrAuth) {
					return WithCode(ExitAuthFailed, err)
				}
				return WithCode(ExitNetwork, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "logged in as", username)
			return nil
		},
	}
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read password from stdin instead of prompting (use for scripted automation; password is never put in argv or env)")
	return cmd
}

// readPassword either prompts on the TTY (interactive) or reads a single line
// from stdin (--password-stdin). The stdin path supports `echo pw | ftsgw-cli
// login --password-stdin` style automation without exposing the password via
// argv, environment, or /proc.
func readPassword(cmd *cobra.Command, fromStdin bool) (string, error) {
	if fromStdin {
		r := bufio.NewReader(cmd.InOrStdin())
		line, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", WithCode(ExitGeneric, fmt.Errorf("read password from stdin: %w", err))
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			return "", WithCode(ExitConfig, errors.New("empty password on stdin"))
		}
		return pw, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", WithCode(ExitConfig, errors.New("password requires a terminal; use --password-stdin for scripts"))
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Password: ")
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", WithCode(ExitGeneric, fmt.Errorf("read password: %w", err))
	}
	return string(pw), nil
}
