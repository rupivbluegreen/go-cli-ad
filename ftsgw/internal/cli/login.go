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
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newLoginCmd(g *Globals) *cobra.Command {
	return &cobra.Command{
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
			fd := int(os.Stdin.Fd())
			if !term.IsTerminal(fd) {
				return WithCode(ExitConfig, errors.New("password requires a terminal"))
			}
			fmt.Fprint(cmd.ErrOrStderr(), "Password: ")
			pw, err := term.ReadPassword(fd)
			fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return WithCode(ExitGeneric, fmt.Errorf("read password: %w", err))
			}
			c, err := NewClient(ClientConfig{BrokerURL: g.BrokerURL, TokenPath: g.TokenPath, CABundlePath: g.CABundlePath})
			if err != nil {
				return WithCode(ExitConfig, err)
			}
			if err := c.Login(username, string(pw)); err != nil {
				if errors.Is(err, ErrAuth) {
					return WithCode(ExitAuthFailed, err)
				}
				return WithCode(ExitNetwork, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "logged in as", username)
			return nil
		},
	}
}
