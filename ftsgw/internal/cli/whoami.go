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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func newWhoamiCmd(g *Globals) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Print current identity and groups",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := NewClient(ClientConfig{BrokerURL: g.BrokerURL, TokenPath: g.TokenPath, CABundlePath: g.CABundlePath})
			if err != nil {
				return WithCode(ExitConfig, err)
			}
			me, err := c.Me()
			if err != nil {
				if errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrTokenNotFound) {
					return WithCode(ExitSessionExpired, err)
				}
				return WithCode(ExitNetwork, err)
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(me)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "UPN:    %s\n", me.UPN)
			fmt.Fprintf(cmd.OutOrStdout(), "Name:   %s\n", me.DisplayName)
			fmt.Fprintf(cmd.OutOrStdout(), "Groups: %v\n", me.Groups)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}
