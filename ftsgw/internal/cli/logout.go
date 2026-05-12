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
	"fmt"

	"github.com/spf13/cobra"
)

func newLogoutCmd(g *Globals) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke current token and remove local cache",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := NewClient(ClientConfig{BrokerURL: g.BrokerURL, TokenPath: g.TokenPath, CABundlePath: g.CABundlePath})
			if err != nil {
				return WithCode(ExitConfig, err)
			}
			if err := c.Logout(); err != nil {
				return WithCode(ExitNetwork, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "logged out")
			return nil
		},
	}
}
