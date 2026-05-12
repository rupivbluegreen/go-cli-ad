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
	"time"

	"github.com/spf13/cobra"
)

func newStatusCmd(g *Globals) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show token state and broker reachability",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tok, err := LoadToken(g.TokenPath)
			if err != nil {
				if errors.Is(err, ErrTokenNotFound) {
					fmt.Fprintln(cmd.OutOrStdout(), "no cached token; run `ftsgw-cli login`")
					return nil
				}
				return WithCode(ExitConfig, err)
			}
			now := time.Now().UTC()
			ttl := tok.ExpiresAt.Sub(now)
			win := tok.RefreshWindowEndsAt.Sub(now)
			fmt.Fprintf(cmd.OutOrStdout(), "Broker:           %s\n", tok.BrokerURL)
			fmt.Fprintf(cmd.OutOrStdout(), "Token expires in: %s\n", roundDur(ttl))
			fmt.Fprintf(cmd.OutOrStdout(), "Refresh window:   %s remaining\n", roundDur(win))
			return nil
		},
	}
}

func roundDur(d time.Duration) time.Duration { return d.Round(time.Second) }
