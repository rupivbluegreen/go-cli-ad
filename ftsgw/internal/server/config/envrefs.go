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

package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func (c *Config) resolveEnv() error {
	if c.IdP.BindDNEnv != "" {
		v, ok := os.LookupEnv(c.IdP.BindDNEnv)
		if !ok || v == "" {
			return fmt.Errorf("%w: %s", ErrEnvSecretMissing, c.IdP.BindDNEnv)
		}
		c.IdP.ResolvedBindDN = v
	}
	if c.IdP.BindPasswordEnv != "" {
		v, ok := os.LookupEnv(c.IdP.BindPasswordEnv)
		if !ok || v == "" {
			return fmt.Errorf("%w: %s", ErrEnvSecretMissing, c.IdP.BindPasswordEnv)
		}
		c.IdP.ResolvedBindPassword = v
	}
	return nil
}
