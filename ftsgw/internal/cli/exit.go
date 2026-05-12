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

// Exit codes for ftsgw-cli. Surfaced to scripts.
const (
	ExitOK             = 0
	ExitGeneric        = 1
	ExitAuthFailed     = 2
	ExitNetwork        = 3
	ExitSessionExpired = 4
	ExitConfig         = 5
)

// Coded is the wrapper type used by command handlers.
type Coded struct {
	Code int
	Err  error
}

// Error implements error.
func (c *Coded) Error() string { return c.Err.Error() }

// Unwrap exposes the wrapped error to errors.Is/As.
func (c *Coded) Unwrap() error { return c.Err }

// WithCode wraps an error with an exit code.
func WithCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &Coded{Code: code, Err: err}
}
