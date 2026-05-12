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

package idp

import "errors"

var (
	// ErrAuth indicates the IdP rejected credentials.
	ErrAuth = errors.New("idp: authentication failed")
	// ErrUnreachable indicates a transport / network failure talking to the IdP.
	ErrUnreachable = errors.New("idp: unreachable")
	// ErrNotSupported is returned by capability methods a given backend does not implement.
	ErrNotSupported = errors.New("idp: capability not supported")
	// ErrNotImplemented marks stub providers reserved for future phases.
	ErrNotImplemented = errors.New("idp: not implemented")
)
