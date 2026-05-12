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

package auth

import "time"

// AuthMethod captures how the user originally authenticated. Phase 0 only
// emits "password"; Phase 1 will add "challenge".
type AuthMethod string

const (
	AuthMethodPassword  AuthMethod = "password"
	AuthMethodChallenge AuthMethod = "challenge"
)

// Claims mirrors the JWT claim set we mint. iat records ORIGINAL password
// auth time and is preserved across refreshes; exp moves forward each refresh.
type Claims struct {
	Subject    string     `json:"sub"`
	Issuer     string     `json:"iss"`
	Audience   string     `json:"aud"`
	IssuedAt   time.Time  `json:"iat"`
	ExpiresAt  time.Time  `json:"exp"`
	JTI        string     `json:"jti"`
	Groups     []string   `json:"groups"`
	Roles      []string   `json:"roles"`
	AuthMethod AuthMethod `json:"auth_method"`
}
