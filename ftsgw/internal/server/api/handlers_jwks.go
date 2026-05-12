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

package api

import (
	"encoding/json"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// HandleJWKS publishes the broker's verification public key as a JWK Set.
func HandleJWKS(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		pub := d.Issuer.PublicVerificationKey()
		kid := d.Issuer.VerificationKeyID()
		key, err := jwk.FromRaw(pub)
		if err != nil {
			WriteProblem(w, http.StatusInternalServerError, "JWKS Failed", err.Error(), "")
			return
		}
		_ = key.Set(jwk.KeyIDKey, kid)
		_ = key.Set(jwk.AlgorithmKey, jwa.EdDSA)
		_ = key.Set(jwk.KeyUsageKey, "sig")

		set := jwk.NewSet()
		_ = set.AddKey(key)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}
}
