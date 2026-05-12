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
	"errors"
	"net/http"
	"strings"

	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/audit"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/auth"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/internal/server/idp"
	"github.com/rupivbluegreen/go-cli-ad/ftsgw/pkg/api/types"
)

// Deps bundles the broker's runtime collaborators. Constructed in cmd/ftsgw-server.
type Deps struct {
	Issuer      *auth.Issuer
	IdP         idp.IdentityProvider
	Audit       *audit.Logger
	RateLimiter *RateLimiter
}

// HandleTokenIssue handles POST /v1/auth/token (password -> app-token).
func HandleTokenIssue(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.TokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
			WriteProblem(w, http.StatusBadRequest, "Bad Request", "invalid body", RequestIDFrom(r.Context()))
			return
		}
		if !d.RateLimiter.AllowAuth(req.Username) {
			RateLimitedTotal.WithLabelValues("/v1/auth/token").Inc()
			_ = d.Audit.Write(r.Context(), audit.Event{
				RequestID: RequestIDFrom(r.Context()), ActorUPN: req.Username,
				Event: audit.EventRateLimited, Outcome: "failure",
			})
			WriteProblem(w, http.StatusTooManyRequests, "Too Many Requests", "auth rate limit exceeded", RequestIDFrom(r.Context()))
			return
		}
		ident, err := d.IdP.Authenticate(r.Context(), req.Username, req.Password)
		if err != nil {
			PasswordAuthTotal.WithLabelValues("failure").Inc()
			_ = d.Audit.Write(r.Context(), audit.Event{
				RequestID: RequestIDFrom(r.Context()), ActorUPN: req.Username,
				Event: audit.EventPasswordRejected, Outcome: "failure", Reason: errorReason(err),
			})
			WriteProblem(w, HTTPStatusFor(err), "Authentication Failed", "credentials rejected", RequestIDFrom(r.Context()))
			return
		}
		PasswordAuthTotal.WithLabelValues("success").Inc()
		_ = d.Audit.Write(r.Context(), audit.Event{
			RequestID: RequestIDFrom(r.Context()), ActorUPN: ident.UPN,
			Event: audit.EventPasswordAuthenticated, Outcome: "success",
		})
		tok, err := d.Issuer.Mint(r.Context(), auth.Subject{UPN: ident.UPN, Groups: ident.Groups, Roles: ident.Roles})
		if err != nil {
			WriteProblem(w, http.StatusInternalServerError, "Mint Failed", err.Error(), RequestIDFrom(r.Context()))
			return
		}
		TokensIssuedTotal.Inc()
		_ = d.Audit.Write(r.Context(), audit.Event{
			RequestID: RequestIDFrom(r.Context()), ActorUPN: ident.UPN,
			Event: audit.EventTokenIssued, Outcome: "success",
			Extras: map[string]any{"jti": tok.JTI, "auth_method": "password"},
		})
		writeTokenResponse(w, tok)
	}
}

// HandleTokenRefresh handles POST /v1/auth/refresh.
func HandleTokenRefresh(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r)
		if !ok {
			WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "missing bearer", RequestIDFrom(r.Context()))
			return
		}
		tok, err := d.Issuer.Refresh(r.Context(), raw)
		if err != nil {
			TokensRefreshRefusedTotal.WithLabelValues(simpleReason(err)).Inc()
			_ = d.Audit.Write(r.Context(), audit.Event{
				RequestID: RequestIDFrom(r.Context()),
				Event:     audit.EventTokenRefreshRefused, Outcome: "failure", Reason: errorReason(err),
			})
			WriteProblem(w, HTTPStatusFor(err), "Refresh Refused", err.Error(), RequestIDFrom(r.Context()))
			return
		}
		TokensRefreshedTotal.Inc()
		_ = d.Audit.Write(r.Context(), audit.Event{
			RequestID: RequestIDFrom(r.Context()),
			Event:     audit.EventTokenRefreshed, Outcome: "success",
			Extras:    map[string]any{"jti": tok.JTI},
		})
		writeTokenResponse(w, tok)
	}
}

// HandleLogout handles POST /v1/auth/logout.
func HandleLogout(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r)
		if !ok {
			WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "missing bearer", RequestIDFrom(r.Context()))
			return
		}
		claims, err := d.Issuer.Validate(r.Context(), raw)
		if err != nil && !errors.Is(err, auth.ErrExpired) {
			WriteProblem(w, HTTPStatusFor(err), "Logout Failed", err.Error(), RequestIDFrom(r.Context()))
			return
		}
		actor := ""
		if claims != nil {
			actor = claims.Subject
		}
		if err := d.Issuer.Revoke(r.Context(), raw, actor, "logout"); err != nil {
			WriteProblem(w, http.StatusInternalServerError, "Revoke Failed", err.Error(), RequestIDFrom(r.Context()))
			return
		}
		TokensRevokedTotal.Inc()
		extras := map[string]any{}
		if claims != nil {
			extras["jti"] = claims.JTI
		}
		_ = d.Audit.Write(r.Context(), audit.Event{
			RequestID: RequestIDFrom(r.Context()),
			ActorUPN:  actor,
			Event:     audit.EventTokenRevoked, Outcome: "success",
			Extras:    extras,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

func writeTokenResponse(w http.ResponseWriter, tok *auth.IssuedToken) {
	body := types.TokenResponse{
		AccessToken:         tok.AccessToken,
		TokenType:           "Bearer",
		ExpiresAt:           tok.ExpiresAt,
		RefreshWindowEndsAt: tok.RefreshWindowEndsAt,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

func errorReason(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func simpleReason(err error) string {
	switch {
	case errors.Is(err, auth.ErrExpired):
		return "expired"
	case errors.Is(err, auth.ErrRefreshWindowExhausted):
		return "refresh_window"
	case errors.Is(err, auth.ErrRevoked):
		return "revoked"
	case errors.Is(err, auth.ErrInvalidSignature):
		return "signature"
	default:
		return "other"
	}
}

// authnFromBearer is the helper used by /v1/me. It enforces validity and
// returns claims; ctx is enriched with the actor UPN.
func authnFromBearer(d *Deps, r *http.Request) (*auth.Claims, *http.Request, error) {
	raw, ok := bearerToken(r)
	if !ok {
		return nil, r, errors.New("missing bearer")
	}
	c, err := d.Issuer.Validate(r.Context(), raw)
	if err != nil {
		return nil, r, err
	}
	r = r.WithContext(WithActorUPN(r.Context(), c.Subject))
	return c, r, nil
}
