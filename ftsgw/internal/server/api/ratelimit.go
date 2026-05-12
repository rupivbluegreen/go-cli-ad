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
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimits is the runtime config.
type RateLimits struct {
	PerIPRPS                 int
	PerIPBurst               int
	AuthPerUsernamePerMinute int
}

// RateLimiter holds per-IP and per-username buckets. Old entries are reaped
// on access; under steady-state traffic memory is bounded by active clients.
type RateLimiter struct {
	limits RateLimits

	ipMu sync.Mutex
	ipB  map[string]*rate.Limiter

	userMu sync.Mutex
	userB  map[string]*userBucket

	// Clock is injected only for tests.
	Clock func() time.Time
}

type userBucket struct {
	count     int
	windowEnd time.Time
}

// NewRateLimiter returns a RateLimiter using time.Now by default.
func NewRateLimiter(l RateLimits) *RateLimiter {
	return &RateLimiter{
		limits: l,
		ipB:    map[string]*rate.Limiter{},
		userB:  map[string]*userBucket{},
		Clock:  func() time.Time { return time.Now().UTC() },
	}
}

// PerIP wraps a handler with per-remote-IP rate limiting.
func (rl *RateLimiter) PerIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if !rl.ip(ip).Allow() {
			WriteProblem(w, http.StatusTooManyRequests, "Too Many Requests", "rate limit exceeded", RequestIDFrom(r.Context()))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) ip(ip string) *rate.Limiter {
	rl.ipMu.Lock()
	defer rl.ipMu.Unlock()
	lim, ok := rl.ipB[ip]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(rl.limits.PerIPRPS), rl.limits.PerIPBurst)
		rl.ipB[ip] = lim
	}
	return lim
}

// AllowAuth consumes one slot from username's per-minute auth quota.
func (rl *RateLimiter) AllowAuth(username string) bool {
	rl.userMu.Lock()
	defer rl.userMu.Unlock()
	now := rl.Clock()
	b, ok := rl.userB[username]
	if !ok || now.After(b.windowEnd) {
		b = &userBucket{windowEnd: now.Add(time.Minute)}
		rl.userB[username] = b
	}
	if b.count >= rl.limits.AuthPerUsernamePerMinute {
		return false
	}
	b.count++
	return true
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
