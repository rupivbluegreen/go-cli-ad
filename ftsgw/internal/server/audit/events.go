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

package audit

// EventType is an enum of audit event names. Order alphabetically when adding.
type EventType string

const (
	EventChallengeCompleted     EventType = "challenge_completed"
	EventChallengeInitiated     EventType = "challenge_initiated"
	EventChallengeRefused       EventType = "challenge_refused"
	EventIdPHealthCheck         EventType = "idp_health_check"
	EventPasswordAuthenticated  EventType = "password_authenticated"
	EventPasswordRejected       EventType = "password_rejected"
	EventRateLimited            EventType = "rate_limited"
	EventTokenIssued            EventType = "token_issued"
	EventTokenRefreshed         EventType = "token_refreshed"
	EventTokenRefreshRefused    EventType = "token_refresh_refused"
	EventTokenRevoked           EventType = "token_revoked"
	EventTokenValidationFailed  EventType = "token_validation_failed"
)
