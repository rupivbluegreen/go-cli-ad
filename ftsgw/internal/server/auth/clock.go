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

// Clock is the seam between real wall-clock time and test fakes. All time
// comparisons in the auth package go through this interface so refresh-window
// exhaustion can be tested without sleeping for hours.
type Clock interface{ Now() time.Time }

// RealClock returns time.Now().UTC().
type RealClock struct{}

// Now implements Clock.
func (RealClock) Now() time.Time { return time.Now().UTC() }
