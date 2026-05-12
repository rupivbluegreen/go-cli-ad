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

import "testing"

func TestEscapeFilterValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{"alice", "alice"},
		{"alice(admin)", `alice\28admin\29`},
		{`a\b*c`, `a\5cb\2ac`},
		{"x\x00y", `x\00y`},
	}
	for _, c := range cases {
		got := escapeFilterValue(c.in)
		if got != c.want {
			t.Fatalf("escapeFilterValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLooksLikeDN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"cn=alice,dc=example,dc=com", true},
		{"uid=bob,ou=people,dc=corp,dc=local", true},
		{"alice", false},
		{"alice@example.com", false},
		{"", false},
		{"=foo", false},                // empty attribute name
		{"cn=alice", false},            // no separator comma
		{"alice,bob", false},           // no equals
		{",cn=alice", false},           // comma before equals
		{"cn=alice,dc=example,", true}, // trailing comma still positive
	}
	for _, c := range cases {
		got := looksLikeDN(c.in)
		if got != c.want {
			t.Fatalf("looksLikeDN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
