package output

import (
	"encoding/json"
	"io"
)

func RenderJSON(w io.Writer, r Result) error {
	if r.Memberships == nil {
		r.Memberships = []Membership{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
