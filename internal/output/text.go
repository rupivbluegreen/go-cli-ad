package output

import (
	"fmt"
	"io"
)

func RenderText(w io.Writer, r Result) error {
	if _, err := fmt.Fprintf(w, "✓ Authenticated as %s\n\n", r.AuthenticatedAs); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Memberships (%d):\n", len(r.Memberships)); err != nil {
		return err
	}
	for _, m := range r.Memberships {
		if _, err := fmt.Fprintf(w, "  %s %s\n", typeTag(m.Type), m.Name); err != nil {
			return err
		}
	}
	return nil
}

func typeTag(t MembershipType) string {
	switch t {
	case TypeDirectoryRole:
		return "[R]"
	case TypeGroup:
		return "[G]"
	default:
		return "[ ]"
	}
}
