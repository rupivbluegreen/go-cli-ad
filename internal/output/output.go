package output

type MembershipType string

const (
	TypeGroup         MembershipType = "group"
	TypeDirectoryRole MembershipType = "directoryRole"
)

type Membership struct {
	Type MembershipType `json:"type"`
	Name string         `json:"name"`
	ID   string         `json:"id,omitempty"`
}

type Result struct {
	AuthenticatedAs string       `json:"authenticated_as"`
	Memberships     []Membership `json:"memberships"`
}
