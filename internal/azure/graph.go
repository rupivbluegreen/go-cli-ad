package azure

import (
	"context"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	a "github.com/microsoft/kiota-authentication-azure-go"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
)

type Membership struct {
	Type        string // "group" or "directoryRole"
	DisplayName string
	ID          string
}

type Identity struct {
	UPN         string
	DisplayName string
}

// NewClient builds a Graph client from any azcore.TokenCredential (a fresh one
// from device-code login, or a wrapped cached token).
func NewClient(cred azcore.TokenCredential) (*msgraph.GraphServiceClient, error) {
	authProvider, err := a.NewAzureIdentityAuthenticationProviderWithScopes(cred, []string{GraphScope})
	if err != nil {
		return nil, fmt.Errorf("auth provider: %w", err)
	}
	adapter, err := msgraph.NewGraphRequestAdapter(authProvider)
	if err != nil {
		return nil, fmt.Errorf("graph adapter: %w", err)
	}
	return msgraph.NewGraphServiceClient(adapter), nil
}

// Me returns the signed-in user's UPN and display name.
func Me(ctx context.Context, client *msgraph.GraphServiceClient) (Identity, error) {
	me, err := client.Me().Get(ctx, nil)
	if err != nil {
		return Identity{}, fmt.Errorf("GET /me: %w", err)
	}
	return Identity{
		UPN:         deref(me.GetUserPrincipalName()),
		DisplayName: deref(me.GetDisplayName()),
	}, nil
}

// MemberOf returns the directory objects the signed-in user belongs to.
// When transitive is true, nested group memberships are expanded.
func MemberOf(ctx context.Context, client *msgraph.GraphServiceClient, transitive bool) ([]Membership, error) {
	type collection interface {
		GetValue() []models.DirectoryObjectable
	}
	var resp collection
	var err error
	if transitive {
		resp, err = client.Me().TransitiveMemberOf().Get(ctx, &users.ItemTransitiveMemberOfRequestBuilderGetRequestConfiguration{})
	} else {
		resp, err = client.Me().MemberOf().Get(ctx, &users.ItemMemberOfRequestBuilderGetRequestConfiguration{})
	}
	if err != nil {
		return nil, fmt.Errorf("GET /me/memberOf: %w", err)
	}
	if resp == nil {
		return nil, errors.New("graph returned no response body")
	}

	out := make([]Membership, 0, len(resp.GetValue()))
	for _, obj := range resp.GetValue() {
		m := Membership{ID: deref(obj.GetId())}
		switch v := obj.(type) {
		case *models.Group:
			m.Type = "group"
			m.DisplayName = deref(v.GetDisplayName())
		case *models.DirectoryRole:
			m.Type = "directoryRole"
			m.DisplayName = deref(v.GetDisplayName())
		default:
			m.Type = "other"
			m.DisplayName = deref(obj.GetOdataType())
		}
		out = append(out, m)
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
