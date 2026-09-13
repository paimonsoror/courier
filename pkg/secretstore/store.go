// Package secretstore defines where Courier delivers client credentials.
package secretstore

import (
	"context"
	"strings"

	"github.com/paimonsoror/courier/pkg/courier"
)

// State marks whether stored credentials are live in the IdP yet.
type State string

const (
	// StatePending: written before the IdP accepted the secret. Consumers
	// should not use it yet.
	StatePending State = "pending"
	// StateActive: the IdP client uses these credentials.
	StateActive State = "active"
)

// Record is what consumers read from the store.
type Record struct {
	ClientID     string
	ClientSecret courier.Secret
	ClientType   courier.ClientType
	GrantTypes   []string
	Scopes       []string
	Endpoints    courier.Endpoints
	OwnerGroup   string
	IDP          string
	ManagedBy    string
	State        State
}

// Fields flattens the record into the key/value layout stored at a path.
// Empty values are omitted, and client_secret is included only when set.
func (r Record) Fields() map[string]string {
	f := map[string]string{
		"client_id":              r.ClientID,
		"client_type":            string(r.ClientType),
		"grant_types":            strings.Join(r.GrantTypes, " "),
		"scopes":                 strings.Join(r.Scopes, " "),
		"issuer":                 r.Endpoints.Issuer,
		"authorization_endpoint": r.Endpoints.AuthorizationURL,
		"token_endpoint":         r.Endpoints.TokenURL,
		"jwks_uri":               r.Endpoints.JWKSURL,
		"userinfo_endpoint":      r.Endpoints.UserinfoURL,
		"owner_group":            r.OwnerGroup,
		"idp":                    r.IDP,
		"managed_by":             r.ManagedBy,
		"state":                  string(r.State),
	}
	if !r.ClientSecret.IsZero() {
		f["client_secret"] = r.ClientSecret.Reveal()
	}
	for k, v := range f {
		if v == "" {
			delete(f, k)
		}
	}
	return f
}

// Store writes credentials. Courier never needs to read them back, so a
// Store's credentials should not have read access.
type Store interface {
	// PathFor returns where credentials for spec live.
	PathFor(spec courier.ClientSpec) string
	// Put replaces everything at path with rec.
	Put(ctx context.Context, path string, rec Record) error
	// Patch merges rec's non-empty fields into path without touching an
	// existing client_secret. rec.ClientSecret must be zero.
	Patch(ctx context.Context, path string, rec Record) error
	// Delete destroys all versions at path. A missing path is not an error.
	Delete(ctx context.Context, path string) error
}
