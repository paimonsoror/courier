// Package idp defines the interface every identity provider adapter implements.
package idp

import (
	"context"
	"errors"

	"github.com/paimonsoror/courier/pkg/courier"
)

// ErrNotManaged means a client with the requested name exists in the IdP but
// Courier did not create it. Adapters wrap it; callers use errors.Is.
var ErrNotManaged = errors.New("client exists but is not managed by Courier")

// Provider creates and manages OAuth clients in one identity provider.
// Implementations must be idempotent: calling EnsureClient twice with the same
// spec leaves the IdP in the same state.
type Provider interface {
	// Name identifies the adapter instance, e.g. "authentik-homelab".
	Name() string

	// Lookup finds the client managed under spec name. found is false when it
	// does not exist; err is reserved for failures.
	Lookup(ctx context.Context, name string) (ref courier.ClientRef, found bool, err error)

	// EnsureClient creates the client or updates it to match spec, including
	// which groups may use it. When secret is non-zero it becomes the client
	// secret; when zero, an existing secret is left unchanged.
	EnsureClient(ctx context.Context, spec courier.ClientSpec, secret courier.Secret) (courier.ClientRef, error)

	// Adopt marks an existing client that Courier did not create as managed and
	// owned by spec.OwnerGroup, so Courier takes over its lifecycle. Callers must
	// then issue a new secret: a secret Courier did not issue is never trusted.
	Adopt(ctx context.Context, spec courier.ClientSpec) (courier.ClientRef, error)

	// DeleteClient removes the client and its IdP-side objects. Deleting a
	// client that no longer exists is not an error.
	DeleteClient(ctx context.Context, ref courier.ClientRef) error

	// Endpoints returns the endpoints consumers of the named client use.
	Endpoints(spec courier.ClientSpec) courier.Endpoints
}
