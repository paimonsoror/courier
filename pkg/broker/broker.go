// Package broker runs the ordered credential lifecycle across an IdP and a
// secret store. It is the heart of Courier and has no Kubernetes dependencies.
package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/paimonsoror/courier/pkg/courier"
	"github.com/paimonsoror/courier/pkg/idp"
	"github.com/paimonsoror/courier/pkg/secretstore"
)

// Prior is what the caller recorded after the last successful Ensure, e.g.
// in OAuthClient status. The broker has no read access to the store, so this
// is how it knows whether credentials were already delivered.
type Prior struct {
	// Delivered is true once credentials were stored and promoted to active.
	Delivered bool
	// SpecChanged is true when the request changed since it was last
	// reconciled. Stored metadata is only rewritten then: every KV v2 write
	// creates a new version, so periodic resyncs must not write.
	SpecChanged bool
}

// Result describes what Ensure did.
type Result struct {
	Ref  courier.ClientRef
	Path string
	// SecretIssued is true when a new client secret was generated and stored.
	SecretIssued bool
}

// Broker coordinates one IdP and one store.
type Broker struct {
	IDP       idp.Provider
	Store     secretstore.Store
	ManagedBy string
	// GenerateSecret defaults to courier.GenerateSecret.
	GenerateSecret func() (courier.Secret, error)
}

// Ensure converges the IdP client and the stored credentials to spec.
//
// Invariant: a secret is written to the store (state=pending) before the IdP
// accepts it, so no live secret ever exists only in memory. A failure at any
// step returns an error, and calling Ensure again is safe.
func (b *Broker) Ensure(ctx context.Context, spec courier.ClientSpec, prior Prior) (Result, error) {
	spec = spec.Normalize()
	if err := spec.Validate(); err != nil {
		return Result{}, fmt.Errorf("invalid client spec: %w", err)
	}
	path := b.Store.PathFor(spec)

	existing, found, err := b.IDP.Lookup(ctx, spec.Name)
	if err != nil {
		return Result{}, fmt.Errorf("look up client %q in %s: %w", spec.Name, b.IDP.Name(), err)
	}

	// Already delivered: converge IdP settings (repairs drift), keep the secret,
	// and refresh stored metadata only if the request changed.
	if found && prior.Delivered {
		ref, err := b.IDP.EnsureClient(ctx, spec, courier.Secret{})
		if err != nil {
			return Result{Path: path}, fmt.Errorf("update client %q in %s: %w", spec.Name, b.IDP.Name(), err)
		}
		if prior.SpecChanged {
			if err := b.Store.Patch(ctx, path, b.record(spec, ref, courier.Secret{}, secretstore.StateActive)); err != nil {
				return Result{Ref: ref, Path: path}, fmt.Errorf("refresh metadata at %s: %w", path, err)
			}
		}
		return Result{Ref: ref, Path: path}, nil
	}

	if spec.Type == courier.ClientTypePublic {
		ref, err := b.IDP.EnsureClient(ctx, spec, courier.Secret{})
		if err != nil {
			return Result{Path: path}, fmt.Errorf("create client %q in %s: %w", spec.Name, b.IDP.Name(), err)
		}
		if err := b.Store.Put(ctx, path, b.record(spec, ref, courier.Secret{}, secretstore.StateActive)); err != nil {
			return Result{Ref: ref, Path: path}, fmt.Errorf("store client metadata at %s: %w", path, err)
		}
		return Result{Ref: ref, Path: path}, nil
	}

	// Confidential client without delivered credentials: issue a new secret.
	// If the client already exists (e.g. status was lost), this rotates it.
	gen := b.GenerateSecret
	if gen == nil {
		gen = courier.GenerateSecret
	}
	secret, err := gen()
	if err != nil {
		return Result{}, fmt.Errorf("generate client secret: %w", err)
	}

	if err := b.Store.Put(ctx, path, b.record(spec, existing, secret, secretstore.StatePending)); err != nil {
		return Result{Path: path}, fmt.Errorf("store pending credentials at %s: %w", path, err)
	}

	ref, err := b.IDP.EnsureClient(ctx, spec, secret)
	if err != nil {
		return Result{Path: path}, fmt.Errorf("create client %q in %s (pending credentials at %s are replaced on retry): %w",
			spec.Name, b.IDP.Name(), path, err)
	}

	if err := b.Store.Patch(ctx, path, b.record(spec, ref, courier.Secret{}, secretstore.StateActive)); err != nil {
		return Result{Ref: ref, Path: path, SecretIssued: true},
			fmt.Errorf("promote credentials at %s to active (the IdP already uses them): %w", path, err)
	}
	return Result{Ref: ref, Path: path, SecretIssued: true}, nil
}

// Delete removes the client from the IdP first, so the credentials stop
// working, and then destroys them in the store.
func (b *Broker) Delete(ctx context.Context, spec courier.ClientSpec) error {
	spec = spec.Normalize()
	ref, found, err := b.IDP.Lookup(ctx, spec.Name)
	if err != nil {
		return fmt.Errorf("look up client %q in %s: %w", spec.Name, b.IDP.Name(), err)
	}
	var errs []error
	if found {
		if err := b.IDP.DeleteClient(ctx, ref); err != nil {
			// Keep the stored credentials: the client still exists.
			return fmt.Errorf("delete client %q in %s: %w", spec.Name, b.IDP.Name(), err)
		}
	}
	if err := b.Store.Delete(ctx, b.Store.PathFor(spec)); err != nil {
		errs = append(errs, fmt.Errorf("destroy credentials: %w", err))
	}
	return errors.Join(errs...)
}

func (b *Broker) record(
	spec courier.ClientSpec, ref courier.ClientRef, secret courier.Secret, state secretstore.State,
) secretstore.Record {
	return secretstore.Record{
		ClientID:     ref.ClientID,
		ClientSecret: secret,
		ClientType:   spec.Type,
		GrantTypes:   spec.GrantTypes,
		Scopes:       spec.Scopes,
		Endpoints:    b.IDP.Endpoints(spec),
		OwnerGroup:   spec.OwnerGroup,
		IDP:          b.IDP.Name(),
		ManagedBy:    b.ManagedBy,
		State:        state,
	}
}
