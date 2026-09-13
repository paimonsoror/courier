//go:build integration

package authentik

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/paimonsoror/courier/pkg/courier"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func providerFromEnv(t *testing.T) *Provider {
	t.Helper()
	base, token := os.Getenv("AUTHENTIK_URL"), os.Getenv("AUTHENTIK_TOKEN")
	if base == "" || token == "" {
		t.Skip("AUTHENTIK_URL and AUTHENTIK_TOKEN are required")
	}
	p, err := New(Config{
		Name:          "authentik-it",
		BaseURL:       base,
		Token:         token,
		ScopeMappings: map[string]string{"groups": envOr("AUTHENTIK_GROUPS_MAPPING", "oauth-groups")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRefusesUnmanagedApplication(t *testing.T) {
	p := providerFromEnv(t)
	_, _, err := p.Lookup(context.Background(), envOr("AUTHENTIK_UNMANAGED_SLUG", "vault"))
	if !errors.Is(err, ErrNotManaged) {
		t.Fatalf("want ErrNotManaged, got %v", err)
	}
}

func TestClientLifecycle(t *testing.T) {
	p := providerFromEnv(t)
	ctx := context.Background()
	name := fmt.Sprintf("it-idp-%d", time.Now().UnixNano()%1_000_000_000)
	spec := courier.ClientSpec{
		Name:       name,
		OwnerGroup: envOr("TEST_OWNER_GROUP", "team-alpha"),
		Type:       courier.ClientTypeConfidential,
		GrantTypes: []string{courier.GrantClientCredentials},
		Scopes:     []string{"openid", "profile", "groups"},
	}.Normalize()
	t.Cleanup(func() {
		if ref, found, err := p.Lookup(context.Background(), name); err == nil && found {
			_ = p.DeleteClient(context.Background(), ref)
		}
	})

	if _, found, err := p.Lookup(ctx, name); err != nil || found {
		t.Fatalf("fresh name: found=%v err=%v", found, err)
	}

	secret, err := courier.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	created, err := p.EnsureClient(ctx, spec, secret)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ClientID == "" || created.Objects["provider_pk"] == "" {
		t.Fatalf("incomplete ref %+v", created)
	}

	spec.DisplayName = "Courier integration " + name
	updated, err := p.EnsureClient(ctx, spec, courier.Secret{})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.ClientID != created.ClientID || updated.Objects["provider_pk"] != created.Objects["provider_pk"] {
		t.Fatalf("update changed identity: %+v -> %+v", created, updated)
	}

	found, ok, err := p.Lookup(ctx, name)
	if err != nil || !ok || found.ClientID != created.ClientID {
		t.Fatalf("lookup after create: %+v ok=%v err=%v", found, ok, err)
	}

	if err := p.DeleteClient(ctx, found); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, err := p.Lookup(ctx, name); err != nil || ok {
		t.Fatalf("after delete: ok=%v err=%v", ok, err)
	}
	if err := p.DeleteClient(ctx, found); err != nil {
		t.Fatalf("second delete should be a no-op: %v", err)
	}
}
