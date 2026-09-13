package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paimonsoror/courier/pkg/courier"
	"github.com/paimonsoror/courier/pkg/secretstore"
)

type recorded struct {
	method, path, contentType, token string
	data                             map[string]string
}

func TestStoreRequests(t *testing.T) {
	var calls []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := recorded{
			method: r.Method, path: r.URL.EscapedPath(),
			contentType: r.Header.Get("Content-Type"), token: r.Header.Get("X-Vault-Token"),
		}
		var body struct {
			Data map[string]string `json:"data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		c.data = body.Data
		calls = append(calls, c)

		switch {
		case strings.HasSuffix(r.URL.Path, "/missing"):
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/denied"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	ctx := context.Background()
	s := &Store{Addr: srv.URL, Tokens: StaticToken("tok")}

	p := s.PathFor(courier.ClientSpec{Name: "app", OwnerGroup: "team-a"})
	if p != "kv/teams/team-a/oauth-clients/app" {
		t.Fatalf("PathFor = %q", p)
	}

	pending := secretstore.Record{
		ClientID: "cid", ClientSecret: courier.NewSecret("sek"), State: secretstore.StatePending,
	}
	if err := s.Put(ctx, p, pending); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Patch(ctx, p, secretstore.Record{ClientID: "cid", State: secretstore.StateActive}); err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if err := s.Patch(ctx, p, secretstore.Record{ClientSecret: courier.NewSecret("x")}); err == nil {
		t.Fatal("Patch with a secret must fail before any request")
	}
	if err := s.Delete(ctx, "kv/teams/team-a/oauth-clients/missing"); err != nil {
		t.Fatalf("Delete of a missing path should succeed: %v", err)
	}
	err := s.Put(ctx, "kv/teams/team-a/oauth-clients/denied", secretstore.Record{ClientSecret: courier.NewSecret("sek")})
	if err == nil || !strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "sek") {
		t.Fatalf("want permission error without the secret, got %v", err)
	}
	if err := s.Put(ctx, "secret/teams/x/oauth-clients/y", secretstore.Record{}); err == nil {
		t.Fatal("path outside the mount must be rejected")
	}

	if len(calls) != 4 {
		t.Fatalf("want 4 requests, got %d: %+v", len(calls), calls)
	}
	put, patch, del := calls[0], calls[1], calls[2]

	if put.method != http.MethodPost || put.path != "/v1/kv/data/teams/team-a/oauth-clients/app" ||
		put.contentType != "application/json" || put.token != "tok" {
		t.Fatalf("unexpected put %+v", put)
	}
	if put.data["client_secret"] != "sek" || put.data["state"] != "pending" {
		t.Fatalf("unexpected put data %v", put.data)
	}
	if patch.method != http.MethodPatch || patch.contentType != "application/merge-patch+json" {
		t.Fatalf("unexpected patch %+v", patch)
	}
	if _, ok := patch.data["client_secret"]; ok || patch.data["state"] != "active" {
		t.Fatalf("unexpected patch data %v", patch.data)
	}
	if del.method != http.MethodDelete || del.path != "/v1/kv/metadata/teams/team-a/oauth-clients/missing" {
		t.Fatalf("unexpected delete %+v", del)
	}
}
