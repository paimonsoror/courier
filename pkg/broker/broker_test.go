package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/paimonsoror/courier/pkg/courier"
	"github.com/paimonsoror/courier/pkg/secretstore"
)

// events is shared by the fakes so tests can assert cross-system ordering.
type events []string

func (e *events) add(format string, args ...any) { *e = append(*e, fmt.Sprintf(format, args...)) }

type fakeIDP struct {
	log        *events
	clients    map[string]courier.ClientRef
	secrets    map[string]string
	failEnsure error
}

func newFakeIDP(log *events) *fakeIDP {
	return &fakeIDP{log: log, clients: map[string]courier.ClientRef{}, secrets: map[string]string{}}
}

func (f *fakeIDP) Name() string { return "fake-idp" }

func (f *fakeIDP) Lookup(_ context.Context, name string) (courier.ClientRef, bool, error) {
	ref, ok := f.clients[name]
	return ref, ok, nil
}

func (f *fakeIDP) EnsureClient(
	_ context.Context, spec courier.ClientSpec, secret courier.Secret,
) (courier.ClientRef, error) {
	if f.failEnsure != nil {
		f.log.add("idp.ensure %s FAILED", spec.Name)
		return courier.ClientRef{}, f.failEnsure
	}
	ref, ok := f.clients[spec.Name]
	if !ok {
		ref = courier.ClientRef{ClientID: "cid-" + spec.Name}
		f.clients[spec.Name] = ref
	}
	if !secret.IsZero() {
		f.secrets[spec.Name] = secret.Reveal()
	}
	f.log.add("idp.ensure %s secret=%t", spec.Name, !secret.IsZero())
	return ref, nil
}

func (f *fakeIDP) DeleteClient(_ context.Context, ref courier.ClientRef) error {
	for name, r := range f.clients {
		if r.ClientID == ref.ClientID {
			delete(f.clients, name)
			delete(f.secrets, name)
		}
	}
	f.log.add("idp.delete %s", ref.ClientID)
	return nil
}

func (f *fakeIDP) Endpoints(spec courier.ClientSpec) courier.Endpoints {
	return courier.Endpoints{Issuer: "https://idp.example/" + spec.Name + "/"}
}

type fakeStore struct {
	log  *events
	data map[string]map[string]string
}

func newFakeStore(log *events) *fakeStore {
	return &fakeStore{log: log, data: map[string]map[string]string{}}
}

func (s *fakeStore) PathFor(spec courier.ClientSpec) string {
	return "kv/teams/" + spec.OwnerGroup + "/oauth-clients/" + spec.Name
}

func (s *fakeStore) Put(_ context.Context, path string, rec secretstore.Record) error {
	s.data[path] = rec.Fields()
	s.log.add("store.put %s state=%s secret=%t", path, rec.State, !rec.ClientSecret.IsZero())
	return nil
}

func (s *fakeStore) Patch(_ context.Context, path string, rec secretstore.Record) error {
	if !rec.ClientSecret.IsZero() {
		return errors.New("patch must not carry a secret")
	}
	cur, ok := s.data[path]
	if !ok {
		cur = map[string]string{}
		s.data[path] = cur
	}
	maps.Copy(cur, rec.Fields())
	s.log.add("store.patch %s state=%s", path, rec.State)
	return nil
}

func (s *fakeStore) Delete(_ context.Context, path string) error {
	delete(s.data, path)
	s.log.add("store.delete %s", path)
	return nil
}

func confidentialSpec() courier.ClientSpec {
	return courier.ClientSpec{
		Name:         "payments-mcp",
		OwnerGroup:   teamPayments,
		Type:         courier.ClientTypeConfidential,
		GrantTypes:   []string{courier.GrantAuthorizationCode, courier.GrantRefreshToken},
		RedirectURIs: []string{"https://mcp.example/callback"},
	}
}

func setup() (*Broker, *fakeIDP, *fakeStore, *events) {
	log := &events{}
	i, s := newFakeIDP(log), newFakeStore(log)
	b := &Broker{
		IDP: i, Store: s, ManagedBy: "test",
		GenerateSecret: func() (courier.Secret, error) { return courier.NewSecret("s3cr3t-value"), nil },
	}
	return b, i, s, log
}

const (
	path           = "kv/teams/team-payments/oauth-clients/payments-mcp"
	teamPayments   = "team-payments"
	cidPaymentsMCP = "cid-payments-mcp"
	stateActive    = "active"
)

func TestEnsureNewConfidentialClientStoresBeforeIdP(t *testing.T) {
	b, idp, store, log := setup()

	res, err := b.Ensure(context.Background(), confidentialSpec(), Prior{})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	want := []string{
		"store.put " + path + " state=pending secret=true",
		"idp.ensure payments-mcp secret=true",
		"store.patch " + path + " state=active",
	}
	if !slices.Equal(*log, want) {
		t.Fatalf("order:\n got %q\nwant %q", *log, want)
	}
	if !res.SecretIssued || res.Ref.ClientID != cidPaymentsMCP || res.Path != path {
		t.Fatalf("unexpected result %+v", res)
	}
	got := store.data[path]
	if got["client_secret"] != idp.secrets["payments-mcp"] {
		t.Fatal("stored secret differs from the secret the IdP accepted")
	}
	if got["state"] != stateActive || got["client_id"] != cidPaymentsMCP || got["owner_group"] != teamPayments {
		t.Fatalf("unexpected stored fields %v", got)
	}
}

func TestEnsureIdPFailureLeavesOnlyPendingCredentials(t *testing.T) {
	b, idp, store, _ := setup()
	idp.failEnsure = errors.New("boom")

	if _, err := b.Ensure(context.Background(), confidentialSpec(), Prior{}); err == nil {
		t.Fatal("expected error")
	}
	if store.data[path]["state"] != "pending" {
		t.Fatalf("want pending record after IdP failure, got %v", store.data[path])
	}
	if len(idp.clients) != 0 {
		t.Fatal("IdP should have no client")
	}

	// Retry after the IdP recovers converges to active.
	idp.failEnsure = nil
	if _, err := b.Ensure(context.Background(), confidentialSpec(), Prior{}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if store.data[path]["state"] != stateActive || store.data[path]["client_secret"] != idp.secrets["payments-mcp"] {
		t.Fatalf("retry did not converge: %v", store.data[path])
	}
}

func TestEnsureDeliveredClientKeepsSecret(t *testing.T) {
	b, idp, store, log := setup()
	ctx := context.Background()
	if _, err := b.Ensure(ctx, confidentialSpec(), Prior{}); err != nil {
		t.Fatal(err)
	}
	firstSecret := store.data[path]["client_secret"]
	*log = nil

	spec := confidentialSpec()
	spec.Scopes = []string{"openid", "email"}
	res, err := b.Ensure(ctx, spec, Prior{Delivered: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.SecretIssued {
		t.Fatal("no new secret expected")
	}
	for _, e := range *log {
		if strings.HasPrefix(e, "store.put") || strings.Contains(e, "secret=true") {
			t.Fatalf("unexpected secret write: %q", *log)
		}
	}
	if store.data[path]["client_secret"] != firstSecret || idp.secrets["payments-mcp"] != firstSecret {
		t.Fatal("secret changed")
	}
	if store.data[path]["scopes"] != "openid email" {
		t.Fatalf("metadata not refreshed: %v", store.data[path])
	}
}

func TestEnsureExistingClientWithoutDeliveryRotates(t *testing.T) {
	b, idp, store, _ := setup()
	idp.clients["payments-mcp"] = courier.ClientRef{ClientID: cidPaymentsMCP}
	idp.secrets["payments-mcp"] = "old-secret-nobody-has"

	res, err := b.Ensure(context.Background(), confidentialSpec(), Prior{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.SecretIssued || idp.secrets["payments-mcp"] == "old-secret-nobody-has" {
		t.Fatal("expected rotation")
	}
	if store.data[path]["client_secret"] != idp.secrets["payments-mcp"] {
		t.Fatal("store and IdP disagree after rotation")
	}
}

func TestEnsurePublicClientStoresNoSecret(t *testing.T) {
	b, idp, store, log := setup()
	spec := courier.ClientSpec{
		Name:         "ide-plugin",
		OwnerGroup:   teamPayments,
		Type:         courier.ClientTypePublic,
		GrantTypes:   []string{courier.GrantAuthorizationCode},
		RedirectURIs: []string{"http://localhost:8250/callback"},
	}
	if _, err := b.Ensure(context.Background(), spec, Prior{}); err != nil {
		t.Fatal(err)
	}
	p := "kv/teams/team-payments/oauth-clients/ide-plugin"
	if _, ok := store.data[p]["client_secret"]; ok {
		t.Fatal("public client must not have a stored secret")
	}
	if len(idp.secrets) != 0 {
		t.Fatal("public client must not get an IdP secret")
	}
	if store.data[p]["state"] != stateActive {
		t.Fatalf("want active, got %v (%q)", store.data[p], *log)
	}
}

func TestDeleteRemovesIdPBeforeStore(t *testing.T) {
	b, _, store, log := setup()
	ctx := context.Background()
	if _, err := b.Ensure(ctx, confidentialSpec(), Prior{}); err != nil {
		t.Fatal(err)
	}
	*log = nil
	if err := b.Delete(ctx, confidentialSpec()); err != nil {
		t.Fatal(err)
	}
	want := []string{"idp.delete cid-payments-mcp", "store.delete " + path}
	if !slices.Equal(*log, want) {
		t.Fatalf("got %q want %q", *log, want)
	}
	if _, ok := store.data[path]; ok {
		t.Fatal("credentials not destroyed")
	}
	// Deleting again is a no-op success.
	if err := b.Delete(ctx, confidentialSpec()); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

func TestInvalidSpecTouchesNothing(t *testing.T) {
	b, _, _, log := setup()
	spec := confidentialSpec()
	spec.RedirectURIs = []string{"http://mcp.example/callback"}
	if _, err := b.Ensure(context.Background(), spec, Prior{}); err == nil {
		t.Fatal("expected validation error")
	}
	if len(*log) != 0 {
		t.Fatalf("invalid spec caused side effects: %q", *log)
	}
}

func TestSecretNeverFormats(t *testing.T) {
	s := courier.NewSecret("s3cr3t-value")
	j, _ := json.Marshal(struct{ S courier.Secret }{s})
	outputs := []string{
		fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s", s, s, s, s),
		fmt.Sprintf("%+v", secretstore.Record{ClientSecret: s}),
		string(j),
	}
	for _, o := range outputs {
		if strings.Contains(o, "s3cr3t") {
			t.Fatalf("secret leaked in %q", o)
		}
	}
}
