package controller

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	courierv1alpha1 "github.com/paimonsoror/courier/api/v1alpha1"
	"github.com/paimonsoror/courier/pkg/broker"
	"github.com/paimonsoror/courier/pkg/courier"
	"github.com/paimonsoror/courier/pkg/secretstore"
)

type memIDP struct {
	clients    map[string]courier.ClientRef
	ensures    int
	secretsSet int
}

func (m *memIDP) Name() string { return "mem-idp" }

func (m *memIDP) Lookup(_ context.Context, name string) (courier.ClientRef, bool, error) {
	ref, ok := m.clients[name]
	return ref, ok, nil
}

func (m *memIDP) EnsureClient(_ context.Context, spec courier.ClientSpec, secret courier.Secret) (courier.ClientRef, error) {
	m.ensures++
	if !secret.IsZero() {
		m.secretsSet++
	}
	ref, ok := m.clients[spec.Name]
	if !ok {
		ref = courier.ClientRef{ClientID: "cid-" + spec.Name}
		m.clients[spec.Name] = ref
	}
	return ref, nil
}

func (m *memIDP) DeleteClient(_ context.Context, ref courier.ClientRef) error {
	for k, v := range m.clients {
		if v.ClientID == ref.ClientID {
			delete(m.clients, k)
		}
	}
	return nil
}

func (m *memIDP) Endpoints(courier.ClientSpec) courier.Endpoints { return courier.Endpoints{} }

type memStore struct{ data map[string]map[string]string }

func (s *memStore) PathFor(spec courier.ClientSpec) string {
	return "kv/teams/" + spec.OwnerGroup + "/oauth-clients/" + spec.Name
}

func (s *memStore) Put(_ context.Context, path string, rec secretstore.Record) error {
	s.data[path] = rec.Fields()
	return nil
}

func (s *memStore) Patch(_ context.Context, path string, rec secretstore.Record) error {
	if s.data[path] == nil {
		s.data[path] = map[string]string{}
	}
	for k, v := range rec.Fields() {
		s.data[path][k] = v
	}
	return nil
}

func (s *memStore) Delete(_ context.Context, path string) error {
	delete(s.data, path)
	return nil
}

func newTestReconciler(t *testing.T, objs ...client.Object) (*OAuthClientReconciler, *memIDP, *memStore) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := courierv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&courierv1alpha1.OAuthClient{}).
		Build()
	i := &memIDP{clients: map[string]courier.ClientRef{}}
	s := &memStore{data: map[string]map[string]string{}}
	r := &OAuthClientReconciler{Client: c, Scheme: scheme, Broker: &broker.Broker{IDP: i, Store: s, ManagedBy: "test"}}
	return r, i, s
}

func sampleClient() *courierv1alpha1.OAuthClient {
	return &courierv1alpha1.OAuthClient{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-alpha", Name: "billing-sync"},
		Spec: courierv1alpha1.OAuthClientSpec{
			ClientType: "confidential",
			GrantTypes: []string{"client_credentials"},
		},
	}
}

var key = types.NamespacedName{Namespace: "team-alpha", Name: "billing-sync"}

func reconcileOK(t *testing.T, r *OAuthClientReconciler) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func fetch(t *testing.T, r *OAuthClientReconciler) *courierv1alpha1.OAuthClient {
	t.Helper()
	var oc courierv1alpha1.OAuthClient
	if err := r.Get(context.Background(), key, &oc); err != nil {
		t.Fatal(err)
	}
	return &oc
}

func TestReconcileDeliversOnceAndKeepsSecret(t *testing.T) {
	r, i, s := newTestReconciler(t, sampleClient())

	reconcileOK(t, r)
	oc := fetch(t, r)

	ready := meta.FindStatusCondition(oc.Status.Conditions, conditionReady)
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("want Ready=True, got %+v", ready)
	}
	wantPath := "kv/teams/team-alpha/oauth-clients/team-alpha-billing-sync"
	if !oc.Status.CredentialsDelivered || oc.Status.ClientID != "cid-team-alpha-billing-sync" || oc.Status.SecretPath != wantPath {
		t.Fatalf("unexpected status %+v", oc.Status)
	}
	if oc.Status.LastSecretIssued == nil || !controllerutil.ContainsFinalizer(oc, finalizerName) {
		t.Fatal("missing lastSecretIssued or finalizer")
	}
	if s.data[wantPath]["client_secret"] == "" || s.data[wantPath]["state"] != "active" {
		t.Fatalf("credentials not delivered: %v", s.data[wantPath])
	}

	reconcileOK(t, r)
	if i.secretsSet != 1 {
		t.Fatalf("second reconcile issued another secret (secretsSet=%d)", i.secretsSet)
	}
}

func TestReconcileRejectsForeignOwner(t *testing.T) {
	oc := sampleClient()
	oc.Spec.OwnerGroup = "team-bravo"
	r, i, _ := newTestReconciler(t, oc)

	reconcileOK(t, r)
	got := fetch(t, r)

	ready := meta.FindStatusCondition(got.Status.Conditions, conditionReady)
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "InvalidSpec" {
		t.Fatalf("want Ready=False/InvalidSpec, got %+v", ready)
	}
	if i.ensures != 0 || controllerutil.ContainsFinalizer(got, finalizerName) {
		t.Fatal("invalid request must not touch the IdP or add a finalizer")
	}
}

func TestReconcileDeleteCleansUp(t *testing.T) {
	r, i, s := newTestReconciler(t, sampleClient())
	reconcileOK(t, r)

	if err := r.Delete(context.Background(), fetch(t, r)); err != nil {
		t.Fatal(err)
	}
	reconcileOK(t, r)

	if len(i.clients) != 0 || len(s.data) != 0 {
		t.Fatalf("leftovers: idp=%v store=%v", i.clients, s.data)
	}
	var oc courierv1alpha1.OAuthClient
	if err := r.Get(context.Background(), key, &oc); !apierrors.IsNotFound(err) {
		t.Fatalf("object should be gone once the finalizer is removed, got %v", err)
	}
}
