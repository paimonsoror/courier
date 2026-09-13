//go:build integration

package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/paimonsoror/courier/pkg/courier"
	"github.com/paimonsoror/courier/pkg/idp/authentik"
	"github.com/paimonsoror/courier/pkg/secretstore/vault"
)

func requireEnv(t *testing.T, keys ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, k := range keys {
		v := os.Getenv(k)
		if v == "" {
			t.Skipf("%s is required (run deploy/phase1/integration-test.sh)", k)
		}
		out[k] = v
	}
	return out
}

// readSecret reads a KV v2 path the way a team member would.
func readSecret(t *testing.T, addr, token, path string) (int, map[string]string) {
	t.Helper()
	mount, rest, _ := strings.Cut(path, "/")
	req, _ := http.NewRequest(http.MethodGet, addr+"/v1/"+mount+"/data/"+rest, nil)
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.Data.Data
}

// clientCredentials asks the IdP for a token using the delivered credentials.
func clientCredentials(t *testing.T, tokenURL, clientID, clientSecret, username, password string) int {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"username":      {username},
		"password":      {password},
		"scope":         {"openid profile groups"},
	}
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestEndToEnd drives the real Authentik and Vault through the whole lifecycle
// and checks what a consuming team experiences.
func TestEndToEnd(t *testing.T) {
	env := requireEnv(t, "AUTHENTIK_URL", "AUTHENTIK_TOKEN", "VAULT_ADDR", "VAULT_WRITER_TOKEN",
		"VAULT_READER_TOKEN", "TEST_OWNER_GROUP", "TEST_SA_USERNAME", "TEST_SA_TOKEN")
	ctx := context.Background()

	idp, err := authentik.New(authentik.Config{
		Name:          "authentik-homelab",
		BaseURL:       env["AUTHENTIK_URL"],
		Token:         env["AUTHENTIK_TOKEN"],
		ScopeMappings: map[string]string{"groups": "oauth-groups"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := &Broker{
		IDP:       idp,
		Store:     &vault.Store{Addr: env["VAULT_ADDR"], Tokens: vault.StaticToken(env["VAULT_WRITER_TOKEN"])},
		ManagedBy: "courier-integration-test",
	}

	name := fmt.Sprintf("it-e2e-%d", time.Now().UnixNano()%1_000_000_000)
	spec := courier.ClientSpec{
		Name:        name,
		DisplayName: "Courier E2E " + name,
		OwnerGroup:  env["TEST_OWNER_GROUP"],
		Type:        courier.ClientTypeConfidential,
		GrantTypes:  []string{courier.GrantClientCredentials},
		Scopes:      []string{"openid", "profile", "groups"},
	}
	t.Cleanup(func() { _ = b.Delete(context.Background(), spec) })

	// 1. A request is fulfilled.
	res, err := b.Ensure(ctx, spec, Prior{})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !res.SecretIssued || res.Ref.ClientID == "" {
		t.Fatalf("unexpected result %+v", res)
	}
	t.Logf("delivered client_id=%s to %s", res.Ref.ClientID, res.Path)

	// 2. Courier's own token cannot read what it wrote.
	if status, _ := readSecret(t, env["VAULT_ADDR"], env["VAULT_WRITER_TOKEN"], res.Path); status != http.StatusForbidden {
		t.Fatalf("courier token read the secret: HTTP %d (want 403)", status)
	}

	// 3. The owning team reads an active record.
	status, data := readSecret(t, env["VAULT_ADDR"], env["VAULT_READER_TOKEN"], res.Path)
	if status != http.StatusOK {
		t.Fatalf("team read: HTTP %d", status)
	}
	if data["state"] != "active" || data["client_id"] != res.Ref.ClientID || data["client_secret"] == "" {
		t.Fatalf("unexpected record fields: state=%q client_id=%q secret_set=%v", data["state"], data["client_id"], data["client_secret"] != "")
	}
	delivered := data["client_secret"]

	// 4. The delivered secret is the live one at the IdP.
	if code := clientCredentials(t, data["token_endpoint"], data["client_id"], delivered, env["TEST_SA_USERNAME"], env["TEST_SA_TOKEN"]); code != http.StatusOK {
		t.Fatalf("client_credentials with delivered secret: HTTP %d", code)
	}

	// 5. Reconciling again keeps the secret.
	res2, err := b.Ensure(ctx, spec, Prior{Delivered: true})
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if res2.SecretIssued {
		t.Fatal("second Ensure issued a new secret")
	}
	if _, again := readSecret(t, env["VAULT_ADDR"], env["VAULT_READER_TOKEN"], res.Path); again["client_secret"] != delivered {
		t.Fatal("secret changed on re-reconcile")
	}

	// 6. Deleting the request removes the client and destroys the credentials.
	if err := b.Delete(ctx, spec); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if status, _ := readSecret(t, env["VAULT_ADDR"], env["VAULT_READER_TOKEN"], res.Path); status != http.StatusNotFound {
		t.Fatalf("credentials still readable after delete: HTTP %d", status)
	}
	if code := clientCredentials(t, data["token_endpoint"], data["client_id"], delivered, env["TEST_SA_USERNAME"], env["TEST_SA_TOKEN"]); code == http.StatusOK {
		t.Fatal("deleted client still issues tokens")
	}
}
