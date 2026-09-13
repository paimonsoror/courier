// Package vault delivers credentials to a HashiCorp Vault (or OpenBao) KV v2
// mount over the plain HTTP API. It needs create, update, patch and delete on
// the credential paths, and never reads them.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/paimonsoror/courier/pkg/courier"
	"github.com/paimonsoror/courier/pkg/secretstore"
)

var _ secretstore.Store = (*Store)(nil)

// TokenSource supplies a Vault token for each request.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a fixed token, for tests and CLI use.
type StaticToken string

// Token returns the token.
func (t StaticToken) Token(context.Context) (string, error) { return string(t), nil }

const defaultJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// KubernetesAuth logs in with the pod's service account token and caches the
// Vault token until shortly before its lease ends.
type KubernetesAuth struct {
	Addr    string
	Mount   string // auth mount, default "kubernetes"
	Role    string
	JWTPath string // default: the in-pod service account token
	HTTP    *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Token returns a cached token or logs in again.
func (k *KubernetesAuth) Token(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && time.Until(k.expires) > time.Minute {
		return k.token, nil
	}

	jwtPath := k.JWTPath
	if jwtPath == "" {
		jwtPath = defaultJWTPath
	}
	jwt, err := os.ReadFile(jwtPath)
	if err != nil {
		return "", fmt.Errorf("read service account token: %w", err)
	}
	mount := k.Mount
	if mount == "" {
		mount = "kubernetes"
	}
	body, err := json.Marshal(map[string]string{"role": k.Role, "jwt": strings.TrimSpace(string(jwt))})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(k.Addr, "/")+"/v1/auth/"+mount+"/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient(k.HTTP).Do(req)
	if err != nil {
		return "", fmt.Errorf("vault kubernetes login: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault kubernetes login: %w", apiError(resp))
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode vault login response: %w", err)
	}
	k.token = out.Auth.ClientToken
	k.expires = time.Now().Add(time.Duration(out.Auth.LeaseDuration) * time.Second)
	return k.token, nil
}

// Store writes credential records to a KV v2 mount.
type Store struct {
	Addr      string
	Mount     string // KV v2 mount, default "kv"
	Namespace string // Vault Enterprise namespace, optional
	Tokens    TokenSource
	HTTP      *http.Client
}

func (s *Store) mount() string {
	if s.Mount == "" {
		return "kv"
	}
	return strings.Trim(s.Mount, "/")
}

// PathFor returns <mount>/teams/<owner group>/oauth-clients/<name>.
func (s *Store) PathFor(spec courier.ClientSpec) string {
	return s.mount() + "/teams/" + spec.OwnerGroup + "/oauth-clients/" + spec.Name
}

// Put replaces the record at path (a new KV version).
func (s *Store) Put(ctx context.Context, path string, rec secretstore.Record) error {
	return s.write(ctx, http.MethodPost, path, "application/json", rec.Fields())
}

// Patch merges non-secret fields with a JSON merge patch. It needs only the
// "patch" capability, so the existing secret is neither read nor resent.
func (s *Store) Patch(ctx context.Context, path string, rec secretstore.Record) error {
	if !rec.ClientSecret.IsZero() {
		return errors.New("vault: Patch must not carry a client secret")
	}
	return s.write(ctx, http.MethodPatch, path, "application/merge-patch+json", rec.Fields())
}

// Delete destroys every version and the metadata at path.
func (s *Store) Delete(ctx context.Context, path string) error {
	u, err := s.url(path, "metadata")
	if err != nil {
		return err
	}
	resp, err := s.do(ctx, http.MethodDelete, u, "", nil)
	if err != nil {
		return fmt.Errorf("vault delete %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	return fmt.Errorf("vault delete %s: %w", path, apiError(resp))
}

func (s *Store) write(ctx context.Context, method, path, contentType string, fields map[string]string) error {
	u, err := s.url(path, "data")
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"data": fields})
	if err != nil {
		return err
	}
	resp, err := s.do(ctx, method, u, contentType, body)
	if err != nil {
		return fmt.Errorf("vault %s %s: %w", strings.ToLower(method), path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return fmt.Errorf("vault %s %s: %w", strings.ToLower(method), path, apiError(resp))
}

// url maps "<mount>/a/b" to "<addr>/v1/<mount>/<kind>/a/b".
func (s *Store) url(path, kind string) (string, error) {
	prefix := s.mount() + "/"
	if !strings.HasPrefix(path, prefix) {
		return "", fmt.Errorf("vault: path %q is outside mount %q", path, s.mount())
	}
	segs := strings.Split(strings.TrimPrefix(path, prefix), "/")
	for i, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("vault: invalid path %q", path)
		}
		segs[i] = url.PathEscape(seg)
	}
	return strings.TrimRight(s.Addr, "/") + "/v1/" + s.mount() + "/" + kind + "/" + strings.Join(segs, "/"), nil
}

func (s *Store) do(ctx context.Context, method, u, contentType string, body []byte) (*http.Response, error) {
	if s.Tokens == nil {
		return nil, errors.New("no token source configured")
	}
	tok, err := s.Tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", tok)
	req.Header.Set("X-Vault-Request", "true")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if s.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.Namespace)
	}
	return httpClient(s.HTTP).Do(req)
}

func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// apiError reports Vault's error strings. Vault never echoes request bodies,
// so this cannot leak the secret being written.
func apiError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(raw, &e) == nil && len(e.Errors) > 0 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.Join(e.Errors, "; "))
	}
	return fmt.Errorf("HTTP %d", resp.StatusCode)
}
