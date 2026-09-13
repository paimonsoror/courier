// Package authentik implements idp.Provider for Authentik's API v3.
//
// Each Courier client becomes an OAuth2 provider named "courier-<name>" plus
// an application with slug <name>. Group policy bindings on the application
// decide who may use it. Applications Courier did not create are never
// touched: they lack the managed-by marker in meta_description.
package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paimonsoror/courier/pkg/courier"
	"github.com/paimonsoror/courier/pkg/idp"
)

var _ idp.Provider = (*Provider)(nil)

// ErrNotManaged means an application with the requested slug exists but
// Courier did not create it.
var ErrNotManaged = idp.ErrNotManaged

const managedMarker = "managed-by: courier"

// Built-in Authentik scope mappings, identified by their managed id.
var managedScopes = map[string]string{
	"openid":         "goauthentik.io/providers/oauth2/scope-openid",
	"email":          "goauthentik.io/providers/oauth2/scope-email",
	"profile":        "goauthentik.io/providers/oauth2/scope-profile",
	"offline_access": "goauthentik.io/providers/oauth2/scope-offline_access",
}

// Config configures the adapter.
type Config struct {
	Name              string // adapter instance name, default "authentik"
	BaseURL           string // e.g. https://auth.sororlab.dev
	Token             string // API token
	AuthorizationFlow string // flow slug, default default-provider-authorization-implicit-consent
	InvalidationFlow  string // flow slug, default default-provider-invalidation-flow
	SigningKey        string // certificate-key pair name, default "authentik Self-signed Certificate"
	SubMode           string // default user_email
	// ScopeMappings maps non-built-in scopes to property mapping names,
	// e.g. {"groups": "oauth-groups"}. It can also override built-ins.
	ScopeMappings map[string]string
	HTTPClient    *http.Client
}

// Provider is the Authentik adapter.
type Provider struct {
	cfg  Config
	http *http.Client
}

// New validates cfg and fills defaults.
func New(cfg Config) (*Provider, error) {
	if cfg.BaseURL == "" || cfg.Token == "" {
		return nil, errors.New("authentik: BaseURL and Token are required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.Name == "" {
		cfg.Name = "authentik"
	}
	if cfg.AuthorizationFlow == "" {
		cfg.AuthorizationFlow = "default-provider-authorization-implicit-consent"
	}
	if cfg.InvalidationFlow == "" {
		cfg.InvalidationFlow = "default-provider-invalidation-flow"
	}
	if cfg.SigningKey == "" {
		cfg.SigningKey = "authentik Self-signed Certificate"
	}
	if cfg.SubMode == "" {
		cfg.SubMode = "user_email"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Provider{cfg: cfg, http: hc}, nil
}

// Name returns the adapter instance name.
func (p *Provider) Name() string { return p.cfg.Name }

// Endpoints returns Authentik's per-application OAuth endpoints.
func (p *Provider) Endpoints(spec courier.ClientSpec) courier.Endpoints {
	base := p.cfg.BaseURL + "/application/o/"
	return courier.Endpoints{
		Issuer:           base + spec.Name + "/",
		AuthorizationURL: base + "authorize/",
		TokenURL:         base + "token/",
		UserinfoURL:      base + "userinfo/",
		JWKSURL:          base + spec.Name + "/jwks/",
	}
}

type application struct {
	PK              string `json:"pk"`
	Slug            string `json:"slug"`
	Provider        *int   `json:"provider"`
	MetaDescription string `json:"meta_description"`
}

type oauth2Provider struct {
	PK                      int    `json:"pk"`
	Name                    string `json:"name"`
	ClientID                string `json:"client_id"`
	AssignedApplicationSlug string `json:"assigned_application_slug"`
}

type object struct {
	PK   string `json:"pk"`
	Name string `json:"name"`
}

func providerName(name string) string { return "courier-" + name }

// Lookup finds a Courier-managed application by slug.
func (p *Provider) Lookup(ctx context.Context, name string) (courier.ClientRef, bool, error) {
	var app application
	found, err := p.get(ctx, "core/applications/"+url.PathEscape(name)+"/", &app)
	if err != nil || !found {
		return courier.ClientRef{}, false, err
	}
	if !strings.Contains(app.MetaDescription, managedMarker) {
		return courier.ClientRef{}, false, fmt.Errorf("authentik: %w: %q", ErrNotManaged, name)
	}
	ref := courier.ClientRef{Objects: map[string]string{"application_slug": app.Slug, "application_pk": app.PK}}
	if app.Provider != nil {
		var prov oauth2Provider
		ok, err := p.get(ctx, fmt.Sprintf("providers/oauth2/%d/", *app.Provider), &prov)
		if err != nil {
			return courier.ClientRef{}, false, err
		}
		if ok {
			ref.ClientID = prov.ClientID
			ref.Objects["provider_pk"] = strconv.Itoa(prov.PK)
		}
	}
	return ref, true, nil
}

// EnsureClient creates or updates the provider, application and group bindings.
func (p *Provider) EnsureClient(
	ctx context.Context, spec courier.ClientSpec, secret courier.Secret,
) (courier.ClientRef, error) {
	spec = spec.Normalize()
	existing, found, err := p.Lookup(ctx, spec.Name)
	if err != nil {
		return courier.ClientRef{}, err
	}

	authzFlow, err := p.flowPK(ctx, p.cfg.AuthorizationFlow)
	if err != nil {
		return courier.ClientRef{}, err
	}
	invalidationFlow, err := p.flowPK(ctx, p.cfg.InvalidationFlow)
	if err != nil {
		return courier.ClientRef{}, err
	}
	signingKey, err := p.namedPK(ctx, "crypto/certificatekeypairs/", p.cfg.SigningKey)
	if err != nil {
		return courier.ClientRef{}, err
	}
	mappings, err := p.scopeMappings(ctx, spec.Scopes)
	if err != nil {
		return courier.ClientRef{}, err
	}
	groups, err := p.groupPKs(ctx, spec.AllowGroups)
	if err != nil {
		return courier.ClientRef{}, err
	}

	redirects := make([]map[string]string, 0, len(spec.RedirectURIs))
	for _, u := range spec.RedirectURIs {
		redirects = append(redirects, map[string]string{"matching_mode": "strict", "url": u})
	}
	body := map[string]any{
		"name":                       providerName(spec.Name),
		"authorization_flow":         authzFlow,
		"invalidation_flow":          invalidationFlow,
		"client_type":                string(spec.Type),
		"grant_types":                spec.GrantTypes, // Authentik 2026.x rejects unlisted grants
		"redirect_uris":              redirects,
		"property_mappings":          mappings,
		"signing_key":                signingKey,
		"sub_mode":                   p.cfg.SubMode,
		"include_claims_in_id_token": true,
	}
	if !secret.IsZero() {
		body["client_secret"] = secret.Reveal()
	}

	provPK, _ := strconv.Atoi(existing.Objects["provider_pk"])
	if provPK == 0 {
		// A provider can be left over from an attempt that failed before the
		// application was created; reuse it instead of colliding on the name.
		provPK, err = p.orphanProvider(ctx, spec.Name)
		if err != nil {
			return courier.ClientRef{}, err
		}
	}
	var prov oauth2Provider
	if provPK != 0 {
		err = p.send(ctx, http.MethodPatch, fmt.Sprintf("providers/oauth2/%d/", provPK), body, &prov, secret)
	} else {
		err = p.send(ctx, http.MethodPost, "providers/oauth2/", body, &prov, secret)
	}
	if err != nil {
		return courier.ClientRef{}, fmt.Errorf("authentik: save provider: %w", err)
	}

	appBody := map[string]any{
		"name":               spec.DisplayName,
		"slug":               spec.Name,
		"provider":           prov.PK,
		"meta_description":   managedMarker + "; owner: " + spec.OwnerGroup,
		"policy_engine_mode": "any",
	}
	var app application
	if found {
		appPath := "core/applications/" + url.PathEscape(spec.Name) + "/"
		err = p.send(ctx, http.MethodPatch, appPath, appBody, &app, courier.Secret{})
	} else {
		err = p.send(ctx, http.MethodPost, "core/applications/", appBody, &app, courier.Secret{})
	}
	if err != nil {
		return courier.ClientRef{}, fmt.Errorf("authentik: save application: %w", err)
	}

	if err := p.syncBindings(ctx, app.PK, groups); err != nil {
		return courier.ClientRef{}, fmt.Errorf("authentik: sync group bindings: %w", err)
	}

	return courier.ClientRef{
		ClientID: prov.ClientID,
		Objects: map[string]string{
			"application_slug": app.Slug,
			"application_pk":   app.PK,
			"provider_pk":      strconv.Itoa(prov.PK),
		},
	}, nil
}

// DeleteClient removes the application (and its bindings) and the provider.
func (p *Provider) DeleteClient(ctx context.Context, ref courier.ClientRef) error {
	if slug := ref.Objects["application_slug"]; slug != "" {
		if err := p.del(ctx, "core/applications/"+url.PathEscape(slug)+"/"); err != nil {
			return fmt.Errorf("authentik: delete application: %w", err)
		}
	}
	if pk := ref.Objects["provider_pk"]; pk != "" {
		if err := p.del(ctx, "providers/oauth2/"+url.PathEscape(pk)+"/"); err != nil {
			return fmt.Errorf("authentik: delete provider: %w", err)
		}
	}
	return nil
}

func (p *Provider) orphanProvider(ctx context.Context, name string) (int, error) {
	var list struct {
		Results []oauth2Provider `json:"results"`
	}
	if _, err := p.get(ctx, "providers/oauth2/?name="+url.QueryEscape(providerName(name)), &list); err != nil {
		return 0, err
	}
	for _, pr := range list.Results {
		if pr.Name != providerName(name) {
			continue
		}
		if pr.AssignedApplicationSlug != "" && pr.AssignedApplicationSlug != name {
			return 0, fmt.Errorf("authentik: provider %q is assigned to application %q", pr.Name, pr.AssignedApplicationSlug)
		}
		return pr.PK, nil
	}
	return 0, nil
}

func (p *Provider) flowPK(ctx context.Context, slug string) (string, error) {
	var flow object
	found, err := p.get(ctx, "flows/instances/"+url.PathEscape(slug)+"/", &flow)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("authentik: flow %q not found", slug)
	}
	return flow.PK, nil
}

func (p *Provider) namedPK(ctx context.Context, collection, name string) (string, error) {
	var list struct {
		Results []object `json:"results"`
	}
	if _, err := p.get(ctx, collection+"?name="+url.QueryEscape(name), &list); err != nil {
		return "", err
	}
	for _, o := range list.Results {
		if o.Name == name {
			return o.PK, nil
		}
	}
	return "", fmt.Errorf("authentik: %s %q not found", strings.TrimSuffix(collection, "/"), name)
}

func (p *Provider) groupPKs(ctx context.Context, names []string) (map[string]string, error) {
	out := make(map[string]string, len(names))
	for _, n := range names {
		pk, err := p.namedPK(ctx, "core/groups/", n)
		if err != nil {
			return nil, err
		}
		out[pk] = n
	}
	return out, nil
}

func (p *Provider) scopeMappings(ctx context.Context, scopes []string) ([]string, error) {
	var list struct {
		Results []struct {
			PK      string  `json:"pk"`
			Name    string  `json:"name"`
			Managed *string `json:"managed"`
		} `json:"results"`
	}
	if _, err := p.get(ctx, "propertymappings/provider/scope/?page_size=500", &list); err != nil {
		return nil, err
	}
	var pks, missing []string
	for _, scope := range scopes {
		wantName := p.cfg.ScopeMappings[scope]
		managedID, builtin := managedScopes[scope]
		pk := ""
		for _, m := range list.Results {
			if wantName != "" && m.Name == wantName ||
				wantName == "" && builtin && m.Managed != nil && *m.Managed == managedID {
				pk = m.PK
				break
			}
		}
		if pk == "" {
			missing = append(missing, scope)
			continue
		}
		pks = append(pks, pk)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("authentik: no scope mapping for %s (set Config.ScopeMappings)", strings.Join(missing, ", "))
	}
	return pks, nil
}

func (p *Provider) syncBindings(ctx context.Context, appPK string, groups map[string]string) error {
	var list struct {
		Results []struct {
			PK    string  `json:"pk"`
			Group *string `json:"group"`
			Order int     `json:"order"`
		} `json:"results"`
	}
	if _, err := p.get(ctx, "policies/bindings/?page_size=500&target="+url.QueryEscape(appPK), &list); err != nil {
		return err
	}
	have := map[string]bool{}
	nextOrder := 0
	for _, b := range list.Results {
		if b.Order >= nextOrder {
			nextOrder = b.Order + 1
		}
		if b.Group == nil {
			continue
		}
		if _, want := groups[*b.Group]; want {
			have[*b.Group] = true
			continue
		}
		if err := p.del(ctx, "policies/bindings/"+url.PathEscape(b.PK)+"/"); err != nil {
			return err
		}
	}
	pks := make([]string, 0, len(groups))
	for pk := range groups {
		pks = append(pks, pk)
	}
	slices.Sort(pks)
	for _, pk := range pks {
		if have[pk] {
			continue
		}
		body := map[string]any{
			"target": appPK, "group": pk, "order": nextOrder, "enabled": true, "negate": false, "timeout": 30,
		}
		if err := p.send(ctx, http.MethodPost, "policies/bindings/", body, nil, courier.Secret{}); err != nil {
			return err
		}
		nextOrder++
	}
	return nil
}

func (p *Provider) get(ctx context.Context, path string, out any) (bool, error) {
	resp, err := p.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, fmt.Errorf("authentik: GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("authentik: GET %s: %w", path, apiError(resp, courier.Secret{}))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return false, fmt.Errorf("authentik: decode %s: %w", path, err)
	}
	return true, nil
}

func (p *Provider) send(ctx context.Context, method, path string, body, out any, secret courier.Secret) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := p.do(ctx, method, path, raw)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s %s: %w", method, path, apiError(resp, secret))
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (p *Provider) del(ctx context.Context, path string) error {
	resp, err := p.do(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	return fmt.Errorf("DELETE %s: %w", path, apiError(resp, courier.Secret{}))
}

func (p *Provider) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.cfg.BaseURL+"/api/v3/"+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return p.http.Do(req)
}

// apiError includes Authentik's (truncated) response and scrubs the secret
// in case a validation error ever echoes it.
func apiError(resp *http.Response, secret courier.Secret) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := strings.TrimSpace(string(raw))
	if !secret.IsZero() {
		msg = strings.ReplaceAll(msg, secret.Reveal(), "[REDACTED]")
	}
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
}
