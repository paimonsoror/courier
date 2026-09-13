// Package courier holds the core domain types shared by every Courier front
// end (Kubernetes controller, CLI). It must not import Kubernetes packages.
package courier

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// ClientType is the OAuth client type.
type ClientType string

const (
	// ClientTypePublic clients authenticate with PKCE only and never get a secret.
	ClientTypePublic ClientType = "public"
	// ClientTypeConfidential clients get a client secret delivered to the store.
	ClientTypeConfidential ClientType = "confidential"
)

// Grant types Courier knows how to request.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
)

var knownGrants = []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials}

var nameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ClientSpec is the desired state of one OAuth client.
type ClientSpec struct {
	// Name is the stable identifier, unique per IdP (a DNS-1123 label).
	// Adapters use it to find the client again, e.g. as the Authentik app slug.
	Name        string
	DisplayName string
	// OwnerGroup is the IdP group that owns the client and may read its credentials.
	OwnerGroup   string
	Type         ClientType
	GrantTypes   []string
	RedirectURIs []string
	Scopes       []string
	// AllowGroups may sign in through the client. Defaults to OwnerGroup.
	AllowGroups []string
}

// Normalize fills defaults. It returns a copy and leaves s unchanged.
func (s ClientSpec) Normalize() ClientSpec {
	if s.DisplayName == "" {
		s.DisplayName = s.Name
	}
	if len(s.AllowGroups) == 0 && s.OwnerGroup != "" {
		s.AllowGroups = []string{s.OwnerGroup}
	}
	if len(s.Scopes) == 0 {
		s.Scopes = []string{"openid"}
	}
	return s
}

// Validate reports every problem with the spec at once.
func (s ClientSpec) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if len(s.Name) > 63 || !nameRE.MatchString(s.Name) {
		add("name %q must be a lowercase DNS label (a-z, 0-9, '-', max 63 chars)", s.Name)
	}
	if s.OwnerGroup == "" {
		add("ownerGroup is required")
	}
	if s.Type != ClientTypePublic && s.Type != ClientTypeConfidential {
		add("type %q must be %q or %q", s.Type, ClientTypePublic, ClientTypeConfidential)
	}
	if len(s.GrantTypes) == 0 {
		add("at least one grant type is required")
	}
	for _, g := range s.GrantTypes {
		if !slices.Contains(knownGrants, g) {
			add("grant type %q is not supported (use one of %s)", g, strings.Join(knownGrants, ", "))
		}
	}
	if slices.Contains(s.GrantTypes, GrantClientCredentials) && s.Type == ClientTypePublic {
		add("client_credentials requires a confidential client")
	}
	if slices.Contains(s.GrantTypes, GrantAuthorizationCode) && len(s.RedirectURIs) == 0 {
		add("authorization_code requires at least one redirect URI")
	}
	for _, raw := range s.RedirectURIs {
		if err := validateRedirect(raw, s.Type); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func validateRedirect(raw string, t ClientType) error {
	if strings.Contains(raw, "*") {
		return fmt.Errorf("redirect URI %q: wildcards are not allowed", raw)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("redirect URI %q: must be an absolute URL", raw)
	}
	if u.Fragment != "" {
		return fmt.Errorf("redirect URI %q: must not contain a fragment", raw)
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		if t != ClientTypePublic {
			return fmt.Errorf("redirect URI %q: http loopback redirects are only allowed for public clients", raw)
		}
		return nil
	default:
		return fmt.Errorf("redirect URI %q: must use https (http only for localhost on public clients)", raw)
	}
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// ClientRef identifies a client that exists in an IdP.
type ClientRef struct {
	ClientID string
	// Objects holds IdP-specific identifiers, e.g. Authentik provider pk.
	Objects map[string]string
}

// Endpoints are the OAuth/OIDC endpoints a consumer needs.
type Endpoints struct {
	Issuer           string
	AuthorizationURL string
	TokenURL         string
	JWKSURL          string
	UserinfoURL      string
}
