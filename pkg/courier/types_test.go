package courier

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	base := ClientSpec{
		Name:         "payments-mcp",
		OwnerGroup:   "team-payments",
		Type:         ClientTypeConfidential,
		GrantTypes:   []string{GrantAuthorizationCode},
		RedirectURIs: []string{"https://mcp.example/callback"},
	}

	cases := []struct {
		name    string
		mutate  func(*ClientSpec)
		wantErr string
	}{
		{"valid", func(*ClientSpec) {}, ""},
		{"bad name", func(s *ClientSpec) { s.Name = "Payments_MCP" }, "lowercase DNS label"},
		{"no owner", func(s *ClientSpec) { s.OwnerGroup = "" }, "ownerGroup is required"},
		{"unknown type", func(s *ClientSpec) { s.Type = "privateKeyJwt" }, "must be"},
		{"unknown grant", func(s *ClientSpec) { s.GrantTypes = []string{"implicit"} }, "not supported"},
		{"public client_credentials", func(s *ClientSpec) {
			s.Type = ClientTypePublic
			s.GrantTypes = []string{GrantClientCredentials}
		}, "requires a confidential client"},
		{"auth code without redirect", func(s *ClientSpec) { s.RedirectURIs = nil }, "requires at least one redirect URI"},
		{"wildcard redirect", func(s *ClientSpec) { s.RedirectURIs = []string{"https://*.example/cb"} }, "wildcards"},
		{"http redirect", func(s *ClientSpec) { s.RedirectURIs = []string{"http://mcp.example/cb"} }, "must use https"},
		{"loopback on confidential", func(s *ClientSpec) {
			s.RedirectURIs = []string{"http://localhost:8250/cb"}
		}, "only allowed for public"},
		{"loopback on public", func(s *ClientSpec) {
			s.Type = ClientTypePublic
			s.RedirectURIs = []string{"http://127.0.0.1:8250/cb"}
		}, ""},
		{"m2m without redirect", func(s *ClientSpec) {
			s.GrantTypes = []string{GrantClientCredentials}
			s.RedirectURIs = nil
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.RedirectURIs = append([]string(nil), base.RedirectURIs...)
			tc.mutate(&s)
			err := s.Normalize().Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestNormalizeDefaults(t *testing.T) {
	s := ClientSpec{Name: "x", OwnerGroup: "team-a"}.Normalize()
	if s.DisplayName != "x" || len(s.AllowGroups) != 1 || s.AllowGroups[0] != "team-a" || s.Scopes[0] != "openid" {
		t.Fatalf("unexpected defaults: %+v", s)
	}
}
