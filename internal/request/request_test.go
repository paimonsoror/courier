package request

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	teamAlpha  = "team-alpha"
	m2mGrant   = "  grantTypes: [client_credentials]\n"
	authCode   = "  grantTypes: [authorization_code]\n"
	newM2MFile = "team-alpha/new-m2m.yaml"
	newM2M     = "new-m2m"
	approval   = "security-approved"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "requests")
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func oauthClient(ns, name, extra string) string {
	return "apiVersion: courier.sororlab.dev/v1alpha1\nkind: OAuthClient\nmetadata:\n  name: " + name +
		"\n  namespace: " + ns + "\nspec:\n  clientType: confidential\n" + extra
}

var policy = Policy{
	TeamPattern:          `^team-[a-z0-9-]+$`,
	AllowedRedirectHosts: []string{"*.sororlab.dev", "localhost"},
	GrantApprovals:       map[string]string{"client_credentials": approval},
}

func check(t *testing.T, files map[string]string, changed, labels []string) []Finding {
	t.Helper()
	root := writeTree(t, files)
	reqs, findings, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	abs := make([]string, 0, len(changed))
	for _, c := range changed {
		abs = append(abs, filepath.ToSlash(filepath.Join(root, c)))
	}
	o := Options{Root: root, Policy: policy, Changed: abs, EnforceApprovals: true, Labels: labels}
	return append(findings, Check(reqs, o)...)
}

func wantFinding(t *testing.T, findings []Finding, substr string) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Message, substr) {
			return
		}
	}
	t.Fatalf("want a finding containing %q, got %v", substr, findings)
}

func TestValidRequestPasses(t *testing.T) {
	findings := check(t, map[string]string{
		".policy.yaml": "ignored: true",
		"README.md":    "# not a request",
		"team-alpha/web-app.yaml": oauthClient(teamAlpha, "web-app",
			authCode+"  redirectUris: [https://app.sororlab.dev/callback]\n"),
	}, []string{"team-alpha/web-app.yaml"}, nil)
	if len(findings) != 0 {
		t.Fatalf("unexpected findings: %v", findings)
	}
}

func TestLayoutRules(t *testing.T) {
	findings := check(t, map[string]string{
		"team-alpha/wrong-name.yaml": oauthClient(teamAlpha, "billing", m2mGrant),
		"team-alpha/other.yaml":      oauthClient("team-bravo", "other", m2mGrant),
		"loose.yaml":                 oauthClient(teamAlpha, "loose", m2mGrant),
		"Team_X/app.yaml":            oauthClient("Team_X", "app", m2mGrant),
	}, nil, nil)
	wantFinding(t, findings, `must match the file name "wrong-name"`)
	wantFinding(t, findings, `must be the team directory "team-alpha"`)
	wantFinding(t, findings, "requests must live at")
	wantFinding(t, findings, "does not match")
}

func TestOnlyOAuthClientsAllowed(t *testing.T) {
	findings := check(t, map[string]string{
		"team-alpha/sneaky.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: sneaky\n",
	}, nil, nil)
	wantFinding(t, findings, "only courier.sororlab.dev/v1alpha1 OAuthClient objects are allowed")
}

func TestUnknownFieldsRejected(t *testing.T) {
	findings := check(t, map[string]string{
		"team-alpha/typo.yaml": oauthClient(teamAlpha, "typo", m2mGrant+"  scopez: [openid]\n"),
	}, nil, nil)
	wantFinding(t, findings, "invalid OAuthClient")
}

func TestControllerRulesApply(t *testing.T) {
	findings := check(t, map[string]string{
		"team-alpha/foreign.yaml":  oauthClient(teamAlpha, "foreign", "  ownerGroup: team-bravo\n"+m2mGrant),
		"team-alpha/insecure.yaml": oauthClient(teamAlpha, "insecure", authCode+"  redirectUris: [http://app.sororlab.dev/cb]\n"),
	}, nil, nil)
	wantFinding(t, findings, "must match the namespace")
	wantFinding(t, findings, "must use https")
}

func TestRedirectHostPolicy(t *testing.T) {
	findings := check(t, map[string]string{
		"team-alpha/web.yaml": oauthClient(teamAlpha, "web", authCode+"  redirectUris: [https://evil.example.com/cb]\n"),
	}, nil, nil)
	wantFinding(t, findings, `redirect URI host "evil.example.com" is not in allowedRedirectHosts`)
}

func TestApprovalLabelOnlyForChangedRequests(t *testing.T) {
	files := map[string]string{
		"team-alpha/existing-m2m.yaml": oauthClient(teamAlpha, "existing-m2m", m2mGrant),
		newM2MFile:                     oauthClient(teamAlpha, newM2M, m2mGrant),
	}

	findings := check(t, files, []string{newM2MFile}, []string{"docs"})
	if len(findings) != 1 || !strings.HasSuffix(findings[0].File, newM2MFile) {
		t.Fatalf("want exactly one approval finding for the changed file, got %v", findings)
	}
	wantFinding(t, findings, `needs the "security-approved" label`)

	if findings := check(t, files, []string{newM2MFile}, []string{approval}); len(findings) != 0 {
		t.Fatalf("label present, want no findings, got %v", findings)
	}
}

func TestDuplicates(t *testing.T) {
	body := oauthClient(teamAlpha, "dup", m2mGrant)
	findings := check(t, map[string]string{"team-alpha/dup.yaml": body + "\n---\n" + body}, nil, nil)
	wantFinding(t, findings, "duplicate request team-alpha/dup")
}

func TestSummary(t *testing.T) {
	root := writeTree(t, map[string]string{newM2MFile: oauthClient(teamAlpha, newM2M, m2mGrant)})
	reqs, _, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	changed := RequestFiles(root, []string{
		filepath.Join(root, filepath.FromSlash(newM2MFile)),
		filepath.Join(root, "team-alpha", "gone.yaml"),
		filepath.Join(root, "README.md"),
	})
	o := Options{Root: root, Policy: policy, Changed: changed, EnforceApprovals: true}
	s := Summary(reqs, o, Check(reqs, o), "kv")

	for _, want := range []string{
		"`kv/teams/team-alpha/oauth-clients/team-alpha-new-m2m`",
		"needs label `security-approved`",
		"| **removed** | team-alpha | `gone` |",
		"### Problems",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "README") {
		t.Fatalf("non-request files must not appear:\n%s", s)
	}
}
