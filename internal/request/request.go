// Package request loads and checks OAuthClient request files kept in a GitOps
// repository (requests/<team>/<name>.yaml). The controller and the courier
// CLI share these rules, so a pull request is checked exactly as the
// controller will enforce it after merge.
package request

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	courierv1alpha1 "github.com/paimonsoror/courier/api/v1alpha1"
	"github.com/paimonsoror/courier/pkg/courier"
)

const (
	requestAPIVersion = "courier.sororlab.dev/v1alpha1"
	requestKind       = "OAuthClient"

	// catalogSuffix marks an optional Backstage entity file next to a request:
	// <root>/<team>/<name>.catalog.yml. ArgoCD only syncs *.yaml, so these are
	// never applied to the cluster.
	catalogSuffix = ".catalog.yml"
	// ClientLabel ties an OAuthClient to its Backstage entity's label selector.
	ClientLabel = "courier.sororlab.dev/client"
)

// ToClientSpec maps a request onto the core spec. The IdP-side name is
// <namespace>-<name> so two teams can reuse a resource name without colliding.
func ToClientSpec(oc *courierv1alpha1.OAuthClient) courier.ClientSpec {
	owner := oc.Spec.OwnerGroup
	if owner == "" {
		owner = oc.Namespace
	}
	display := oc.Spec.DisplayName
	if display == "" {
		display = oc.Namespace + "/" + oc.Name
	}
	return courier.ClientSpec{
		Name:         oc.Namespace + "-" + oc.Name,
		DisplayName:  display,
		OwnerGroup:   owner,
		Type:         courier.ClientType(oc.Spec.ClientType),
		GrantTypes:   oc.Spec.GrantTypes,
		RedirectURIs: oc.Spec.RedirectURIs,
		Scopes:       oc.Spec.Scopes,
		AllowGroups:  oc.Spec.AllowGroups,
	}
}

// CheckClient applies the rules the controller enforces: the owner group is
// the namespace, and the spec passes core validation.
func CheckClient(oc *courierv1alpha1.OAuthClient) error {
	spec := ToClientSpec(oc)
	if spec.OwnerGroup != oc.Namespace {
		return fmt.Errorf("ownerGroup %q must match the namespace %q", spec.OwnerGroup, oc.Namespace)
	}
	return spec.Normalize().Validate()
}

// Policy holds repository rules that go beyond what the controller enforces.
type Policy struct {
	// TeamPattern is a regular expression every team directory must match.
	TeamPattern string `json:"teamPattern,omitempty"`
	// AllowedRedirectHosts lists exact hosts or "*.domain" patterns. Empty allows any host.
	AllowedRedirectHosts []string `json:"allowedRedirectHosts,omitempty"`
	// GrantApprovals maps a grant type to the pull request label that must be present.
	GrantApprovals map[string]string `json:"grantApprovals,omitempty"`
}

// LoadPolicy reads a policy file. An empty path returns the zero policy.
func LoadPolicy(file string) (Policy, error) {
	var p Policy
	if file == "" {
		return p, nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return p, err
	}
	if err := yaml.UnmarshalStrict(raw, &p); err != nil {
		return p, fmt.Errorf("%s: %w", file, err)
	}
	if p.TeamPattern != "" {
		if _, err := regexp.Compile(p.TeamPattern); err != nil {
			return p, fmt.Errorf("%s: teamPattern: %w", file, err)
		}
	}
	return p, nil
}

func (p Policy) redirectHostAllowed(host string) bool {
	if len(p.AllowedRedirectHosts) == 0 {
		return true
	}
	for _, pattern := range p.AllowedRedirectHosts {
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if host == pattern {
			return true
		}
	}
	return false
}

// Request is one OAuthClient read from a file.
type Request struct {
	File   string // slash-separated path, e.g. requests/team-alpha/billing-sync.yaml
	Client courierv1alpha1.OAuthClient
}

// Finding is one problem, tied to a file.
type Finding struct {
	File    string
	Message string
}

func (f Finding) String() string { return f.File + ": " + f.Message }

// IsRequestFile reports whether file sits where requests belong:
// <root>/<team>/<name>.yaml, not hidden.
func IsRequestFile(root, file string) bool {
	rel, ok := strings.CutPrefix(path.Clean(filepath.ToSlash(file)), path.Clean(filepath.ToSlash(root))+"/")
	if !ok {
		return false
	}
	parts := strings.Split(rel, "/")
	if len(parts) != 2 || strings.HasPrefix(parts[0], ".") || strings.HasPrefix(parts[1], ".") {
		return false
	}
	if strings.HasSuffix(parts[1], catalogSuffix) {
		return false
	}
	ext := path.Ext(parts[1])
	return ext == ".yaml" || ext == ".yml"
}

// Load parses every .yaml/.yml file below root, skipping hidden files and
// directories (such as root/.policy.yaml). Unparseable content becomes findings.
func Load(root string) ([]Request, []Finding, error) {
	var reqs []Request
	var findings []Finding
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if p != root && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(p); d.IsDir() || (ext != ".yaml" && ext != ".yml") || strings.HasSuffix(p, catalogSuffix) {
			return nil
		}
		file := filepath.ToSlash(p)
		docs, err := readDocs(p)
		if err != nil {
			findings = append(findings, Finding{file, err.Error()})
			return nil
		}
		for _, doc := range docs {
			req, finding := parse(file, doc)
			if finding != nil {
				findings = append(findings, *finding)
				continue
			}
			reqs = append(reqs, req)
		}
		return nil
	})
	return reqs, findings, err
}

func parse(file string, doc []byte) (Request, *Finding) {
	var tm struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}
	if err := yaml.Unmarshal(doc, &tm); err != nil {
		return Request{}, &Finding{file, "not valid YAML: " + err.Error()}
	}
	if tm.APIVersion != requestAPIVersion || tm.Kind != requestKind {
		return Request{}, &Finding{file, fmt.Sprintf("only %s %s objects are allowed here, found %q %q",
			requestAPIVersion, requestKind, tm.APIVersion, tm.Kind)}
	}
	var oc courierv1alpha1.OAuthClient
	if err := yaml.UnmarshalStrict(doc, &oc); err != nil {
		return Request{}, &Finding{file, "invalid OAuthClient: " + err.Error()}
	}
	return Request{File: file, Client: oc}, nil
}

func readDocs(file string) ([][]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	reader := utilyaml.NewYAMLReader(bufio.NewReader(f))
	var docs [][]byte
	for {
		doc, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, err
		}
		// Skip empty and comment-only documents. Keep everything else,
		// including unparseable YAML, so parse reports it.
		var probe map[string]any
		if len(bytes.TrimSpace(doc)) > 0 && (yaml.Unmarshal(doc, &probe) != nil || len(probe) > 0) {
			docs = append(docs, doc)
		}
	}
}

// Options controls repository checks.
type Options struct {
	Root   string
	Policy Policy
	// Changed lists request files touched by the pull request.
	Changed []string
	// EnforceApprovals requires Policy.GrantApprovals labels on changed requests.
	EnforceApprovals bool
	Labels           []string
}

// Check applies repository layout, controller and policy rules to every request.
func Check(reqs []Request, o Options) []Finding {
	var out []Finding
	add := func(file, format string, args ...any) {
		out = append(out, Finding{file, fmt.Sprintf(format, args...)})
	}
	var teamRE *regexp.Regexp
	if o.Policy.TeamPattern != "" {
		teamRE = regexp.MustCompile(o.Policy.TeamPattern)
	}
	root := path.Clean(filepath.ToSlash(o.Root))
	seen := map[string]string{}

	for i := range reqs {
		r := &reqs[i]
		oc := &r.Client
		if !IsRequestFile(root, r.File) {
			add(r.File, "requests must live at %s/<team>/<name>.yaml", root)
			continue
		}
		team := path.Base(path.Dir(r.File))
		base := strings.TrimSuffix(path.Base(r.File), path.Ext(r.File))

		if teamRE != nil && !teamRE.MatchString(team) {
			add(r.File, "team directory %q does not match %s", team, o.Policy.TeamPattern)
		}
		if oc.Namespace != team {
			add(r.File, "metadata.namespace %q must be the team directory %q", oc.Namespace, team)
		}
		if oc.Name != base {
			add(r.File, "metadata.name %q must match the file name %q", oc.Name, base)
		}
		if v, ok := oc.Labels[ClientLabel]; ok && v != oc.Name {
			add(r.File, "label %s must be %q", ClientLabel, oc.Name)
		}
		key := oc.Namespace + "/" + oc.Name
		if prev, dup := seen[key]; dup {
			add(r.File, "duplicate request %s (also in %s)", key, prev)
		} else {
			seen[key] = r.File
		}

		if err := CheckClient(oc); err != nil {
			for line := range strings.SplitSeq(err.Error(), "\n") {
				add(r.File, "%s", line)
			}
		}
		for _, raw := range oc.Spec.RedirectURIs {
			if u, err := url.Parse(raw); err == nil && u.Host != "" && !o.Policy.redirectHostAllowed(u.Hostname()) {
				add(r.File, "redirect URI host %q is not in allowedRedirectHosts", u.Hostname())
			}
		}
		if o.EnforceApprovals && slices.Contains(o.Changed, r.File) {
			for _, label := range missingApprovals(oc, o) {
				add(r.File, "needs the %q label on the pull request (grant requires approval)", label)
			}
		}
	}
	return out
}

func requiredApprovals(oc *courierv1alpha1.OAuthClient, p Policy) []string {
	var labels []string
	for _, g := range oc.Spec.GrantTypes {
		if label := p.GrantApprovals[g]; label != "" && !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
	}
	return labels
}

func missingApprovals(oc *courierv1alpha1.OAuthClient, o Options) []string {
	var missing []string
	for _, label := range requiredApprovals(oc, o.Policy) {
		if !slices.Contains(o.Labels, label) {
			missing = append(missing, label)
		}
	}
	return missing
}

// RequestFiles keeps only request files from a list of changed paths.
func RequestFiles(root string, files []string) []string {
	var out []string
	for _, f := range files {
		f = path.Clean(filepath.ToSlash(strings.TrimSpace(f)))
		if IsRequestFile(root, f) && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	slices.Sort(out)
	return out
}

// Summary renders a Markdown overview of the changed requests for reviewers.
func Summary(reqs []Request, o Options, findings []Finding, vaultMount string) string {
	var b strings.Builder
	b.WriteString("## Courier client requests\n\n")

	byFile := map[string][]*Request{}
	for i := range reqs {
		byFile[reqs[i].File] = append(byFile[reqs[i].File], &reqs[i])
	}

	if len(o.Changed) == 0 {
		b.WriteString("No request files changed.\n")
	} else {
		b.WriteString("| Change | Team | Client | Type | Grants | Credentials path | Approval |\n")
		b.WriteString("|---|---|---|---|---|---|---|\n")
		for _, f := range o.Changed {
			rs, ok := byFile[f]
			if !ok {
				fmt.Fprintf(&b, "| **removed** | %s | `%s` | | | | client and credentials are deleted on merge |\n",
					path.Base(path.Dir(f)), strings.TrimSuffix(path.Base(f), path.Ext(f)))
				continue
			}
			for _, r := range rs {
				oc := &r.Client
				spec := ToClientSpec(oc)
				fmt.Fprintf(&b, "| added or changed | %s | `%s` | %s | %s | `%s/teams/%s/oauth-clients/%s` | %s |\n",
					oc.Namespace, oc.Name, oc.Spec.ClientType, strings.Join(oc.Spec.GrantTypes, ", "),
					vaultMount, spec.OwnerGroup, spec.Name, approvalCell(oc, o))
			}
		}
	}

	if len(findings) == 0 {
		b.WriteString("\n**All checks passed.**\n")
		return b.String()
	}
	b.WriteString("\n### Problems\n\n")
	for _, f := range findings {
		fmt.Fprintf(&b, "- `%s`: %s\n", f.File, f.Message)
	}
	return b.String()
}

type catalogEntity struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string            `json:"name"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Type  string `json:"type"`
		Owner string `json:"owner"`
	} `json:"spec"`
}

// CheckCatalog validates the optional Backstage entity files
// (<root>/<team>/<name>.catalog.yml) against the requests they describe, so a
// catalog entry can never claim another team's client or show its status.
func CheckCatalog(root string, reqs []Request) ([]Finding, error) {
	byKey := map[string]*courierv1alpha1.OAuthClient{}
	for i := range reqs {
		oc := &reqs[i].Client
		byKey[oc.Namespace+"/"+oc.Name] = oc
	}
	files, err := filepath.Glob(filepath.Join(root, "*", "*"+catalogSuffix))
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, f := range files {
		file := filepath.ToSlash(f)
		team := path.Base(path.Dir(file))
		base := strings.TrimSuffix(path.Base(file), catalogSuffix)
		add := func(format string, args ...any) {
			out = append(out, Finding{file, fmt.Sprintf(format, args...)})
		}

		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var e catalogEntity
		if err := yaml.Unmarshal(raw, &e); err != nil {
			add("not valid YAML: %v", err)
			continue
		}
		oc, ok := byKey[team+"/"+base]
		if !ok {
			add("no request %s/%s.yaml for this catalog entry", team, base)
			continue
		}
		if e.APIVersion != "backstage.io/v1alpha1" || e.Kind != "Resource" {
			add("must be a backstage.io/v1alpha1 Resource")
		}
		if want := team + "-" + base; e.Metadata.Name != want {
			add("metadata.name %q must be %q", e.Metadata.Name, want)
		}
		if e.Spec.Type != "oauth-client" {
			add("spec.type %q must be oauth-client", e.Spec.Type)
		}
		if e.Spec.Owner != "group:"+team && e.Spec.Owner != "group:default/"+team {
			add("spec.owner %q must be group:default/%s", e.Spec.Owner, team)
		}
		if v := e.Metadata.Annotations["backstage.io/kubernetes-namespace"]; v != team {
			add("annotation backstage.io/kubernetes-namespace %q must be %q", v, team)
		}
		if v, want := e.Metadata.Annotations["backstage.io/kubernetes-label-selector"], ClientLabel+"="+base; v != want {
			add("annotation backstage.io/kubernetes-label-selector %q must be %q", v, want)
		}
		if oc.Labels[ClientLabel] != base {
			add("request %s/%s.yaml must carry label %s: %s for this entry to find it", team, base, ClientLabel, base)
		}
	}
	return out, nil
}

func approvalCell(oc *courierv1alpha1.OAuthClient, o Options) string {
	required := requiredApprovals(oc, o.Policy)
	if len(required) == 0 {
		return "not required"
	}
	if missing := missingApprovals(oc, o); len(missing) > 0 {
		return "needs label `" + strings.Join(missing, "`, `") + "`"
	}
	return "approved (`" + strings.Join(required, "`, `") + "`)"
}
