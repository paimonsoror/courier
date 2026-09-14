// Command courier is the Courier CLI.
//
//	courier validate [flags] [requests-dir]
//
// validate checks a request repository with the same rules the controller
// enforces, plus repository policy (layout, redirect hosts, approval labels).
// In GitHub Actions it emits file annotations.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/paimonsoror/courier/internal/request"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "validate" {
		_, _ = fmt.Fprintln(stderr, "usage: courier validate [flags] [requests-dir]")
		return 2
	}

	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyFile := fs.String("policy", "", "policy file (default: <requests-dir>/.policy.yaml when present)")
	labels := fs.String("labels", "", "comma-separated pull request labels")
	changed := fs.String("changed", "", "comma-separated files changed by the pull request")
	enforce := fs.Bool("enforce-approvals", false, "require policy approval labels on changed requests")
	summaryFile := fs.String("summary", "", "append a Markdown summary of changed requests to this file")
	mount := fs.String("vault-kv-mount", "kv", "KV v2 mount shown in the summary")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	root := "requests"
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}

	if *policyFile == "" {
		if _, err := os.Stat(filepath.Join(root, ".policy.yaml")); err == nil {
			*policyFile = filepath.Join(root, ".policy.yaml")
		}
	}
	policy, err := request.LoadPolicy(*policyFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "policy:", err)
		return 2
	}

	reqs, findings, err := request.Load(root)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "load:", err)
		return 2
	}
	opts := request.Options{
		Root:             root,
		Policy:           policy,
		Changed:          request.RequestFiles(root, splitList(*changed)),
		EnforceApprovals: *enforce,
		Labels:           splitList(*labels),
	}
	findings = append(findings, request.Check(reqs, opts)...)
	catalogFindings, err := request.CheckCatalog(root, reqs)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "catalog:", err)
		return 2
	}
	findings = append(findings, catalogFindings...)

	if *summaryFile != "" {
		if err := appendFile(*summaryFile, request.Summary(reqs, opts, findings, *mount)); err != nil {
			_, _ = fmt.Fprintln(stderr, "summary:", err)
			return 2
		}
	}

	annotate := os.Getenv("GITHUB_ACTIONS") == "true"
	for _, f := range findings {
		if annotate {
			_, _ = fmt.Fprintf(stdout, "::error file=%s::%s\n", f.File, escapeAnnotation(f.Message))
		} else {
			_, _ = fmt.Fprintln(stdout, f)
		}
	}
	if len(findings) > 0 {
		_, _ = fmt.Fprintf(stdout, "%d problem(s) found\n", len(findings))
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%d request(s) valid\n", len(reqs))
	return 0
}

func splitList(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func appendFile(name, text string) error {
	f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// escapeAnnotation follows GitHub's workflow command encoding.
func escapeAnnotation(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}
