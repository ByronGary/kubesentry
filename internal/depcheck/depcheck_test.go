package depcheck

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/ByronGary/kubesentry"

// rule: a module whose packages only the allowed packages (or their
// subtrees, for an entry ending in "/...") may import.
type rule struct {
	module string
	only   []string
	// tests applies the rule to test imports as well.
	tests bool
}

var rules = []rule{
	{module: "github.com/anthropics/anthropic-sdk-go", only: []string{"internal/llm"}, tests: true},
	{module: "github.com/aws/aws-sdk-go-v2", only: []string{"internal/cloudwatch", "internal/awsauth", "internal/aws/...", "internal/llm"}},
	{module: "github.com/aws/smithy-go", only: []string{"internal/cloudwatch", "internal/awsauth", "internal/aws/...", "internal/llm"}},
	{module: "k8s.io/client-go", only: []string{"internal/kube"}},
	{module: "github.com/jackc/pgx", only: []string{"internal/pgstore"}},
}

func (r rule) covers(path string) bool {
	return path == r.module || strings.HasPrefix(path, r.module+"/")
}

func (r rule) allows(pkg string) bool {
	rel := strings.TrimPrefix(strings.TrimPrefix(pkg, module), "/")
	for _, a := range r.only {
		if sub, ok := strings.CutSuffix(a, "/..."); ok {
			if rel == sub || strings.HasPrefix(rel, sub+"/") {
				return true
			}
		} else if rel == a {
			return true
		}
	}
	return false
}

// TestThirdPartyClientsStayIsolated lists every package of the module with
// go list and checks its imports against the rules.
func TestThirdPartyClientsStayIsolated(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command on PATH")
	}
	cmd := exec.Command(gobin, "list", "-f", "{{.ImportPath}}\t{{join .Imports \" \"}}\t{{join .TestImports \" \"}} {{join .XTestImports \" \"}}", module+"/...")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	pkgs := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 3)
		if len(parts) != 3 {
			continue
		}
		pkgs++
		pkg, imports, testImports := parts[0], strings.Fields(parts[1]), strings.Fields(parts[2])
		for _, r := range rules {
			check := func(list []string, kind string) {
				for _, imp := range list {
					if r.covers(imp) && !r.allows(pkg) {
						t.Errorf("%s %s %s: only %s may import %s", pkg, kind, imp, strings.Join(r.only, ", "), r.module)
					}
				}
			}
			check(imports, "imports")
			if r.tests {
				check(testImports, "tests import")
			}
		}
	}
	if pkgs < 20 {
		t.Fatalf("go list found only %d packages:\n%s", pkgs, out)
	}
}

func TestRuleMatching(t *testing.T) {
	aws := rules[1]
	for pkg, want := range map[string]bool{
		module + "/internal/aws/cloudtrail": true, module + "/internal/aws": true, module + "/internal/llm": true,
		module + "/internal/awsauthx": false, module + "/internal/api": false, module + "/cmd/server": false,
	} {
		if aws.allows(pkg) != want {
			t.Errorf("%s allowed = %v", pkg, !want)
		}
	}
	if !rules[0].covers("github.com/anthropics/anthropic-sdk-go/bedrock") || rules[0].covers("github.com/anthropics/anthropic-sdk-go-x") {
		t.Error("module prefix matching")
	}
}
