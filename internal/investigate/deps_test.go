package investigate_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
)

// The investigator stays stdlib: no SDK, no client library, only
// kubesentry's stdlib packages (CLAUDE.md, docs/contracts.md).
func TestImportsStayStdlib(t *testing.T) {
	allowed := map[string]bool{
		"github.com/ByronGary/kubesentry/internal/incidents":   true,
		"github.com/ByronGary/kubesentry/internal/audit":       true,
		"github.com/ByronGary/kubesentry/internal/model":       true,
		"github.com/ByronGary/kubesentry/internal/investigate": true,
	}
	for _, dir := range []string{".", "investigatetest"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range parsed.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") && !allowed[p] {
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
	}
}

// incidents.Runner is the IncidentSource as it is: cmd/server adds only
// the workload state.
var _ investigate.IncidentSource = (*incidents.Runner)(nil)
