package agents

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func pods(n int) []*corev1.Pod {
	var out []*corev1.Pod
	for i := 0; i < n; i++ {
		out = append(out, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: fmt.Sprintf("p%d", i), UID: types.UID(fmt.Sprintf("uid-%d", i))},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "sidecar"}}},
		})
	}
	return out
}

func TestReportsHitTheTargetSizeAndNamePods(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 1))
	for _, target := range []int{50 << 10, 150 << 10} {
		body, procs := buildReport(r, "node-a", pods(10), target)
		if len(body) < target || len(body) > target+target/5 {
			t.Errorf("target %d: body %d bytes", target, len(body))
		}
		var rep Report
		if err := json.Unmarshal(body, &rep); err != nil || rep.Node != "node-a" || len(rep.Processes) != procs {
			t.Fatalf("decode: %v node %q procs %d/%d", err, rep.Node, len(rep.Processes), procs)
		}
		uids := map[string]bool{}
		for _, p := range rep.Processes {
			uids[p.PodUID] = true
			if p.PodUID == "" {
				t.Fatal("process without pod UID")
			}
		}
		if len(uids) != 10 {
			t.Errorf("%d pods named, want 10", len(uids))
		}
		if procs > 20000 {
			t.Errorf("%d processes exceed kubesentry's 20,000 cap", procs)
		}
	}
	// A node without pods sends an empty report.
	body, procs := buildReport(r, "empty", nil, 100<<10)
	if procs != 0 || len(body) > 200 {
		t.Errorf("empty node: %d processes, %d bytes", procs, len(body))
	}
}
