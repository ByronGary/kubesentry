package audit_test

import (
	"context"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/audit/audittest"
)

// The memory store's indexed tag counts equal the reference built from
// plain queries, for random events and tag queries.
func TestCountTagsEqualsReference(t *testing.T) {
	ctx := context.Background()
	for seed := int64(1); seed <= 5; seed++ {
		rng := rand.New(rand.NewSource(seed))
		mem := audit.NewMemoryStore(1 << 20)
		mem.Add(audittest.Events(rng, 1500, span)...)
		st := mem.AsStore()
		if _, ok := st.(audit.TagCounter); !ok {
			t.Fatal("the memory store is not a TagCounter")
		}
		for i := 0; i < 200; i++ {
			q := audittest.TagQuery(rng, span)
			want, err := audit.CountTagsByQuery(ctx, st, q)
			if err != nil {
				t.Fatal(err)
			}
			got, err := audit.CountTags(ctx, st, q)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("seed %d query %d %+v:\n got %+v\nwant %+v", seed, i, q, got, want)
			}
		}
	}
}

func TestCountTags(t *testing.T) {
	base := audittest.Base
	mem := audit.NewMemoryStore(100)
	add := func(id string, ago time.Duration, user, ns string, tags ...string) {
		kind := audit.ClassifyActor(user, audit.DefaultSystemPrefixes)
		mem.Add(audit.Event{AuditID: id, Time: base.Add(-ago), Verb: "create", Username: user, ActorKind: kind, Namespace: ns, Tags: tags})
	}
	add("1", time.Minute, "alice", "prod", audit.TagExec)
	add("2", 2*time.Minute, "alice", "staging", audit.TagExec)
	add("3", 3*time.Minute, "system:serviceaccount:ci:deployer", "prod", audit.TagSecretAccess)
	add("4", 4*time.Minute, "system:kube-scheduler", "prod", audit.TagDenied)
	add("5", 25*time.Hour, "bob", "prod", audit.TagExec)                     // too old
	add("6", 5*time.Minute, "bob", "", audit.TagRBACChange, audit.TagDenied) // cluster-scoped
	add("7", 6*time.Minute, "carol", "team-b", audit.TagExec)                // out of scope

	got := mem.CountTags(audit.TagCountQuery{
		Since:      base.Add(-24 * time.Hour),
		Tags:       []string{audit.TagExec, audit.TagSecretAccess, audit.TagRBACChange, audit.TagDenied},
		Actors:     map[string]bool{"user": true, "serviceaccount": true},
		Namespaces: map[string]bool{"prod": true, "staging": true}, ClusterScoped: true,
		Subset: map[string]bool{"prod": true},
		Latest: 2, LatestTags: []string{audit.TagExec, audit.TagRBACChange},
	})
	wantBy := map[string]int{audit.TagExec: 2, audit.TagSecretAccess: 1, audit.TagRBACChange: 1, audit.TagDenied: 1}
	wantSub := map[string]int{audit.TagExec: 1, audit.TagSecretAccess: 1, audit.TagRBACChange: 0, audit.TagDenied: 0}
	if !reflect.DeepEqual(got.ByTag, wantBy) || !reflect.DeepEqual(got.Subset, wantSub) {
		t.Errorf("counts = %v, subset %v", got.ByTag, got.Subset)
	}
	if len(got.Latest) != 2 || got.Latest[0].AuditID != "1" || got.Latest[1].AuditID != "2" {
		t.Errorf("latest = %+v", got.Latest)
	}
	// Nothing in scope: zeros for every tag, never nil maps.
	none := mem.CountTags(audit.TagCountQuery{Tags: []string{audit.TagExec}, Namespaces: map[string]bool{}, Latest: 5})
	if none.ByTag[audit.TagExec] != 0 || none.Subset == nil || none.Latest == nil || len(none.Latest) != 0 {
		t.Errorf("empty scope = %+v", none)
	}
}
