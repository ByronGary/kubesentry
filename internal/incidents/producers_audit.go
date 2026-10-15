package incidents

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// CheckpointAudit is the audit poller's checkpoint name.
const CheckpointAudit = "incidents/audit"

// writeVerbs change objects.
var writeVerbs = map[string]bool{"create": true, "update": true, "patch": true, "delete": true, "deletecollection": true}

// resourceKinds maps the audited resources incidents follow to their kinds.
var resourceKinds = map[string]string{
	"deployments": "Deployment", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet", "jobs": "Job", "cronjobs": "CronJob",
	"replicasets": "ReplicaSet", "pods": "Pod", "services": "Service", "horizontalpodautoscalers": "HorizontalPodAutoscaler",
	"nodes": "Node",
	// Namespace-level objects: a change attaches to every incident in the namespace.
	"configmaps": "ConfigMap", "secrets": "Secret", "rolebindings": "RoleBinding", "roles": "Role", "serviceaccounts": "ServiceAccount",
	"networkpolicies": "NetworkPolicy", "ingresses": "Ingress", "persistentvolumeclaims": "PersistentVolumeClaim",
	"resourcequotas": "ResourceQuota", "limitranges": "LimitRange", "poddisruptionbudgets": "PodDisruptionBudget",
}

var namespaceLevel = map[string]bool{
	"configmaps": true, "secrets": true, "rolebindings": true, "roles": true, "serviceaccounts": true, "networkpolicies": true,
	"ingresses": true, "persistentvolumeclaims": true, "resourcequotas": true, "limitranges": true, "poddisruptionbudgets": true,
}

// AuditPoll reads the writes people made (audit actor kind "user") since a
// checkpoint and turns them into audit-change context: on a workload, its
// pods or Services for that root; on a namespace-level object (ConfigMap,
// Secret, RoleBinding, ...) for every incident in the namespace; on a Node
// for the node. It re-reads an overlap each time (audit events can be
// stored a little late) and drops what it already saw; a new leadership
// term re-reads the lookbehind once, so context waiting for an incident
// survives a failover (signal IDs are stable, so nothing doubles).
type AuditPoll struct {
	store audit.Store
	o     Options

	since time.Time
	seen  map[string]time.Time // audit ID → event time, within the overlap
}

// auditOverlap is re-read every poll; auditMaxLag is the most an event is
// expected to arrive late.
const (
	auditOverlap = 5 * time.Minute
	auditMaxLag  = 10 * time.Minute
	auditPage    = 1000
	auditPages   = 10
)

type auditCheckpoint struct {
	Time time.Time `json:"time"`
}

// NewAuditPoll returns a poller starting from checkpoint (nil: the
// lookbehind before now).
func NewAuditPoll(store audit.Store, o Options, checkpoint []byte, now time.Time) *AuditPoll {
	o.defaults()
	p := &AuditPoll{store: store, o: o, seen: map[string]time.Time{}}
	p.since = now.Add(-o.Lookbehind)
	var cp auditCheckpoint
	if len(checkpoint) > 0 && json.Unmarshal(checkpoint, &cp) == nil && !cp.Time.IsZero() {
		p.since = cp.Time.Add(-o.Lookbehind)
	}
	if floor := now.Add(-o.MaxRange); p.since.Before(floor) {
		p.since = floor
	}
	return p
}

// Poll returns the signals of new writes and the checkpoint to commit.
// Without a view nothing can be placed, so it reads nothing.
func (p *AuditPoll) Poll(ctx context.Context, v *snapshot.View, now time.Time) ([]Signal, []byte, error) {
	if v == nil {
		return nil, nil, nil
	}
	from := p.since.Add(-auditOverlap)
	q := audit.Query{Since: from, Actors: map[string]bool{"user": true}, Limit: auditPage}
	var evs []audit.Event
	for page := 0; page < auditPages; page++ {
		got, err := p.store.Query(ctx, q)
		if err != nil {
			return nil, nil, fmt.Errorf("incidents: audit poll: %w", err)
		}
		evs = append(evs, got...)
		if len(got) < auditPage {
			break
		}
		last := got[len(got)-1]
		q.Before = audit.Cursor{Time: last.Time, AuditID: last.AuditID}
	}
	newest := p.since
	var out []Signal
	for i := len(evs) - 1; i >= 0; i-- { // oldest first
		e := &evs[i]
		if e.Time.After(newest) {
			newest = e.Time
		}
		if _, dup := p.seen[e.AuditID]; dup {
			continue
		}
		p.seen[e.AuditID] = e.Time
		out = append(out, AuditSignals(v, e)...)
	}
	if floor := now.Add(-auditMaxLag); newest.Before(floor) {
		newest = floor
	}
	p.since = newest
	for id, t := range p.seen {
		if t.Before(p.since.Add(-auditOverlap)) {
			delete(p.seen, id)
		}
	}
	cp, _ := json.Marshal(auditCheckpoint{Time: newest.UTC()})
	return out, cp, nil
}

// AuditSignals maps one audit event to audit-change signals: none for
// reads, failures, people's writes to objects incidents do not follow, and
// system actors.
func AuditSignals(v *snapshot.View, e *audit.Event) []Signal {
	if !writeVerbs[e.Verb] || e.ActorKind != "user" || e.StatusCode >= 400 || e.Decision == "forbid" {
		return nil
	}
	kind, ok := resourceKinds[e.Resource]
	if !ok || (e.Name == "" && e.Verb != "deletecollection") {
		return nil
	}
	var subjects []Subject
	switch {
	case namespaceLevel[e.Resource]:
		if e.Namespace != "" {
			subjects = []Subject{{Kind: KindNamespace, Name: e.Namespace}}
		}
	case e.Resource == "nodes":
		subjects = []Subject{{Kind: KindNode, Name: e.Name}}
	case e.Resource == "pods":
		if s, ok := SubjectOfPod(v, e.Namespace, e.Name); ok {
			subjects = []Subject{s}
		}
	case e.Resource == "services":
		subjects = SubjectsOfService(v, e.Namespace, e.Name)
	case e.Resource == "horizontalpodautoscalers":
		for _, w := range indexOf(v).byName[[2]string{e.Namespace, e.Name}] {
			if w.Kind == "Deployment" || w.Kind == "StatefulSet" {
				subjects = append(subjects, Subject{Kind: w.Kind, Namespace: e.Namespace, Name: w.Name})
			}
		}
	default:
		if s, ok := SubjectOfWorkload(v, kind, e.Namespace, e.Name); ok || kind != "ReplicaSet" {
			subjects = []Subject{s}
		}
	}
	if len(subjects) == 0 {
		return nil
	}
	what := e.Resource
	if e.Subresource != "" {
		what += "/" + e.Subresource
	}
	obj := e.Name
	if e.Namespace != "" {
		obj = e.Namespace + "/" + e.Name
	}
	title := fmt.Sprintf("%s %s %s %s", e.Username, pastTense(e.Verb, e.Subresource), what, obj)
	attrs := map[string]string{"user": e.Username, "verb": e.Verb, "resource": e.Resource, "auditID": e.AuditID,
		"statusCode": strconv.Itoa(e.StatusCode)}
	if e.Subresource != "" {
		attrs["subresource"] = e.Subresource
	}
	if e.APIGroup != "" {
		attrs["apiGroup"] = e.APIGroup
	}
	if e.UserAgent != "" {
		attrs["userAgent"] = e.UserAgent
	}
	if len(e.SourceIPs) > 0 {
		attrs["sourceIP"] = e.SourceIPs[0]
	}
	if e.ARN != "" {
		attrs["arn"] = e.ARN
	}
	out := make([]Signal, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, Signal{ID: "audit:" + e.AuditID, Type: TypeAuditChange, Source: SourceAudit, Role: Context, Start: e.Time,
			Subject: s, Object: model.ObjectRef{Kind: kind, Namespace: e.Namespace, Name: e.Name}, Title: title, Attrs: attrs})
	}
	return out
}

func pastTense(verb, sub string) string {
	if sub == "exec" || sub == "attach" || sub == "portforward" {
		return "opened"
	}
	switch verb {
	case "create":
		return "created"
	case "update":
		return "updated"
	case "patch":
		return "patched"
	case "delete", "deletecollection":
		return "deleted"
	}
	return strings.TrimSuffix(verb, "e") + "ed"
}
