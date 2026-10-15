package incidents

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// CheckpointCloudTrail is the CloudTrail poller's checkpoint name.
const CheckpointCloudTrail = "incidents/cloudtrail"

// CloudTrailPoll reads write events from a CloudTrailSource after a
// checkpoint and keeps those that touch a related resource (RelatedIndex):
// cloudtrail-change context for each subject they concern, or cluster-wide
// context for changes to the EKS cluster, its node groups and add-ons.
// Failed calls change nothing and are skipped. Events are de-duplicated by
// ID (lookup sources re-read an overlap).
type CloudTrailPoll struct {
	src CloudTrailSource
	o   Options
	red *Redactor

	since time.Time
	cp    []byte
	seen  map[string]time.Time // event ID → event time
}

// NewCloudTrailPoll returns a poller resuming from checkpoint, or reading
// CloudTrailStart back when there is none.
func NewCloudTrailPoll(src CloudTrailSource, o Options, red *Redactor, checkpoint []byte, now time.Time) *CloudTrailPoll {
	o.defaults()
	return &CloudTrailPoll{src: src, o: o, red: red, since: now.Add(-o.CloudTrailStart), cp: slices.Clone(checkpoint), seen: map[string]time.Time{}}
}

// Poll returns the signals of new changes, the source's new checkpoint,
// and how many events it read and kept.
// Without a view nothing can be matched, so it reads nothing.
func (p *CloudTrailPoll) Poll(ctx context.Context, v *snapshot.View, now time.Time) (sigs []Signal, cp []byte, read, kept int, err error) {
	if v == nil {
		return nil, nil, 0, 0, nil
	}
	evs, cp, err := p.src.Changes(ctx, p.since, p.cp)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("incidents: cloudtrail %s: %w", p.src.Name(), err)
	}
	if len(cp) > 0 {
		p.cp = slices.Clone(cp)
	}
	idx := RelatedIndexOf(v, p.o.Cluster)
	for i := range evs {
		e := &evs[i]
		read++
		if e.ID == "" || e.ReadOnly || e.ErrorCode != "" {
			continue
		}
		if _, dup := p.seen[e.ID]; dup {
			continue
		}
		p.seen[e.ID] = e.Time
		out := CloudTrailSignals(idx, e, p.red)
		if len(out) > 0 {
			kept++
			sigs = append(sigs, out...)
		}
	}
	cut := now.Add(-2 * time.Hour)
	for id, t := range p.seen {
		if t.Before(cut) {
			delete(p.seen, id)
		}
	}
	return sigs, cp, read, kept, nil
}

// CloudTrailSignals maps one write event to its signals through the index.
func CloudTrailSignals(idx *RelatedIndex, e *CloudTrailEvent, red *Redactor) []Signal {
	subjects, matched, cluster := idx.Match(e)
	if len(subjects) == 0 && !cluster {
		return nil
	}
	if cluster {
		subjects = append(subjects, Subject{Kind: KindCluster, Name: idx.cluster})
	}
	objName := ""
	if len(matched) > 0 {
		_, objName, _ = strings.Cut(matched[0], ":")
	}
	actor := e.Actor
	if i := strings.LastIndexByte(actor, '/'); i >= 0 && i < len(actor)-1 {
		actor = actor[i+1:]
	}
	service := strings.TrimSuffix(e.Source, ".amazonaws.com")
	title := fmt.Sprintf("%s called %s:%s", actor, service, e.Name)
	if objName != "" {
		title += " on " + objName
	}
	attrs := map[string]string{"eventName": e.Name, "eventSource": e.Source, "actor": e.Actor, "eventID": e.ID,
		"matched": strings.Join(matched, ","), "resources": strings.Join(e.Resources, ",")}
	if e.Region != "" {
		attrs["region"] = e.Region
	}
	if e.Raw != "" {
		attrs["raw"] = red.String(e.Raw)
	}
	kind := "AWS::" + awsService(e.Source)
	out := make([]Signal, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, Signal{ID: "cloudtrail:" + e.ID, Type: TypeCloudTrailChange, Source: SourceCloudTrail, Role: Context,
			Start: e.Time, Subject: s, Object: model.ObjectRef{Kind: kind, Name: objName}, Title: red.String(title), Attrs: red.Map(attrs)})
	}
	return out
}

// awsService names a service the way CloudFormation types do, from an event
// source (ec2.amazonaws.com → EC2).
func awsService(source string) string {
	s := strings.TrimSuffix(source, ".amazonaws.com")
	switch s {
	case "elasticloadbalancing":
		return "ElasticLoadBalancingV2"
	case "eks", "ec2", "iam", "sts", "s3", "rds", "kms":
		return strings.ToUpper(s)
	case "autoscaling":
		return "AutoScaling"
	}
	if s == "" {
		return "Unknown"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
