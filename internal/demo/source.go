package demo

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

// link fills in what a real cluster derives from the objects above, so the
// demo exercises the same association as a live one: container and readiness
// state, workload UIDs, ownerReferences through ReplicaSets (and Jobs to
// their CronJobs), and the EndpointSlices behind each Service.
func (c *Cluster) link(now time.Time) {
	c.info = model.ClusterInfo{Name: "shop-prod", Version: "v1.34.2-eks-b3126f4", Platform: "eks", Provider: "aws", Region: "us-east-1"}

	for i := range c.workloads {
		w := &c.workloads[i]
		w.UID = uidOf(w.Kind + "/" + w.Namespace + "/" + w.Name)
	}
	for i := range c.workloads {
		if w := &c.workloads[i]; w.Kind == "Job" {
			if cj, ok := c.workload("CronJob", w.Namespace, cronJobName(w.Name)); ok {
				w.Owners = []model.OwnerRef{{Kind: "CronJob", Name: cj.Name, UID: cj.UID, Controller: true}}
			}
		}
	}

	rsSeen := map[string]bool{}
	for i := range c.pods {
		p := &c.pods[i]
		settle(p, i)
		w, ok := c.ownerByLabels(p)
		if !ok {
			continue
		}
		if w.Kind != "Deployment" {
			p.Owners = []model.OwnerRef{{Kind: w.Kind, Name: w.Name, UID: w.UID, Controller: true}}
			continue
		}
		rsName := w.Name + "-" + p.Labels["pod-template-hash"]
		rsUID := uidOf("ReplicaSet/" + p.Namespace + "/" + rsName)
		p.Owners = []model.OwnerRef{{Kind: "ReplicaSet", Name: rsName, UID: rsUID, Controller: true}}
		if !rsSeen[p.Namespace+"/"+rsName] {
			rsSeen[p.Namespace+"/"+rsName] = true
			rs := model.ReplicaSet{Namespace: p.Namespace, Name: rsName, UID: rsUID, Created: p.Created,
				Owners: []model.OwnerRef{{Kind: "Deployment", Name: w.Name, UID: w.UID, Controller: true}}}
			c.replicaSets = append(c.replicaSets, rs)
		}
	}
	// A ReplicaSet's desired and ready counts are its live, ready pods; the
	// old one of a finished rollout (or one scaling down) wants none.
	for i := range c.replicaSets {
		rs := &c.replicaSets[i]
		old := false
		for _, p := range c.pods {
			if len(p.Owners) == 0 || p.Owners[0].Name != rs.Name || p.Namespace != rs.Namespace {
				continue
			}
			if !p.DeletedAt.IsZero() {
				old = true
			}
			if p.Phase == "Running" && p.Ready && p.DeletedAt.IsZero() {
				rs.Ready++
			}
			if p.Phase != "Succeeded" && p.Phase != "Failed" && p.DeletedAt.IsZero() {
				rs.Desired++
			}
		}
		if old {
			rs.Desired = 0
		}
	}

	c.slices = nil
	for _, svc := range c.services {
		es := model.EndpointSlice{Namespace: svc.Namespace, Name: svc.Name + "-" + hexOf(svc.Namespace + "/" + svc.Name)[:5],
			Service: svc.Name, ManagedBy: "endpointslice-controller.k8s.io", Endpoints: []model.Endpoint{}}
		for _, p := range c.pods {
			if p.Namespace != svc.Namespace || p.PodIP == "" || p.Phase != "Running" || !matches(svc.Selector, p.Labels) {
				continue
			}
			terminating := !p.DeletedAt.IsZero()
			es.Endpoints = append(es.Endpoints, model.Endpoint{
				Addresses: []string{p.PodIP}, Ready: p.Ready && !terminating, Serving: p.Ready || terminating, Terminating: terminating,
				NodeName: p.NodeName, TargetKind: "Pod", TargetName: p.Name, TargetUID: p.UID,
			})
		}
		c.slices = append(c.slices, es)
	}
}

// settle gives a pod the container states, readiness and address its phase
// implies, keeping whatever the story set explicitly.
func settle(p *model.Pod, i int) {
	p.QOSClass = "Burstable"
	ready := p.Phase == "Running"
	for j := range p.Containers {
		ct := &p.Containers[j]
		if ct.State == "" {
			switch p.Phase {
			case "Running":
				ct.State, ct.Ready, ct.Started = "running", true, true
			case "Succeeded":
				ct.State, ct.Reason = "terminated", "Completed"
			case "Failed":
				ct.State, ct.Reason = "terminated", "Error"
			}
		}
		if !ct.Init && !ct.Ready {
			ready = false
		}
	}
	if !p.DeletedAt.IsZero() {
		ready = false // the kubelet marks a terminating pod not ready
	}
	p.Ready = ready
	p.ReadyChanged = p.Created
	for _, ct := range p.Containers {
		if ct.LastTerminatedAt.After(p.ReadyChanged) {
			p.ReadyChanged = ct.LastTerminatedAt
		}
	}
	if p.Phase == "Running" && p.NodeName != "" {
		p.PodIP = fmt.Sprintf("10.0.%d.%d", 100+i/200, 10+i%200)
	}
}

func matches(sel map[string]string, l map[string]string) bool {
	if len(sel) == 0 {
		return false
	}
	return detectors.MatchSelector(&model.LabelSelector{MatchLabels: sel}, l)
}

// ownerByLabels finds the controller that created a pod: the workload of its
// namespace whose selector matches it, Jobs and controllers alike.
func (c *Cluster) ownerByLabels(p *model.Pod) (*model.Workload, bool) {
	for i := range c.workloads {
		w := &c.workloads[i]
		if w.Namespace == p.Namespace && w.Kind != "CronJob" && w.Selector != nil && detectors.MatchSelector(w.Selector, p.Labels) {
			return w, true
		}
	}
	return nil, false
}

func (c *Cluster) workload(kind, ns, name string) (*model.Workload, bool) {
	for i := range c.workloads {
		if w := &c.workloads[i]; w.Kind == kind && w.Namespace == ns && w.Name == name {
			return w, true
		}
	}
	return nil, false
}

// cronJobName is the CronJob a Job named <cronjob>-<minutes> came from.
func cronJobName(job string) string {
	if i := strings.LastIndexByte(job, '-'); i > 0 && strings.Trim(job[i+1:], "0123456789") == "" {
		return job[:i]
	}
	return ""
}

// Inventory implements snapshot.Source: one consistent read of everything,
// like the informer cache's. Slices are copies; the shared demo data is
// never handed out for modification.
func (c *Cluster) Inventory(ctx context.Context) (model.Inventory, error) {
	if err := ctx.Err(); err != nil {
		return model.Inventory{}, err
	}
	rbac := model.RBAC{Roles: clone(c.rbac.Roles), Bindings: clone(c.rbac.Bindings)}
	certs := c.certs
	certs.Certificates, certs.Issuers, certs.Requests = clone(c.certs.Certificates), clone(c.certs.Issuers), clone(c.certs.Requests)
	return model.Inventory{
		Pods: clone(c.pods), PVCs: clone(c.pvcs), PVs: clone(c.pvs), StorageClasses: clone(c.classes),
		Workloads: clone(c.workloads), ReplicaSets: clone(c.replicaSets), Services: clone(c.services),
		EndpointSlices: clone(c.slices), Ingresses: clone(c.ingresses), Nodes: clone(c.nodes),
		Namespaces: clone(c.namespaces), RBAC: rbac, Certs: certs, Cluster: c.info,
		Unavailable: map[string]string{}, ReadAt: time.Now(),
	}, nil
}

func clone[T any](s []T) []T { return append([]T(nil), s...) }

// ListReplicaSets and ListEndpointSlices complete the list interfaces, so
// the demo also works through snapshot.FromLists.
func (c *Cluster) ListReplicaSets(context.Context) ([]model.ReplicaSet, error) {
	return clone(c.replicaSets), nil
}

func (c *Cluster) ListEndpointSlices(context.Context) ([]model.EndpointSlice, error) {
	out := clone(c.slices)
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace+"/"+out[i].Name < out[j].Namespace+"/"+out[j].Name })
	return out, nil
}
