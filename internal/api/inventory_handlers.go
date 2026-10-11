package api

import (
	"context"
	"log/slog"
	"net/http"
	"sort"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

// namespaceParam reads the optional ?namespace= filter. ok is false after it
// has answered 400 for an invalid name.
func namespaceParam(w http.ResponseWriter, r *http.Request) (ns string, ok bool) {
	ns = r.URL.Query().Get("namespace")
	if ns != "" && !validName(ns) {
		writeError(w, http.StatusBadRequest, "invalid namespace")
		return "", false
	}
	return ns, true
}

// workloads lists Deployments, StatefulSets, DaemonSets, Jobs and CronJobs,
// most troubled first.
func (s *Server) workloads(w http.ResponseWriter, r *http.Request) {
	ns, ok := namespaceParam(w, r)
	if !ok {
		return
	}
	ws, err := s.Inventory.ListWorkloads(r.Context())
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	pods, err := s.Cluster.ListPods(r.Context())
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	if ns != "" {
		ws = inNamespace(ws, ns, func(w model.Workload) string { return w.Namespace })
		pods = inNamespace(pods, ns, func(p model.Pod) string { return p.Namespace })
	}
	items := detectors.SummarizeWorkloads(ws, pods, s.now())
	writeJSON(w, http.StatusOK, workloadsResponse{Count: len(items), Items: items})
}

func inNamespace[T any](items []T, ns string, nsOf func(T) string) []T {
	var out []T
	for _, it := range items {
		if nsOf(it) == ns {
			out = append(out, it)
		}
	}
	return out
}

// nodes lists cluster nodes with their requested resources and pods.
func (s *Server) nodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.Inventory.ListNodes(r.Context())
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	pods, err := s.Cluster.ListPods(r.Context())
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	ws, err := s.Inventory.ListWorkloads(r.Context())
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	items := detectors.SummarizeNodes(nodes, pods, ws, s.now())
	writeJSON(w, http.StatusOK, nodesResponse{Count: len(items), Items: items})
}

// storage judges claims, volumes and classes, and repeats the unused-PVC list
// so the page needs one request.
func (s *Server) storage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pvcs, err := s.Cluster.ListPVCs(ctx)
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	pods, err := s.Cluster.ListPods(ctx)
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	pvs, err := s.Inventory.ListPVs(ctx)
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	classes, err := s.Inventory.ListStorageClasses(ctx)
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	now := s.now()
	resp := storageResponse{Unused: detectors.FindUnusedPVCs(pvcs, pods, now, s.PVCOptions)}
	resp.Claims, resp.Volumes, resp.Classes = detectors.SummarizeStorage(pvcs, pvs, classes, pods, now)
	for _, u := range resp.Unused {
		resp.UnusedMonthlyCostUSD += u.EstMonthlyCostUSD
	}
	writeJSON(w, http.StatusOK, resp)
}

// security audits pod specs, RBAC, Pod Security labels and exposure. A source
// that cannot be read (RBAC is often forbidden) skips its checks and adds a
// warning instead of failing the page.
func (s *Server) security(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in detectors.SecurityInput
	var warnings []string
	read := func(what string, err error) {
		if err != nil {
			slog.Error("security source failed", "source", what, "err", err)
			warnings = append(warnings, "Could not read "+what+"; those checks were skipped.")
		}
	}
	var err error
	in.Pods, err = s.Cluster.ListPods(ctx)
	read("pods", err)
	in.Workloads, err = s.Inventory.ListWorkloads(ctx)
	read("workloads", err)
	in.Namespaces, err = s.Inventory.ListNamespaces(ctx)
	read("namespaces", err)
	in.RBAC, err = s.Inventory.ListRBAC(ctx)
	read("roles and bindings", err)
	in.Services, err = s.Inventory.ListServices(ctx)
	read("services", err)
	in.Ingresses, err = s.Inventory.ListIngresses(ctx)
	read("ingresses", err)

	findings, posture := detectors.AuditSecurity(in)
	counts := map[string]int{"crit": 0, "warn": 0, "info": 0}
	for _, f := range findings {
		if !f.System {
			counts[f.Severity]++
		}
	}
	writeJSON(w, http.StatusOK, securityResponse{Counts: counts, Findings: findings, Namespaces: posture, Warnings: warnings})
}

// certificates reports cert-manager Certificates, issuers and stuck requests.
func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	cm, err := s.Certs.CertManager(r.Context())
	if err != nil {
		upstreamError(w, "cert-manager", err)
		return
	}
	resp := certificatesResponse{Installed: cm.Installed}
	resp.Certificates, resp.Issuers, resp.Requests = detectors.SummarizeCerts(cm, s.now())
	writeJSON(w, http.StatusOK, resp)
}

// topology maps one namespace. Without ?namespace= it picks the first
// non-system namespace that has pods.
func (s *Server) topology(w http.ResponseWriter, r *http.Request) {
	ns, ok := namespaceParam(w, r)
	if !ok {
		return
	}
	pods, err := s.Cluster.ListPods(r.Context())
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}

	seen := map[string]bool{}
	namespaces := []string{}
	for _, p := range pods {
		if !seen[p.Namespace] {
			seen[p.Namespace] = true
			namespaces = append(namespaces, p.Namespace)
		}
	}
	sort.Strings(namespaces)
	switch {
	case ns != "" && !seen[ns]:
		writeError(w, http.StatusNotFound, "no pods in namespace "+ns)
		return
	case ns == "" && len(namespaces) > 0:
		ns = namespaces[0]
		for _, n := range namespaces {
			if !detectors.SystemNamespaces[n] {
				ns = n
				break
			}
		}
	}

	in, err := s.topologyInput(r.Context(), pods)
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	writeJSON(w, http.StatusOK, mapResponse{Namespace: ns, Namespaces: namespaces, Graph: detectors.BuildTopology(ns, in)})
}

func (s *Server) topologyInput(ctx context.Context, pods []model.Pod) (detectors.TopologyInput, error) {
	in := detectors.TopologyInput{Pods: pods, Now: s.now()}
	var err error
	if in.Workloads, err = s.Inventory.ListWorkloads(ctx); err != nil {
		return in, err
	}
	if in.Services, err = s.Inventory.ListServices(ctx); err != nil {
		return in, err
	}
	if in.Ingresses, err = s.Inventory.ListIngresses(ctx); err != nil {
		return in, err
	}
	if in.Nodes, err = s.Inventory.ListNodes(ctx); err != nil {
		return in, err
	}
	if in.PVCs, err = s.Cluster.ListPVCs(ctx); err != nil {
		return in, err
	}
	in.StorageClasses, err = s.Inventory.ListStorageClasses(ctx)
	return in, err
}
