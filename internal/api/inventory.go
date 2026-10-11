package api

import (
	"context"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

// InventorySource lists the objects behind the Map, Workloads, Storage and
// Security pages. It is optional: when nil, those routes do not exist.
type InventorySource interface {
	ListWorkloads(ctx context.Context) ([]model.Workload, error)
	ListServices(ctx context.Context) ([]model.Service, error)
	ListIngresses(ctx context.Context) ([]model.Ingress, error)
	ListNodes(ctx context.Context) ([]model.Node, error)
	ListPVs(ctx context.Context) ([]model.PV, error)
	ListStorageClasses(ctx context.Context) ([]model.StorageClass, error)
	ListNamespaces(ctx context.Context) ([]model.Namespace, error)
	ListRBAC(ctx context.Context) (model.RBAC, error)
}

// CertSource reads cert-manager objects. It is optional: when nil, the
// certificates route does not exist. When cert-manager is not installed it
// returns CertManager{Installed: false} and no error.
type CertSource interface {
	CertManager(ctx context.Context) (model.CertManager, error)
}

// Response shapes. Mirrored in web/src/types.ts.

// GET /api/v1/workloads[?namespace=&limit=&continue=]
type workloadsResponse struct {
	Count    int                         `json:"count"`
	Items    []detectors.WorkloadSummary `json:"items"`
	Continue string                      `json:"continue,omitempty"`
}

// GET /api/v1/storage[?limit=&continue=]
type storageResponse struct {
	Claims               []detectors.ClaimSummary  `json:"claims"`
	Volumes              []detectors.VolumeSummary `json:"volumes"`
	Classes              []detectors.ClassSummary  `json:"classes"`
	Unused               []detectors.UnusedPVC     `json:"unused"` // same rules as /api/v1/pvcs/unused
	UnusedMonthlyCostUSD float64                   `json:"unusedMonthlyCostUSD"`
	Continue             string                    `json:"continue,omitempty"` // pages claims
}

// GET /api/v1/security[?view=summary][?limit=&continue=]
type securityResponse struct {
	// Counts by severity, excluding System findings.
	Counts     map[string]int               `json:"counts"`
	Findings   []detectors.SecurityFinding  `json:"findings"`
	Namespaces []detectors.NamespacePosture `json:"namespaces"`
	Warnings   []string                     `json:"warnings,omitempty"` // a source that could not be read, e.g. RBAC forbidden
	Continue   string                       `json:"continue,omitempty"` // pages findings
}

// GET /api/v1/certificates
type certificatesResponse struct {
	Installed    bool                       `json:"installed"`
	Certificates []detectors.CertSummary    `json:"certificates"`
	Issuers      []detectors.IssuerSummary  `json:"issuers"`
	Requests     []detectors.RequestSummary `json:"requests"`
}

// GET /api/v1/map[?namespace=]. Without a namespace the server picks the
// caller's non-system namespace with the most live pods.
type mapResponse struct {
	Namespace  string          `json:"namespace"`
	Namespaces []string        `json:"namespaces"` // every namespace with pods, for the picker
	Graph      detectors.Graph `json:"graph"`
	// NamespaceStats has the live pods of each namespace in Namespaces, for
	// choosing a default.
	NamespaceStats []namespaceStat `json:"namespaceStats"`
}

type namespaceStat struct {
	Name   string `json:"name"`
	Pods   int    `json:"pods"`
	System bool   `json:"system"`
}

// GET /api/v1/nodes
type nodesResponse struct {
	Count int                     `json:"count"`
	Items []detectors.NodeSummary `json:"items"`
}

// GET /api/v1/nodes?summary=true: nodes without their pods.
type nodesSummaryResponse struct {
	Count int       `json:"count"`
	Items []nodeOut `json:"items"`
}
