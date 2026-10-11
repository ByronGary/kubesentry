package snapshot

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

// The list interfaces below have the same method sets as internal/api's
// ClusterSource, InventorySource and CertSource, so the values the API server
// already holds satisfy them without this package importing internal/api.

// ClusterLister lists pods and claims.
type ClusterLister interface {
	ListPVCs(ctx context.Context) ([]model.PVC, error)
	ListPods(ctx context.Context) ([]model.Pod, error)
	GetPod(ctx context.Context, namespace, name string) (*model.Pod, error)
	GetPVC(ctx context.Context, namespace, name string) (*model.PVC, error)
}

// InventoryLister lists the objects behind the inventory pages.
type InventoryLister interface {
	ListWorkloads(ctx context.Context) ([]model.Workload, error)
	ListServices(ctx context.Context) ([]model.Service, error)
	ListIngresses(ctx context.Context) ([]model.Ingress, error)
	ListNodes(ctx context.Context) ([]model.Node, error)
	ListPVs(ctx context.Context) ([]model.PV, error)
	ListStorageClasses(ctx context.Context) ([]model.StorageClass, error)
	ListNamespaces(ctx context.Context) ([]model.Namespace, error)
	ListRBAC(ctx context.Context) (model.RBAC, error)
}

// CertLister reads cert-manager objects.
type CertLister interface {
	CertManager(ctx context.Context) (model.CertManager, error)
}

// An InventoryLister may also offer these; the older interfaces do not, so
// without them ReplicaSets and EndpointSlices are reported unavailable and
// Services fall back to their selectors.
type (
	replicaSetLister interface {
		ListReplicaSets(ctx context.Context) ([]model.ReplicaSet, error)
	}
	endpointSliceLister interface {
		ListEndpointSlices(ctx context.Context) ([]model.EndpointSlice, error)
	}
)

// Source names recorded in Inventory.Unavailable by FromLists.
const (
	SourcePods           = "pods"
	SourcePVCs           = "persistentvolumeclaims"
	SourceWorkloads      = "workloads"
	SourceServices       = "services"
	SourceIngresses      = "ingresses"
	SourceNodes          = "nodes"
	SourcePVs            = "persistentvolumes"
	SourceStorageClasses = "storageclasses"
	SourceNamespaces     = "namespaces"
	SourceRBAC           = "rbac"
	SourceCertManager    = "certmanager"
)

// FromLists adapts the per-request list interfaces into a Source. inventory
// and certs may be nil. Every list runs concurrently; one that fails is
// recorded in Inventory.Unavailable with its error and left empty, so a
// forbidden source degrades its checks instead of failing the view. Only when
// every list fails (the API server is down) does Inventory return an error,
// which makes a Manager keep its last view.
func FromLists(cluster ClusterLister, inventory InventoryLister, certs CertLister) Source {
	return listSource{cluster: cluster, inventory: inventory, certs: certs}
}

type listSource struct {
	cluster   ClusterLister
	inventory InventoryLister
	certs     CertLister
}

// get reads one list into dst, leaving dst empty when the read fails.
func get[T any](ctx context.Context, dst *T, list func(context.Context) (T, error)) func() error {
	return func() error {
		v, err := list(ctx)
		if err == nil {
			*dst = v
		}
		return err
	}
}

func (s listSource) Inventory(ctx context.Context) (model.Inventory, error) {
	inv := model.Inventory{Unavailable: map[string]string{}}
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		attempts int
		errs     []error
	)
	mark := func(name, reason string) {
		mu.Lock()
		inv.Unavailable[name] = reason
		mu.Unlock()
	}
	run := func(name string, f func() error) {
		attempts++
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil {
				mu.Lock()
				inv.Unavailable[name] = err.Error()
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				mu.Unlock()
			}
		}()
	}
	notConfigured := func(names ...string) {
		for _, n := range names {
			mark(n, "not configured")
		}
	}

	// Each goroutine writes only its own field of inv; Unavailable is guarded.
	if s.cluster != nil {
		run(SourcePods, get(ctx, &inv.Pods, s.cluster.ListPods))
		run(SourcePVCs, get(ctx, &inv.PVCs, s.cluster.ListPVCs))
	} else {
		notConfigured(SourcePods, SourcePVCs)
	}
	if s.inventory != nil {
		in := s.inventory
		run(SourceWorkloads, get(ctx, &inv.Workloads, in.ListWorkloads))
		run(SourceServices, get(ctx, &inv.Services, in.ListServices))
		run(SourceIngresses, get(ctx, &inv.Ingresses, in.ListIngresses))
		run(SourceNodes, get(ctx, &inv.Nodes, in.ListNodes))
		run(SourcePVs, get(ctx, &inv.PVs, in.ListPVs))
		run(SourceStorageClasses, get(ctx, &inv.StorageClasses, in.ListStorageClasses))
		run(SourceNamespaces, get(ctx, &inv.Namespaces, in.ListNamespaces))
		run(SourceRBAC, get(ctx, &inv.RBAC, in.ListRBAC))
		if l, ok := in.(replicaSetLister); ok {
			run(detectors.SourceReplicaSets, get(ctx, &inv.ReplicaSets, l.ListReplicaSets))
		} else {
			mark(detectors.SourceReplicaSets, "not available from list sources")
		}
		if l, ok := in.(endpointSliceLister); ok {
			run(detectors.SourceEndpointSlices, get(ctx, &inv.EndpointSlices, l.ListEndpointSlices))
		} else {
			mark(detectors.SourceEndpointSlices, "not available from list sources")
		}
	} else {
		notConfigured(SourceWorkloads, SourceServices, SourceIngresses, SourceNodes, SourcePVs,
			SourceStorageClasses, SourceNamespaces, SourceRBAC, detectors.SourceReplicaSets, detectors.SourceEndpointSlices)
	}
	if s.certs != nil {
		run(SourceCertManager, get(ctx, &inv.Certs, s.certs.CertManager))
	} else {
		notConfigured(SourceCertManager)
	}
	wg.Wait()
	inv.ReadAt = time.Now()

	if err := ctx.Err(); err != nil {
		return inv, err
	}
	if attempts > 0 && len(errs) == attempts {
		return inv, errors.Join(errs...)
	}
	return inv, nil
}
