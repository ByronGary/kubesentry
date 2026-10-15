package kube

import (
	"context"
	"log/slog"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
)

// crdAPI is a custom resource API the Cache watches only while the API server
// serves it: cert-manager, the AWS Load Balancer Controller. An API that is
// not served is not an error; its part of the Inventory is simply empty.
type crdAPI struct {
	name      string // for logs, e.g. "cert-manager"
	group     string
	version   string
	resources []string     // in the order their objects appear in the Inventory
	reset     func(*memos) // forgets the conversions once the API is gone
}

// groupVersion names the API as discovery does, e.g. "cert-manager.io/v1".
func (a *crdAPI) groupVersion() string { return a.group + "/" + a.version }

func (a *crdAPI) gvr(resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: a.group, Version: a.version, Resource: resource}
}

// crdAPIs are the custom resource APIs the Cache looks for, in Inventory
// order.
var crdAPIs = []*crdAPI{certManagerAPI, targetGroupBindingAPI}

// crdState is a served custom resource API's informers.
type crdState struct {
	cancel context.CancelFunc
	res    map[string]*informerState
}

// crd returns the API's informers, nil while it is not served.
func (c *Cache) crd(a *crdAPI) *crdState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.crds[a]
}

// syncCRDs starts or stops the informers of every custom resource API.
func (c *Cache) syncCRDs(ctx context.Context) {
	for _, a := range crdAPIs {
		c.syncCRD(ctx, a)
	}
}

// syncCRD starts an API's informers when discovery finds it served, and stops
// them when it goes away.
func (c *Cache) syncCRD(ctx context.Context, a *crdAPI) {
	if c.dyn == nil || c.disc == nil {
		return
	}
	_, err := c.disc.ServerResourcesForGroupVersion(a.groupVersion())
	if err != nil && !apierrors.IsNotFound(err) {
		slog.Warn("discover "+a.name+"; keeping the current state", "err", err)
		return
	}
	served := err == nil
	cur := c.crd(a)
	switch {
	case served && cur == nil:
		c.startCRD(ctx, a)
	case !served && cur != nil:
		cur.cancel()
		c.mu.Lock()
		delete(c.crds, a)
		c.mu.Unlock()
		a.reset(&c.m)
		slog.Info(a.name + " API no longer served; stopped its informers")
		c.notify()
	}
}

func (c *Cache) startCRD(ctx context.Context, a *crdAPI) {
	checks := make([]access, len(a.resources))
	for i, r := range a.resources {
		checks[i] = access{group: a.group, resource: r}
	}
	allowed, reasons := c.probe(ctx, checks)
	crdCtx, cancel := context.WithCancel(ctx)
	f := dynamicinformer.NewDynamicSharedInformerFactory(c.dyn, 0)
	st := &crdState{cancel: cancel, res: map[string]*informerState{}}
	for i, r := range a.resources {
		is := &informerState{name: r}
		if allowed[i] {
			is.inf = f.ForResource(a.gvr(r)).Informer()
			_ = is.inf.SetTransform(c.transform)
			c.watch(is)
		} else {
			is.reason = reasons[i]
		}
		st.res[r] = is
	}
	f.Start(crdCtx.Done())
	go func() {
		<-crdCtx.Done()
		f.Shutdown()
	}()
	c.mu.Lock()
	if c.crds == nil {
		c.crds = map[*crdAPI]*crdState{}
	}
	c.crds[a] = st
	c.mu.Unlock()
	if c.started.Load() {
		slog.Info(a.name + " API found; started its informers")
		c.notify()
	}
}
