package kube

import (
	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// The Cache and Source satisfy the interfaces the server wires them into.
var (
	_ snapshot.Source     = (*Cache)(nil)
	_ snapshot.Notifier   = (*Cache)(nil)
	_ api.ClusterSource   = (*Cache)(nil)
	_ api.InventorySource = (*Cache)(nil)
	_ api.CertSource      = (*Cache)(nil)

	_ snapshot.Source     = (*Source)(nil)
	_ api.ClusterSource   = (*Source)(nil)
	_ api.InventorySource = (*Source)(nil)
	_ api.CertSource      = (*Source)(nil)

	_ auth.Reviewer = (*Reviewer)(nil)

	_ incidents.EventSource = (*EventWatcher)(nil)
	_ incidents.LogSource   = (*PodLogs)(nil)
	_ PodGetter             = (*Cache)(nil)
	_ PodGetter             = (*Source)(nil)
)
