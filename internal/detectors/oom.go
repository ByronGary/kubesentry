package detectors

import (
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// OOMEvent is a container whose most recent termination was OOMKilled.
type OOMEvent struct {
	model.ContainerKey
	RestartCount int32     `json:"restartCount"`
	LastOOMAt    time.Time `json:"lastOOMAt"`
	ExitCode     int32     `json:"exitCode"`
}

// FindOOMKills returns containers whose latest recorded termination reason is
// OOMKilled, newest first. A zero since returns all of them. The Kubernetes API
// only keeps the last termination per container, so this is "most recent OOM",
// not a count; the leak detector adds history from Prometheus.
func FindOOMKills(pods []model.Pod, since time.Time) []OOMEvent {
	out := []OOMEvent{}
	for _, p := range pods {
		for _, c := range p.Containers {
			if c.LastTerminatedReason != "OOMKilled" {
				continue
			}
			if !since.IsZero() && c.LastTerminatedAt.Before(since) {
				continue
			}
			out = append(out, OOMEvent{
				ContainerKey: model.ContainerKey{Namespace: p.Namespace, Pod: p.Name, Container: c.Name},
				RestartCount: c.RestartCount,
				LastOOMAt:    c.LastTerminatedAt,
				ExitCode:     c.LastExitCode,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastOOMAt.After(out[j].LastOOMAt) })
	return out
}
