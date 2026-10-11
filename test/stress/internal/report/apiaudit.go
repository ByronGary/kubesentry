package report

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/test/stress/internal/hist"
)

// APILoad is the API server traffic of one user, from the audit log.
type APILoad struct {
	User         string         `json:"user"`
	Requests     int            `json:"requests"`
	PerSecond    float64        `json:"perSecond"`
	PeakPerMin   int            `json:"peakPerMinute"`
	PeakPerSec   float64        `json:"peakPerSecond"` // peak minute / 60
	ByVerbRes    map[string]int `json:"byVerbResource"`
	Codes        map[string]int `json:"codes"`
	ServerTimeMs hist.Summary   `json:"serverTimeMs"` // stageTimestamp - requestReceivedTimestamp
	Minutes      []MinuteCount  `json:"minutes"`
	Truncated    bool           `json:"truncated,omitempty"` // log rotated past the window start
	OldestSeen   time.Time      `json:"oldestSeen"`
}

// MinuteCount is requests per minute.
type MinuteCount struct {
	T time.Time `json:"t"`
	N int       `json:"n"`
}

type auditLine struct {
	RequestURI string `json:"requestURI"`
	Stage      string `json:"stage"`
	Verb       string `json:"verb"`
	User       struct {
		Username string `json:"username"`
	} `json:"user"`
	ObjectRef *struct {
		Resource    string `json:"resource"`
		Subresource string `json:"subresource"`
	} `json:"objectRef"`
	ResponseStatus *struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
	RequestReceived time.Time `json:"requestReceivedTimestamp"`
	StageTimestamp  time.Time `json:"stageTimestamp"`
}

// AuditLog reads the kube-apiserver audit log on the kind control plane and
// returns, per window, the requests made by user. The grep runs inside the
// node container so only that user's lines cross over.
func AuditLog(ctx context.Context, node, user string, windows map[string][2]time.Time) (map[string]*APILoad, error) {
	pattern := fmt.Sprintf(`"username":"%s"`, user)
	cmd := exec.CommandContext(ctx, "docker", "exec", node, "sh", "-c",
		"grep -h -F '"+pattern+"' /var/log/kubernetes/audit/*.log || true")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	type acc struct {
		load    *APILoad
		minutes map[int64]int
		h       *hist.Hist
	}
	accs := map[string]*acc{}
	for name := range windows {
		accs[name] = &acc{load: &APILoad{User: user, ByVerbRes: map[string]int{}, Codes: map[string]int{}}, minutes: map[int64]int{}, h: hist.New()}
	}
	oldest := time.Time{}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var l auditLine
		if json.Unmarshal(sc.Bytes(), &l) != nil || l.User.Username != user {
			continue
		}
		if oldest.IsZero() || l.RequestReceived.Before(oldest) {
			oldest = l.RequestReceived
		}
		if l.Stage != "ResponseComplete" {
			continue
		}
		for name, w := range windows {
			if l.RequestReceived.Before(w[0]) || l.RequestReceived.After(w[1]) {
				continue
			}
			a := accs[name]
			a.load.Requests++
			res := l.RequestURI // non-resource requests such as discovery
			if i := strings.IndexByte(res, '?'); i >= 0 {
				res = res[:i]
			}
			if l.ObjectRef != nil {
				res = l.ObjectRef.Resource
				if l.ObjectRef.Subresource != "" {
					res += "/" + l.ObjectRef.Subresource
				}
			}
			a.load.ByVerbRes[l.Verb+" "+res]++
			code := 0
			if l.ResponseStatus != nil {
				code = l.ResponseStatus.Code
			}
			a.load.Codes[fmt.Sprint(code)]++
			a.minutes[l.RequestReceived.Unix()/60]++
			a.h.AddDuration(l.StageTimestamp.Sub(l.RequestReceived))
		}
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("docker exec %s: %w", node, err)
	}
	out := map[string]*APILoad{}
	for name, a := range accs {
		w := windows[name]
		secs := w[1].Sub(w[0]).Seconds()
		if secs > 0 {
			a.load.PerSecond = float64(a.load.Requests) / secs
		}
		for m, n := range a.minutes {
			a.load.Minutes = append(a.load.Minutes, MinuteCount{T: time.Unix(m*60, 0).UTC(), N: n})
			if n > a.load.PeakPerMin {
				a.load.PeakPerMin = n
			}
		}
		sort.Slice(a.load.Minutes, func(i, j int) bool { return a.load.Minutes[i].T.Before(a.load.Minutes[j].T) })
		a.load.PeakPerSec = float64(a.load.PeakPerMin) / 60
		a.load.ServerTimeMs = a.h.Summarize()
		a.load.OldestSeen = oldest
		a.load.Truncated = !oldest.IsZero() && oldest.After(w[0])
		out[name] = a.load
	}
	return out, nil
}
