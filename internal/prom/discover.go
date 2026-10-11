package prom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Flavours Probe recognises.
const (
	FlavorPrometheus      = "prometheus"
	FlavorThanos          = "thanos"
	FlavorVictoriaMetrics = "victoriametrics"
	FlavorMimir           = "mimir"
	FlavorAMP             = "amp"
	FlavorUnknown         = "unknown" // answers PromQL, flavour not recognised
)

// BuildInfo describes a server that answered Probe.
type BuildInfo struct {
	URL     string `json:"url"`
	Flavor  string `json:"flavor"`
	Version string `json:"version,omitempty"`
	// RetentionHours is the TSDB retention a Prometheus reports; 0 when the
	// server does not say (Thanos, AMP, VictoriaMetrics).
	RetentionHours float64 `json:"retentionHours,omitempty"`
	// UpTargets is count(up) at probe time: 0 means reachable but empty.
	UpTargets int `json:"upTargets"`
}

// Rejection is a candidate that failed its probe.
type Rejection struct {
	URL    string `json:"url"`
	Reason string `json:"reason"`
}

const probeBodyLimit = 1 << 20

// ampHost matches Amazon Managed Prometheus workspace endpoints. The awsauth
// package has the same check; prom stays free of the AWS SDK.
var ampHost = regexp.MustCompile(`^aps-workspaces\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$`)

// Probe checks that baseURL serves the Prometheus query API and identifies
// what serves it. It reads /api/v1/status/buildinfo when the server has it
// (Prometheus, Thanos, Mimir, VictoriaMetrics), then always runs count(up),
// which is what proves the query path and its credentials work. A nil client
// uses a 10-second timeout; pass awsauth's transport for AMP.
func Probe(ctx context.Context, baseURL string, client *http.Client) (BuildInfo, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return BuildInfo{}, fmt.Errorf("not an http(s) URL: %q", baseURL)
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	base := strings.TrimRight(baseURL, "/")
	info := BuildInfo{URL: base, Flavor: FlavorUnknown}

	var bi struct {
		Status string `json:"status"`
		Data   struct {
			Version     string `json:"version"`
			Revision    string `json:"revision"`
			GoVersion   string `json:"goVersion"`
			Application string `json:"application"`
		} `json:"data"`
	}
	haveBuild := getJSON(ctx, client, base+"/api/v1/status/buildinfo", &bi) == nil && bi.Status == "success"

	// The query is the real test: buildinfo can answer while queries are
	// refused (wrong credentials, a frontend without a querier).
	body, status, err := post(ctx, client, base+"/api/v1/query", url.Values{"query": {"count(up)"}})
	if err != nil {
		return BuildInfo{}, err
	}
	series, _, err := parseResponse(status, body)
	if err != nil {
		switch {
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			return BuildInfo{}, fmt.Errorf("query refused: HTTP %d (check credentials)", status)
		case json.Valid(body):
			return BuildInfo{}, fmt.Errorf("query failed: %w", err)
		default:
			return BuildInfo{}, fmt.Errorf("not a Prometheus query API (HTTP %d, non-JSON response)", status)
		}
	}
	if len(series) > 0 && len(series[0].Samples) > 0 {
		info.UpTargets = int(series[0].Samples[0].V)
	}

	switch {
	case ampHost.MatchString(u.Hostname()):
		info.Flavor = FlavorAMP
	case haveBuild && strings.Contains(strings.ToLower(bi.Data.Application), "mimir"):
		info.Flavor = FlavorMimir
	case strings.Contains(string(body), `"seriesFetched"`) || strings.Contains(u.Path, "/select/"):
		// VictoriaMetrics adds query stats to every response and serves its
		// cluster API under /select/<tenant>/prometheus.
		info.Flavor = FlavorVictoriaMetrics
	case haveBuild && strings.HasPrefix(bi.Data.Version, "0."):
		info.Flavor = FlavorThanos // Prometheus is 2.x or 3.x; Thanos is 0.x
	case haveBuild && bi.Data.GoVersion == "" && bi.Data.Revision == "":
		info.Flavor = FlavorVictoriaMetrics // emulates buildinfo with a version only
	case haveBuild:
		info.Flavor = FlavorPrometheus
	}
	if haveBuild && info.Flavor != FlavorVictoriaMetrics {
		info.Version = bi.Data.Version
	}

	if info.Flavor == FlavorPrometheus {
		var rt struct {
			Status string `json:"status"`
			Data   struct {
				StorageRetention string `json:"storageRetention"`
			} `json:"data"`
		}
		if getJSON(ctx, client, base+"/api/v1/status/runtimeinfo", &rt) == nil && rt.Status == "success" {
			info.RetentionHours = parseRetention(rt.Data.StorageRetention)
		}
	}
	return info, nil
}

// Choose probes the candidates, in parallel, and returns the first in list
// order that answered, with the reasons the others were rejected. The order
// is the caller's preference (annotated Service, pinned Service, well-known
// names).
func Choose(ctx context.Context, candidates []string, client *http.Client) (BuildInfo, []Rejection, error) {
	type result struct {
		info BuildInfo
		err  error
	}
	results := make([]result, len(candidates))
	var wg sync.WaitGroup
	for i, c := range candidates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := Probe(ctx, c, client)
			results[i] = result{info, err}
		}()
	}
	wg.Wait()

	var rejected []Rejection
	chosen := -1
	for i, r := range results {
		if r.err != nil {
			rejected = append(rejected, Rejection{URL: candidates[i], Reason: r.err.Error()})
		} else if chosen < 0 {
			chosen = i
		}
	}
	if chosen < 0 {
		if len(candidates) == 0 {
			return BuildInfo{}, nil, errors.New("no Prometheus candidates")
		}
		reasons := make([]string, len(rejected))
		for i, r := range rejected {
			reasons[i] = r.URL + ": " + r.Reason
		}
		return BuildInfo{}, rejected, fmt.Errorf("no Prometheus candidate answered: %s", strings.Join(reasons, "; "))
	}
	return results[chosen].info, rejected, nil
}

func getJSON(ctx context.Context, client *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, probeBodyLimit))
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, probeBodyLimit)).Decode(v)
}

func post(ctx context.Context, client *http.Client, u string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, probeBodyLimit))
	if err != nil {
		return nil, 0, fmt.Errorf("read response: %w", err)
	}
	return body, resp.StatusCode, nil
}

// parseRetention reads Prometheus' storageRetention, such as "15d",
// "6h30m" or "15d or 50GiB", into hours; 0 when there is no time limit.
func parseRetention(s string) float64 {
	for _, part := range strings.Split(s, " or ") {
		if h, ok := parsePromDuration(strings.TrimSpace(part)); ok {
			return h
		}
	}
	return 0
}

var durPart = regexp.MustCompile(`(\d+)(ms|y|w|d|h|m|s)`)

// parsePromDuration parses a Prometheus duration ("1y2w3d4h5m6s7ms") into
// hours.
func parsePromDuration(s string) (float64, bool) {
	if s == "" || durPart.ReplaceAllString(s, "") != "" {
		return 0, false
	}
	unit := map[string]float64{"y": 365 * 24, "w": 7 * 24, "d": 24, "h": 1, "m": 1.0 / 60, "s": 1.0 / 3600, "ms": 1.0 / 3600000}
	var h float64
	for _, m := range durPart.FindAllStringSubmatch(s, -1) {
		n, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, false
		}
		h += n * unit[m[2]]
	}
	return h, true
}
