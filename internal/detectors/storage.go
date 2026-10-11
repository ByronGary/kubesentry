package detectors

import (
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// SummarizeStorage judges claims, volumes and storage classes with the
// default policy.
func SummarizeStorage(pvcs []model.PVC, pvs []model.PV, classes []model.StorageClass, pods []model.Pod, now time.Time) ([]ClaimSummary, []VolumeSummary, []ClassSummary) {
	return SummarizeStorageWith(pvcs, pvs, classes, pods, compatPolicy(), now)
}

// SummarizeStorageWith judges claims, volumes and storage classes for the
// Storage page, pricing claims and classes with p.Pricing. Claims and volumes
// are sorted most troubled first; classes default first, then by name.
func SummarizeStorageWith(pvcs []model.PVC, pvs []model.PV, classes []model.StorageClass, pods []model.Pod, p Policy, now time.Time) ([]ClaimSummary, []VolumeSummary, []ClassSummary) {
	classByName := make(map[string]model.StorageClass, len(classes))
	for _, c := range classes {
		classByName[c.Name] = c
	}
	usedBy := claimUsers(pods)

	claims := make([]ClaimSummary, 0, len(pvcs))
	type total struct {
		claims   int
		capacity int64
	}
	totals := make(map[string]total, len(classes))
	for _, c := range pvcs {
		t := totals[c.StorageClass]
		t.claims++
		t.capacity += c.CapacityBytes
		totals[c.StorageClass] = t

		users := usedBy[nsName{c.Namespace, c.Name}]
		if users == nil {
			users = []string{}
		}
		s := ClaimSummary{
			Namespace: c.Namespace, Name: c.Name, Phase: c.Phase, StorageClass: c.StorageClass,
			VolumeName: c.VolumeName, CapacityBytes: c.CapacityBytes, UsedBy: users, Created: c.Created,
		}
		s.EstMonthlyCostUSD, s.CostKnown, s.PriceSource = monthlyCost(c.CapacityBytes, c.StorageClass, classByName, p.Pricing)
		s.Status, s.Detail = judgeClaim(c, users, classByName, p.Thresholds.PendingGrace, now)
		claims = append(claims, s)
	}
	sort.Slice(claims, func(i, j int) bool {
		a, b := claims[i], claims[j]
		switch {
		case statusRank(a.Status) != statusRank(b.Status):
			return statusRank(a.Status) < statusRank(b.Status)
		case a.Namespace != b.Namespace:
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})

	volumes := make([]VolumeSummary, 0, len(pvs))
	for _, v := range pvs {
		s := VolumeSummary{
			Name: v.Name, Phase: v.Phase, StorageClass: v.StorageClass, ReclaimPolicy: v.ReclaimPolicy,
			Source: v.Source, Driver: v.Driver, VolumeHandle: v.VolumeHandle, CapacityBytes: v.CapacityBytes, Created: v.Created,
		}
		if v.ClaimName != "" {
			s.Claim = v.ClaimNamespace + "/" + v.ClaimName
		}
		s.Status, s.Detail = judgeVolume(v, s.Claim)
		volumes = append(volumes, s)
	}
	sort.Slice(volumes, func(i, j int) bool {
		a, b := volumes[i], volumes[j]
		if statusRank(a.Status) != statusRank(b.Status) {
			return statusRank(a.Status) < statusRank(b.Status)
		}
		return a.Name < b.Name
	})

	out := make([]ClassSummary, 0, len(classes))
	for _, c := range classes {
		s := ClassSummary{
			Name: c.Name, Provisioner: c.Provisioner, ReclaimPolicy: c.ReclaimPolicy,
			BindingMode: c.BindingMode, AllowExpansion: c.AllowExpansion, Default: c.Default,
			Claims: totals[c.Name].claims, CapacityBytes: totals[c.Name].capacity,
		}
		if len(c.Parameters) > 0 {
			s.Parameters = maps.Clone(c.Parameters)
		}
		s.PricePerGiBMonth, s.PriceSource, _ = p.Pricing.Price(c)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Default != out[j].Default {
			return out[i].Default
		}
		return out[i].Name < out[j].Name
	})
	return claims, volumes, out
}

// claimUsers maps each claim to the sorted names of the live pods mounting it.
func claimUsers(pods []model.Pod) map[nsName][]string {
	out := map[nsName][]string{}
	for i := range pods {
		p := &pods[i]
		if !isLive(p) {
			continue
		}
		for j, c := range p.Claims {
			if j > 0 && containsBefore(p.Claims, j) {
				continue
			}
			k := nsName{p.Namespace, c}
			out[k] = append(out[k], p.Name)
		}
	}
	for _, names := range out {
		sort.Strings(names)
	}
	return out
}

// containsBefore reports whether s[j] already occurs in s[:j]. Pods mount few
// claims, so this beats a set.
func containsBefore(s []string, j int) bool {
	for _, v := range s[:j] {
		if v == s[j] {
			return true
		}
	}
	return false
}

func judgeClaim(c model.PVC, users []string, classes map[string]model.StorageClass, pendingGrace time.Duration, now time.Time) (string, string) {
	class, classFound := classes[c.StorageClass]
	switch {
	case c.Phase == "Lost":
		return StatusCrit, strings.TrimSpace("Lost its volume "+c.VolumeName) + "; the data may be gone."
	// A bound claim keeps working without its class (static volumes often name
	// one that was never created), so only an unbound claim is stuck by it.
	case c.StorageClass != "" && !classFound && c.Phase != "Bound":
		return StatusCrit, "Storage class " + c.StorageClass + " does not exist."
	case c.Phase == "Pending":
		if class.BindingMode == "WaitForFirstConsumer" && len(users) == 0 {
			return StatusOK, "Waiting for its first pod (WaitForFirstConsumer)."
		}
		if age := now.Sub(c.Created); age > pendingGrace {
			return StatusWarn, "Pending for " + duration(age) + "."
		}
		return StatusOK, "Being provisioned."
	case len(users) == 0 && c.Phase == "Bound":
		return StatusWarn, "Not mounted by any running pod."
	case len(users) == 1:
		return StatusOK, "Mounted by " + users[0] + "."
	case len(users) > 1:
		return StatusOK, fmt.Sprintf("Mounted by %d pods.", len(users))
	}
	return StatusOK, "Phase " + c.Phase + "."
}

func judgeVolume(v model.PV, claim string) (string, string) {
	switch v.Phase {
	case "Released":
		from := ""
		if claim != "" {
			from = " by " + claim
		}
		if v.ReclaimPolicy == "Retain" {
			return StatusWarn, "Released" + from + ". The Retain reclaim policy keeps the data, and the volume costs money until someone deletes it."
		}
		return StatusWarn, "Released" + from + " but not yet reclaimed (policy " + v.ReclaimPolicy + "). It costs money while it exists."
	case "Failed":
		return StatusCrit, "Reclaiming the volume failed; it needs manual cleanup."
	case "Available":
		return StatusOK, "Available, unclaimed."
	case "Bound":
		return StatusOK, "Bound to " + claim + "."
	}
	return StatusOK, "Phase " + v.Phase + "."
}

// duration formats an age coarsely: "12m", "5h", "3d".
func duration(d time.Duration) string {
	return strings.TrimSuffix(ago(d), " ago")
}
