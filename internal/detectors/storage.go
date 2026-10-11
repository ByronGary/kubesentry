package detectors

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// pendingGrace is how long a claim or request may wait before it is flagged.
const pendingGrace = 5 * time.Minute

// SummarizeStorage judges claims, volumes and storage classes for the Storage
// page. Claims and volumes are sorted most troubled first; classes default
// first, then by name.
func SummarizeStorage(pvcs []model.PVC, pvs []model.PV, classes []model.StorageClass, pods []model.Pod, now time.Time) ([]ClaimSummary, []VolumeSummary, []ClassSummary) {
	classByName := make(map[string]model.StorageClass, len(classes))
	for _, c := range classes {
		classByName[c.Name] = c
	}
	usedBy := claimUsers(pods)

	claims := make([]ClaimSummary, 0, len(pvcs))
	for _, c := range pvcs {
		users := usedBy[c.Namespace+"/"+c.Name]
		if users == nil {
			users = []string{}
		}
		s := ClaimSummary{
			Namespace: c.Namespace, Name: c.Name, Phase: c.Phase, StorageClass: c.StorageClass,
			VolumeName: c.VolumeName, CapacityBytes: c.CapacityBytes, UsedBy: users, Created: c.Created,
		}
		s.Status, s.Detail = judgeClaim(c, users, classByName, now)
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
			Source: v.Source, CapacityBytes: v.CapacityBytes, Created: v.Created,
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
		}
		for _, p := range pvcs {
			if p.StorageClass == c.Name {
				s.Claims++
				s.CapacityBytes += p.CapacityBytes
			}
		}
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

// claimUsers maps "namespace/claim" to the sorted names of the live pods
// mounting it.
func claimUsers(pods []model.Pod) map[string][]string {
	out := map[string][]string{}
	for _, p := range pods {
		if !live(p) {
			continue
		}
		seen := map[string]bool{}
		for _, c := range p.Claims {
			if seen[c] {
				continue
			}
			seen[c] = true
			out[p.Namespace+"/"+c] = append(out[p.Namespace+"/"+c], p.Name)
		}
	}
	for _, names := range out {
		sort.Strings(names)
	}
	return out
}

func judgeClaim(c model.PVC, users []string, classes map[string]model.StorageClass, now time.Time) (string, string) {
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
