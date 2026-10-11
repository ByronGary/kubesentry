// Package detectors holds the pure analysis logic. It depends only on
// internal/model, so everything here is testable without a cluster.
package detectors

import (
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

const gib = float64(1 << 30)

// PVCOptions tunes unused-PVC detection.
type PVCOptions struct {
	// MinAge hides PVCs younger than this, to avoid flagging volumes that are
	// still waiting for their first pod.
	MinAge time.Duration
	// PricePerGiBMonth maps storage class to USD per GiB-month.
	PricePerGiBMonth map[string]float64
	// DefaultPricePerGiBMonth is used for classes missing from the map.
	DefaultPricePerGiBMonth float64
}

// UnusedPVC is a PVC that no live pod mounts.
type UnusedPVC struct {
	model.PVC
	AgeHours          float64 `json:"ageHours"`
	EstMonthlyCostUSD float64 `json:"estMonthlyCostUSD"`
}

// FindUnusedPVCs returns PVCs not mounted by any pod, most expensive first.
//
// Rules:
//   - Pods in phase Succeeded or Failed no longer hold a volume and are ignored.
//   - Pending PVCs are skipped: with WaitForFirstConsumer binding they are
//     unused by design, and they have no provisioned capacity to bill.
//
// Caveat: a StatefulSet scaled to zero leaves its PVCs unmounted on purpose.
// MinAge reduces noise but cannot distinguish that case.
func FindUnusedPVCs(pvcs []model.PVC, pods []model.Pod, now time.Time, opts PVCOptions) []UnusedPVC {
	inUse := make(map[string]struct{})
	for _, p := range pods {
		if p.Phase == "Succeeded" || p.Phase == "Failed" {
			continue
		}
		for _, c := range p.Claims {
			inUse[p.Namespace+"/"+c] = struct{}{}
		}
	}

	out := []UnusedPVC{}
	for _, pvc := range pvcs {
		if pvc.Phase == "Pending" {
			continue
		}
		if _, used := inUse[pvc.Namespace+"/"+pvc.Name]; used {
			continue
		}
		age := now.Sub(pvc.Created)
		if age < opts.MinAge {
			continue
		}
		out = append(out, UnusedPVC{
			PVC:               pvc,
			AgeHours:          age.Hours(),
			EstMonthlyCostUSD: monthlyCost(pvc, opts),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].EstMonthlyCostUSD != out[j].EstMonthlyCostUSD {
			return out[i].EstMonthlyCostUSD > out[j].EstMonthlyCostUSD
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func monthlyCost(pvc model.PVC, opts PVCOptions) float64 {
	price, ok := opts.PricePerGiBMonth[pvc.StorageClass]
	if !ok {
		price = opts.DefaultPricePerGiBMonth
	}
	return float64(pvc.CapacityBytes) / gib * price
}
