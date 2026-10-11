// Package detectors holds the pure analysis logic. It depends only on
// internal/model, so everything here is testable without a cluster.
package detectors

import (
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

const gib = float64(1 << 30)

// PVCOptions tunes unused-PVC detection. It predates Policy: FindUnusedPVCs
// maps its prices onto a Pricing with ClassPrices and DefaultPrice.
type PVCOptions struct {
	// MinAge hides PVCs younger than this, to avoid flagging volumes that are
	// still waiting for their first pod.
	MinAge time.Duration
	// PricePerGiBMonth maps storage class to USD per GiB-month.
	PricePerGiBMonth map[string]float64
	// DefaultPricePerGiBMonth is used for classes missing from the map; 0
	// means no estimate.
	DefaultPricePerGiBMonth float64
}

// UnusedPVC is a PVC that no live pod mounts.
type UnusedPVC struct {
	model.PVC
	AgeHours float64 `json:"ageHours"`
	// EstMonthlyCostUSD is 0 when CostKnown is false; PriceSource says where
	// the price came from or why there is none (see the PriceFrom* constants).
	EstMonthlyCostUSD float64 `json:"estMonthlyCostUSD"`
	CostKnown         bool    `json:"costKnown"`
	PriceSource       string  `json:"priceSource"`
}

// FindUnusedPVCs returns PVCs not mounted by any pod, most expensive first,
// priced from opts.
func FindUnusedPVCs(pvcs []model.PVC, pods []model.Pod, now time.Time, opts PVCOptions) []UnusedPVC {
	return FindUnusedPVCsWith(pvcs, pods, nil, now, opts.MinAge, pricingFromOptions(opts))
}

// FindUnusedPVCsWith returns PVCs not mounted by any pod and at least minAge
// old, most expensive first. Each is priced from its StorageClass (looked up
// in classes) with pr; claims whose class nothing prices have no estimate.
//
// Rules:
//   - Pods in phase Succeeded or Failed no longer hold a volume and are ignored.
//   - Pending PVCs are skipped: with WaitForFirstConsumer binding they are
//     unused by design, and they have no provisioned capacity to bill.
//
// Caveat: a StatefulSet scaled to zero leaves its PVCs unmounted on purpose.
// minAge reduces noise but cannot distinguish that case.
func FindUnusedPVCsWith(pvcs []model.PVC, pods []model.Pod, classes []model.StorageClass, now time.Time, minAge time.Duration, pr Pricing) []UnusedPVC {
	inUse := make(map[nsName]struct{}, len(pods))
	for i := range pods {
		p := &pods[i]
		if !isLive(p) {
			continue
		}
		for _, c := range p.Claims {
			inUse[nsName{p.Namespace, c}] = struct{}{}
		}
	}
	classByName := make(map[string]model.StorageClass, len(classes))
	for _, c := range classes {
		classByName[c.Name] = c
	}

	out := []UnusedPVC{}
	for _, pvc := range pvcs {
		if pvc.Phase == "Pending" {
			continue
		}
		if _, used := inUse[nsName{pvc.Namespace, pvc.Name}]; used {
			continue
		}
		age := now.Sub(pvc.Created)
		if age < minAge {
			continue
		}
		u := UnusedPVC{PVC: pvc, AgeHours: age.Hours()}
		u.EstMonthlyCostUSD, u.CostKnown, u.PriceSource = monthlyCost(pvc.CapacityBytes, pvc.StorageClass, classByName, pr)
		out = append(out, u)
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
