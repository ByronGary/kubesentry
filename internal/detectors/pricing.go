package detectors

import (
	"slices"
	"strconv"
	"strings"

	"github.com/ByronGary/kubesentry/internal/model"
)

// Price returns what one GiB-month of sc costs and where the price came from.
// The order is: the StorageClass's kubesentry.io/price-per-gib-month
// annotation, ClassPrices by class name, "usage-billed" for UsageBilled
// provisioners (EFS, FSx: no size-based estimate, ok false), EBSPrices by the
// class's parameters.type for EBS provisioners, then DefaultPrice. ok is false
// when nothing prices the class (source "unknown").
//
// An EBS class without parameters.type gets the provisioner's default volume
// type: gp2 for the in-tree kubernetes.io/aws-ebs, gp3 for the CSI drivers.
// A StorageClass the caller could not find can be passed with only its Name.
func (pr Pricing) Price(sc model.StorageClass) (perGiB float64, source string, ok bool) {
	if a := strings.TrimSpace(sc.PriceAnnotation); a != "" {
		if v, err := strconv.ParseFloat(strings.TrimPrefix(a, "$"), 64); err == nil && v >= 0 {
			return v, PriceFromAnnotation, true
		}
	}
	if v, found := pr.ClassPrices[sc.Name]; found && sc.Name != "" {
		return v, PriceFromClassFlag, true
	}
	if sc.Provisioner != "" && slices.Contains(pr.UsageBilled, sc.Provisioner) {
		return 0, PriceUsageBilled, false
	}
	if sc.Provisioner != "" && slices.Contains(pr.EBSProvisioners, sc.Provisioner) {
		if v, found := pr.EBSPrices[ebsType(sc)]; found {
			return v, PriceFromEBSTable, true
		}
	}
	if pr.DefaultPrice != nil {
		return *pr.DefaultPrice, PriceFromDefault, true
	}
	return 0, PriceUnknown, false
}

// ebsType is the class's EBS volume type, lower case.
func ebsType(sc model.StorageClass) string {
	for k, v := range sc.Parameters {
		if strings.EqualFold(k, "type") && v != "" {
			return strings.ToLower(v)
		}
	}
	if sc.Provisioner == "kubernetes.io/aws-ebs" {
		return "gp2"
	}
	return "gp3"
}

// monthlyCost prices capacity bytes of a claim in class name, looked up in
// classes. It returns the cost (0 when unknown), whether it is known, and the
// price source.
func monthlyCost(capacity int64, class string, classes map[string]model.StorageClass, pr Pricing) (float64, bool, string) {
	sc, found := classes[class]
	if !found {
		sc = model.StorageClass{Name: class}
	}
	price, source, ok := pr.Price(sc)
	if !ok {
		return 0, false, source
	}
	return float64(capacity) / gib * price, true, source
}

// pricingFromOptions maps the older PVCOptions onto Pricing. A zero default
// price meant "free" before; it now means "no estimate", which reports the
// same zero cost.
func pricingFromOptions(opts PVCOptions) Pricing {
	pr := Pricing{ClassPrices: opts.PricePerGiBMonth}
	if opts.DefaultPricePerGiBMonth != 0 {
		d := opts.DefaultPricePerGiBMonth
		pr.DefaultPrice = &d
	}
	return pr
}
