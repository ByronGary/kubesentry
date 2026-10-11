package detectors

import (
	"math"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestPricingPrice(t *testing.T) {
	def := 0.10
	pr := DefaultPolicy().Pricing
	pr.ClassPrices = map[string]float64{"premium": 0.20, "efs-priced": 0.30}
	withDefault := pr
	withDefault.DefaultPrice = &def

	cases := []struct {
		name   string
		pr     Pricing
		sc     model.StorageClass
		price  float64
		source string
		ok     bool
	}{
		{"annotation wins", pr, model.StorageClass{Name: "premium", Provisioner: "ebs.csi.aws.com", PriceAnnotation: "0.5", Parameters: map[string]string{"type": "io2"}}, 0.5, PriceFromAnnotation, true},
		{"bad annotation is ignored", pr, model.StorageClass{Name: "premium", PriceAnnotation: "cheap"}, 0.20, PriceFromClassFlag, true},
		{"class price", pr, model.StorageClass{Name: "premium", Provisioner: "ebs.csi.aws.com"}, 0.20, PriceFromClassFlag, true},
		{"class price beats usage billing", pr, model.StorageClass{Name: "efs-priced", Provisioner: "efs.csi.aws.com"}, 0.30, PriceFromClassFlag, true},
		{"ebs type", pr, model.StorageClass{Name: "fast", Provisioner: "ebs.csi.aws.com", Parameters: map[string]string{"type": "io2"}}, 0.125, PriceFromEBSTable, true},
		{"ebs type case", pr, model.StorageClass{Name: "fast", Provisioner: "ebs.csi.aws.com", Parameters: map[string]string{"Type": "ST1"}}, 0.045, PriceFromEBSTable, true},
		{"csi default gp3", pr, model.StorageClass{Name: "gp", Provisioner: "ebs.csi.aws.com"}, 0.08, PriceFromEBSTable, true},
		{"auto mode default gp3", pr, model.StorageClass{Name: "auto", Provisioner: "ebs.csi.eks.amazonaws.com"}, 0.08, PriceFromEBSTable, true},
		{"in-tree default gp2", pr, model.StorageClass{Name: "gp2", Provisioner: "kubernetes.io/aws-ebs"}, 0.10, PriceFromEBSTable, true},
		{"efs is usage billed even with a default", withDefault, model.StorageClass{Name: "efs", Provisioner: "efs.csi.aws.com"}, 0, PriceUsageBilled, false},
		{"unknown ebs type falls to default", withDefault, model.StorageClass{Name: "x", Provisioner: "ebs.csi.aws.com", Parameters: map[string]string{"type": "gp9"}}, 0.10, PriceFromDefault, true},
		{"local path with default", withDefault, model.StorageClass{Name: "standard", Provisioner: "rancher.io/local-path"}, 0.10, PriceFromDefault, true},
		{"nothing prices it", pr, model.StorageClass{Name: "standard", Provisioner: "rancher.io/local-path"}, 0, PriceUnknown, false},
		{"missing class by name", pr, model.StorageClass{Name: "premium"}, 0.20, PriceFromClassFlag, true},
	}
	for _, c := range cases {
		price, source, ok := c.pr.Price(c.sc)
		if math.Abs(price-c.price) > 1e-12 || source != c.source || ok != c.ok {
			t.Errorf("%s: %v %s %v, want %v %s %v", c.name, price, source, ok, c.price, c.source, c.ok)
		}
	}
}

func TestStorageCostsFromPolicy(t *testing.T) {
	g := int64(1 << 30)
	old := podNow.Add(-72 * time.Hour)
	classes := []model.StorageClass{
		{Name: "gp3", Provisioner: "ebs.csi.aws.com", Parameters: map[string]string{"type": "gp3", "iops": "3000"}, Default: true},
		{Name: "efs", Provisioner: "efs.csi.aws.com"},
		{Name: "local", Provisioner: "rancher.io/local-path", PriceAnnotation: "0.02"},
	}
	pvcs := []model.PVC{
		{Namespace: "a", Name: "data", StorageClass: "gp3", Phase: "Bound", CapacityBytes: 100 * g, Created: old},
		{Namespace: "a", Name: "shared", StorageClass: "efs", Phase: "Bound", CapacityBytes: 500 * g, Created: old},
		{Namespace: "a", Name: "scratch", StorageClass: "local", Phase: "Bound", CapacityBytes: 50 * g, Created: old},
		{Namespace: "a", Name: "mystery", StorageClass: "nfs", Phase: "Bound", CapacityBytes: 10 * g, Created: old},
	}
	p := DefaultPolicy()

	unused := FindUnusedPVCsWith(pvcs, nil, classes, podNow, 24*time.Hour, p.Pricing)
	got := map[string]UnusedPVC{}
	for _, u := range unused {
		got[u.Name] = u
	}
	if u := got["data"]; !u.CostKnown || u.PriceSource != PriceFromEBSTable || math.Abs(u.EstMonthlyCostUSD-8) > 1e-9 {
		t.Errorf("data = %+v", u)
	}
	if u := got["shared"]; u.CostKnown || u.PriceSource != PriceUsageBilled || u.EstMonthlyCostUSD != 0 {
		t.Errorf("efs = %+v", u)
	}
	if u := got["scratch"]; !u.CostKnown || u.PriceSource != PriceFromAnnotation || math.Abs(u.EstMonthlyCostUSD-1) > 1e-9 {
		t.Errorf("annotated = %+v", u)
	}
	if u := got["mystery"]; u.CostKnown || u.PriceSource != PriceUnknown {
		t.Errorf("unpriced = %+v", u)
	}
	if unused[0].Name != "data" {
		t.Errorf("most expensive first: %s", unused[0].Name)
	}

	claims, _, cls := SummarizeStorageWith(pvcs, nil, classes, nil, p, podNow)
	for _, c := range claims {
		if c.Name == "data" && (!c.CostKnown || math.Abs(c.EstMonthlyCostUSD-8) > 1e-9) {
			t.Errorf("claim cost = %+v", c)
		}
		if c.Name == "shared" && (c.CostKnown || c.PriceSource != PriceUsageBilled) {
			t.Errorf("efs claim = %+v", c)
		}
	}
	by := map[string]ClassSummary{}
	for _, c := range cls {
		by[c.Name] = c
	}
	if c := by["gp3"]; c.PricePerGiBMonth != 0.08 || c.PriceSource != PriceFromEBSTable || c.Parameters["iops"] != "3000" || c.Claims != 1 {
		t.Errorf("gp3 class = %+v", c)
	}
	if c := by["efs"]; c.PricePerGiBMonth != 0 || c.PriceSource != PriceUsageBilled || c.Parameters != nil {
		t.Errorf("efs class = %+v", c)
	}

	// The PVCOptions wrapper: no default price now means no estimate.
	legacy := FindUnusedPVCs(pvcs[:1], nil, podNow, PVCOptions{})
	if len(legacy) != 1 || legacy[0].CostKnown || legacy[0].EstMonthlyCostUSD != 0 || legacy[0].PriceSource != PriceUnknown {
		t.Errorf("legacy without prices = %+v", legacy)
	}
}
