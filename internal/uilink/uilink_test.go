package uilink

import "testing"

func TestRoutes(t *testing.T) {
	for got, want := range map[string]string{
		Workload("payments", "api"):                       "#/workloads?namespace=payments&q=api",
		Pod("payments", "api-0"):                          "#/pods/payments/api-0",
		Security("cluster-admin", "x"):                    "#/security?check=cluster-admin&q=x",
		Certificate("payments", "api-tls"):                "#/certificates?q=payments%2Fapi-tls",
		Node("ip-10-0-0-1"):                               "#/nodes?node=ip-10-0-0-1",
		Owner("team a"):                                   "#/?owner=team+a",
		Activity("exec", "alice@example.com"):             "#/activity?tag=exec&user=alice%40example.com",
		Activity("", ""):                                  "#/activity",
		Agents():                                          "#/agents",
		Incident("20261015T101500Z-0a1b2c3d4e5f"):         "#/incidents/20261015T101500Z-0a1b2c3d4e5f",
		Incident("a/b"):                                   "#/incidents/a%2Fb",
		Absolute("https://ks.example.com/", "#/pods/a/b"): "https://ks.example.com/#/pods/a/b",
		Absolute("", "#/pods/a/b"):                        "",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
