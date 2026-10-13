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
		Absolute("https://ks.example.com/", "#/pods/a/b"): "https://ks.example.com/#/pods/a/b",
		Absolute("", "#/pods/a/b"):                        "",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
