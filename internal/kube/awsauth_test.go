package kube

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestAWSAuthParse(t *testing.T) {
	got, err := ParseAWSAuth(map[string]string{
		"mapRoles": `
- rolearn: arn:aws:iam::123:role/nodes
  username: system:node:{{EC2PrivateDNSName}}
  groups:
    - system:bootstrappers
    - system:nodes
- rolearn: arn:aws:iam::123:role/admins
  username: admin
  groups: [system:masters]
`,
		"mapUsers": "- userarn: arn:aws:iam::123:user/erin\n  username: erin\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := model.AWSAuth{
		MapRoles: []model.AWSAuthMapping{
			{ARN: "arn:aws:iam::123:role/nodes", Username: "system:node:{{EC2PrivateDNSName}}", Groups: []string{"system:bootstrappers", "system:nodes"}},
			{ARN: "arn:aws:iam::123:role/admins", Username: "admin", Groups: []string{"system:masters"}},
		},
		MapUsers: []model.AWSAuthMapping{{ARN: "arn:aws:iam::123:user/erin", Username: "erin"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestAWSAuthParseToleratesMalformedEntries(t *testing.T) {
	got, err := ParseAWSAuth(map[string]string{
		"mapRoles": `
- just a string
- username: no-arn
  groups: [system:masters]
- rolearn: arn:aws:iam::123:role/single-group
  groups: system:masters
- rolearn: " arn:aws:iam::123:role/mixed "
  groups: [devs, 42, {nested: true}, ""]
- userarn: arn:aws:iam::123:user/in-the-wrong-list
`,
		"mapUsers": "- userarn: [unclosed\n",
	})
	if err == nil {
		t.Fatal("malformed entries should be reported")
	}
	for _, frag := range []string{"mapRoles[0]: not a mapping", "mapRoles[1]: no rolearn", "mapUsers"} {
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("error %q lacks %q", err, frag)
		}
	}
	want := []model.AWSAuthMapping{
		{ARN: "arn:aws:iam::123:role/single-group", Groups: []string{"system:masters"}},
		{ARN: "arn:aws:iam::123:role/mixed", Groups: []string{"devs"}},
		{ARN: "arn:aws:iam::123:user/in-the-wrong-list"},
	}
	if !reflect.DeepEqual(got.MapRoles, want) || got.MapUsers != nil {
		t.Errorf("got %+v", got)
	}

	if got, err := ParseAWSAuth(nil); err != nil || got.MapRoles != nil || got.MapUsers != nil {
		t.Errorf("empty: %+v, %v", got, err)
	}
	if _, err := ParseAWSAuth(map[string]string{"mapRoles": "rolearn: not-a-list"}); err == nil || !strings.Contains(err.Error(), "not a list") {
		t.Errorf("map instead of list: %v", err)
	}
}
