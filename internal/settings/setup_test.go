package settings

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden.json")

func golden(t *testing.T, name string, v any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	path := filepath.Join("testdata", name+".golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/settings -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from %s; run go test ./internal/settings -update and review the diff\n%s", name, path, got)
	}
}

func tab(g Guide, id string) Tab {
	for _, t := range g.Tabs {
		if t.ID == id {
			return t
		}
	}
	return Tab{}
}

func TestSetupGoldens(t *testing.T) {
	bedrock := helmDefaults()
	runtime := bedrock
	runtime.BedrockAPI, runtime.Model, runtime.Region = BedrockRuntime, "us.anthropic.claude-opus-5-5", "us-west-2"
	anthropic := bedrock
	anthropic.Provider = ProviderAnthropic
	eks := Environment{Kind: EnvEKS, Cluster: "prod-eks", Region: "us-east-1", Platform: "eks", Namespace: "kubesentry", ServiceAccount: "kubesentry"}
	for _, tc := range []struct {
		name string
		in   SetupInput
		rec  string
	}{
		// EKS with IRSA, the issuer unknown: the describe-cluster command
		// and a placeholder.
		{"eks-irsa-mantle", SetupInput{Env: eks, Settings: bedrock, DefaultRegion: "us-east-1",
			Creds: Credentials{Kind: CredIRSA, RoleARN: "arn:aws:iam::111122223333:role/kubesentry", AccountID: "111122223333"}}, TabIRSA},
		// EKS with Pod Identity, InvokeModel through an inference profile,
		// the issuer known.
		{"eks-pod-identity-runtime", SetupInput{Env: func() Environment {
			e := eks
			e.OIDCIssuer = "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
			return e
		}(), Settings: runtime, Creds: Credentials{Kind: CredPodIdentity}}, TabPodIdentity},
		// A laptop with an SSO profile.
		{"remote-sso", SetupInput{Env: Environment{Kind: EnvRemote, Cluster: "demo-eks", KubeContext: "demo-eks"}, Settings: bedrock,
			DefaultRegion: "eu-west-1", Creds: Credentials{Kind: CredProfile, Profile: "platform-admin", SSO: true}}, TabOutsideEKS},
		// The Anthropic API in another cluster.
		{"kubernetes-anthropic", SetupInput{Env: Environment{Kind: EnvKubernetes, Namespace: "observability", ServiceAccount: "ks"},
			Settings: anthropic, Creds: Credentials{Kind: CredNone, AnthropicKey: true}}, TabAnthropic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := Setup(tc.in)
			if g.Recommended != tc.rec || len(g.Tabs) != 4 {
				t.Errorf("recommended %q, %d tabs", g.Recommended, len(g.Tabs))
			}
			for _, tb := range g.Tabs {
				for _, st := range tb.Steps {
					if st.Lang == "json" && !json.Valid([]byte(st.Code)) {
						t.Errorf("%s/%s: not JSON:\n%s", tb.ID, st.Title, st.Code)
					}
				}
			}
			golden(t, "setup-"+tc.name, g)
		})
	}
}

func TestSetupContent(t *testing.T) {
	in := SetupInput{Env: Environment{Kind: EnvEKS, Cluster: "prod-eks", Namespace: "kubesentry", ServiceAccount: "kubesentry"},
		Settings: helmDefaults(), DefaultRegion: "us-east-1", Creds: Credentials{Kind: CredIRSA}}
	all := func(tb Tab) string {
		var b strings.Builder
		for _, s := range tb.Steps {
			b.WriteString(s.Title + "\n" + s.Text + "\n" + s.Code + "\n")
		}
		return b.String()
	}
	irsa := all(tab(Setup(in), TabIRSA))
	for _, want := range []string{"bedrock-mantle:CreateInference", "arn:aws:bedrock-mantle:us-east-1:<ACCOUNT_ID>:project/*",
		"com.amazonaws.us-east-1.bedrock-mantle", "--private-dns-enabled", "--port 443", "aws eks describe-cluster --name prod-eks",
		"cluster.identity.oidc.issuer", "<OIDC_ISSUER>:sub", "system:serviceaccount:kubesentry:kubesentry", "sts:AssumeRoleWithWebIdentity",
		"eks.amazonaws.com/role-arn: arn:aws:iam::<ACCOUNT_ID>:role/kubesentry-investigator", "anthropic.claude-opus-5\""} {
		if !strings.Contains(irsa, want) {
			t.Errorf("IRSA steps lack %q", want)
		}
	}
	in.Settings.BedrockAPI, in.Settings.Fallback = BedrockRuntime, FallbackOff
	pi := all(tab(Setup(in), TabPodIdentity))
	for _, want := range []string{"bedrock:InvokeModelWithResponseStream", "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-5-5",
		"com.amazonaws.us-east-1.bedrock-runtime", "pods.eks.amazonaws.com", "sts:TagSession",
		"aws eks create-pod-identity-association --region us-east-1 --cluster-name prod-eks", "--service-account kubesentry"} {
		if !strings.Contains(pi, want) {
			t.Errorf("Pod Identity steps lack %q", want)
		}
	}
	if strings.Contains(pi, "anthropic.claude-opus-5\"") {
		t.Error("fallback off, but the fallback model is in the policy")
	}
	out := all(tab(Setup(in), TabOutsideEKS))
	for _, want := range []string{"aws sso login --profile <PROFILE>", "kubectl -n kubesentry create secret generic kubesentry-aws", "secretKeyRef"} {
		if !strings.Contains(out, want) {
			t.Errorf("outside-EKS steps lack %q", want)
		}
	}
	an := all(tab(Setup(in), TabAnthropic))
	for _, want := range []string{"kubesentry-anthropic", "existingSecret: kubesentry-anthropic", "api.anthropic.com"} {
		if !strings.Contains(an, want) {
			t.Errorf("Anthropic steps lack %q", want)
		}
	}
	for f, want := range map[[2]string]string{{"", "anthropic.claude-opus-5-5"}: "anthropic.claude-opus-5", {"auto", "arn:aws:bedrock:x"}: "",
		{"off", "anthropic.claude-opus-5-5"}: "", {"anthropic.claude-sonnet-5", "x"}: "anthropic.claude-sonnet-5"} {
		if got := BedrockFallback(f[0], f[1]); got != want {
			t.Errorf("BedrockFallback(%q, %q) = %q", f[0], f[1], got)
		}
	}
}
