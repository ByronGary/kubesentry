package settings

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Where kubesentry runs (Environment.Kind).
const (
	EnvEKS        = "eks"        // in a pod of an EKS cluster
	EnvKubernetes = "kubernetes" // in a pod of another cluster
	EnvRemote     = "remote"     // outside the cluster: a laptop (-kube-context, -eks-cluster), EC2, ECS
)

// Environment is where kubesentry runs, as far as it knows.
type Environment struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	// Cluster is -cluster-name (or -eks-cluster).
	Cluster  string `json:"cluster,omitempty"`
	Region   string `json:"region,omitempty"`
	Platform string `json:"platform,omitempty"`
	// Namespace and ServiceAccount are kubesentry's own, in the cluster.
	Namespace      string `json:"namespace,omitempty"`
	ServiceAccount string `json:"serviceAccount,omitempty"`
	KubeContext    string `json:"kubeContext,omitempty"`
	// OIDCIssuer is the cluster's OIDC issuer URL, when known.
	OIDCIssuer string `json:"oidcIssuer,omitempty"`
}

// EnvironmentLabel is a readable name for a kind.
func EnvironmentLabel(kind string) string {
	switch kind {
	case EnvEKS:
		return "In-cluster on Amazon EKS"
	case EnvKubernetes:
		return "In-cluster (not EKS)"
	case EnvRemote:
		return "Outside the cluster (remote mode)"
	}
	return "Unknown"
}

// Setup tabs.
const (
	TabIRSA        = "irsa"
	TabPodIdentity = "pod-identity"
	TabOutsideEKS  = "outside-eks"
	TabAnthropic   = "anthropic"
)

// Guide is the generated setup steps, one tab per way to connect.
type Guide struct {
	// Recommended is the tab for the detected environment and provider.
	Recommended string `json:"recommended"`
	Tabs        []Tab  `json:"tabs"`
}

// Tab is one way to set the investigator up.
type Tab struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Steps   []Step `json:"steps"`
}

// Step is one instruction, with an optional block to copy.
type Step struct {
	Title string `json:"title"`
	Text  string `json:"text"`
	Code  string `json:"code,omitempty"`
	// Lang is json, yaml or shell.
	Lang string `json:"lang,omitempty"`
}

// SetupInput is what the guide is generated from.
type SetupInput struct {
	Env      Environment
	Creds    Credentials
	Settings Investigator
	// DefaultRegion is -aws-region, then AWS_REGION.
	DefaultRegion string
}

// Placeholders the guide leaves for the reader.
const (
	phAccount  = "<ACCOUNT_ID>"
	phRegion   = "<REGION>"
	phCluster  = "<CLUSTER>"
	phIssuer   = "<OIDC_ISSUER>"
	phVPC      = "<VPC_ID>"
	phSubnets  = "<PRIVATE_SUBNET_IDS>"
	phEndpoint = "<ENDPOINT_SG_ID>"
	phNodeSG   = "<NODE_SG_ID>"
	phProfile  = "<PROFILE>"
)

// setup is the guide's derived names.
type setup struct {
	in                   SetupInput
	region, account      string
	cluster, ns, sa      string
	roleName, roleARN    string
	issuer               string
	issuerKnown          bool
	api, model, fallback string
	profile              string
}

func newSetup(in SetupInput) setup {
	s := setup{in: in}
	s.region = in.Settings.RegionOr(in.DefaultRegion)
	if s.region == "" {
		s.region = in.Env.Region
	}
	if s.region == "" {
		s.region = phRegion
	}
	s.account = in.Creds.AccountID
	if s.account == "" {
		s.account = phAccount
	}
	s.cluster = or(in.Env.Cluster, phCluster)
	s.ns = or(in.Env.Namespace, "kubesentry")
	s.sa = or(in.Env.ServiceAccount, "kubesentry")
	s.roleName = or(RoleName(in.Creds.RoleARN), "kubesentry-investigator")
	s.roleARN = in.Creds.RoleARN
	if s.roleARN == "" {
		s.roleARN = "arn:aws:iam::" + s.account + ":role/" + s.roleName
	}
	if iss := strings.TrimPrefix(strings.TrimPrefix(in.Env.OIDCIssuer, "https://"), "http://"); iss != "" {
		s.issuer, s.issuerKnown = iss, true
	} else {
		s.issuer = phIssuer
	}
	s.api = in.Settings.BedrockAPIOrDefault()
	s.model = DefaultBedrockModel
	if in.Settings.Provider == ProviderBedrock && in.Settings.Model != "" {
		s.model = in.Settings.Model
	}
	s.fallback = BedrockFallback(in.Settings.Fallback, s.model)
	s.profile = or(in.Creds.Profile, phProfile)
	return s
}

func or(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// BedrockFallback is the refusal fallback model on Bedrock: a model ID
// given, or with auto Claude Opus 5 in the form of a Claude Opus 5.5 ID
// (internal/llm's rule); "" for none.
func BedrockFallback(fallback, model string) string {
	switch fb := strings.TrimSpace(fallback); fb {
	case FallbackOff:
		return ""
	case "", FallbackAuto:
		const opus55, opus5 = "claude-opus-5-5", "claude-opus-5"
		if strings.HasPrefix(model, "arn:") || !strings.HasSuffix(model, opus55) {
			return ""
		}
		return strings.TrimSuffix(model, opus55) + opus5
	default:
		return fb
	}
}

// Setup generates the steps for every tab, and recommends the one for the
// environment, the credentials and the provider.
func Setup(in SetupInput) Guide {
	s := newSetup(in)
	g := Guide{Tabs: []Tab{s.irsaTab(), s.podIdentityTab(), s.outsideTab(), s.anthropicTab()}}
	switch {
	case in.Settings.Provider == ProviderAnthropic:
		g.Recommended = TabAnthropic
	case in.Env.Kind != EnvEKS:
		g.Recommended = TabOutsideEKS
	case in.Creds.Kind == CredPodIdentity:
		g.Recommended = TabPodIdentity
	default:
		g.Recommended = TabIRSA
	}
	return g
}

// ---- policies ----

type policy struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

type statement struct {
	Sid       string         `json:"Sid,omitempty"`
	Effect    string         `json:"Effect"`
	Principal map[string]any `json:"Principal,omitempty"`
	Action    any            `json:"Action"`
	Resource  any            `json:"Resource,omitempty"`
	Condition map[string]any `json:"Condition,omitempty"`
}

func pretty(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false) // keep the <PLACEHOLDERS> readable
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// models are the models the policies name: the model and its fallback.
func (s setup) models() []string {
	if s.fallback == "" || s.fallback == s.model {
		return []string{s.model}
	}
	return []string{s.model, s.fallback}
}

// inferenceProfilePrefixes are the geographic prefixes of cross-Region
// inference profile IDs.
var inferenceProfilePrefixes = []string{"us.", "eu.", "apac.", "jp.", "au.", "ca.", "us-gov.", "global."}

// runtimeResources are the ARNs bedrock-runtime checks for the models.
func (s setup) runtimeResources() []string {
	var out []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, m := range s.models() {
		if strings.HasPrefix(m, "arn:") {
			add(m)
			continue
		}
		base, profile := m, false
		for _, p := range inferenceProfilePrefixes {
			if strings.HasPrefix(m, p) {
				base, profile = strings.TrimPrefix(m, p), true
				break
			}
		}
		if profile {
			add("arn:aws:bedrock:" + s.region + ":" + s.account + ":inference-profile/" + m)
			add("arn:aws:bedrock:*::foundation-model/" + base)
		} else {
			add("arn:aws:bedrock:" + s.region + "::foundation-model/" + m)
		}
	}
	return out
}

// inference is the statement that lets the role call the model.
func (s setup) inference(principal bool) statement {
	var st statement
	if s.api == BedrockRuntime {
		st = statement{Sid: "KubesentryInvestigatorBedrockRuntime", Effect: "Allow",
			Action:   []string{"bedrock:InvokeModelWithResponseStream", "bedrock:InvokeModel"},
			Resource: s.runtimeResources()}
	} else {
		st = statement{Sid: "KubesentryInvestigatorBedrockMantle", Effect: "Allow",
			Action:    []string{"bedrock-mantle:CreateInference"},
			Resource:  "arn:aws:bedrock-mantle:" + s.region + ":" + s.account + ":project/*",
			Condition: map[string]any{"StringLike": map[string]any{"bedrock-mantle:Model": s.models()}}}
	}
	if principal {
		st.Principal = map[string]any{"AWS": s.roleARN}
	}
	return st
}

func (s setup) rolePolicy() string {
	return pretty(policy{Version: "2012-10-17", Statement: []statement{s.inference(false)}})
}

func (s setup) endpointPolicy() string {
	return pretty(policy{Version: "2012-10-17", Statement: []statement{s.inference(true)}})
}

func (s setup) irsaTrust() string {
	return pretty(policy{Version: "2012-10-17", Statement: []statement{{
		Effect:    "Allow",
		Principal: map[string]any{"Federated": "arn:aws:iam::" + s.account + ":oidc-provider/" + s.issuer},
		Action:    "sts:AssumeRoleWithWebIdentity",
		Condition: map[string]any{"StringEquals": map[string]any{
			s.issuer + ":sub": "system:serviceaccount:" + s.ns + ":" + s.sa,
			s.issuer + ":aud": "sts.amazonaws.com",
		}},
	}}})
}

func (s setup) podIdentityTrust() string {
	return pretty(policy{Version: "2012-10-17", Statement: []statement{{
		Sid: "AllowEksAuthToAssumeRoleForPodIdentity", Effect: "Allow",
		Principal: map[string]any{"Service": "pods.eks.amazonaws.com"},
		Action:    []string{"sts:AssumeRole", "sts:TagSession"},
	}}})
}

// ---- shared steps ----

func (s setup) serviceName() string {
	if s.api == BedrockRuntime {
		return "com.amazonaws." + s.region + ".bedrock-runtime"
	}
	return "com.amazonaws." + s.region + ".bedrock-mantle"
}

func (s setup) hostname() string {
	if s.api == BedrockRuntime {
		return "bedrock-runtime." + s.region + ".amazonaws.com"
	}
	return "bedrock-mantle." + s.region + ".api.aws"
}

func (s setup) modelAccess() Step {
	text := "In the Amazon Bedrock console of " + s.region + ", open Model access and request Anthropic's Claude Opus 5.5 (" + s.model + ")."
	if s.fallback != "" {
		text += " The refusal fallback uses " + s.fallback + ": request it too, or set the fallback to off."
	}
	text += " The first Anthropic model in an account also asks for the use-case form."
	return Step{Title: "Enable model access", Text: text}
}

func (s setup) rolePolicyStep() Step {
	action := "bedrock-mantle:CreateInference on the account's Mantle projects"
	if s.api == BedrockRuntime {
		action = "bedrock:InvokeModelWithResponseStream on the model and inference-profile ARNs"
	}
	return Step{Title: "Role policy", Text: "kubesentry's role needs " + action + " (Bedrock API: " + s.api + "). Save it as investigator-policy.json.",
		Code: s.rolePolicy(), Lang: "json"}
}

func (s setup) vpcEndpointSteps() []Step {
	return []Step{
		{Title: "Find the cluster's network", Text: "The VPC, the private subnets of the nodes and the cluster security group.",
			Code: "aws eks describe-cluster --name " + s.cluster + " --region " + s.region +
				" \\\n  --query 'cluster.resourcesVpcConfig.{vpc:vpcId,subnets:subnetIds,clusterSG:clusterSecurityGroupId}'", Lang: "shell"},
		{Title: "Endpoint security group", Text: "Allow HTTPS (TCP 443) into the endpoint from the nodes (or from the pods' security group with security groups for pods).",
			Code: "aws ec2 create-security-group --region " + s.region + " --vpc-id " + phVPC +
				" \\\n  --group-name kubesentry-bedrock-endpoint --description 'Bedrock endpoint for kubesentry'\n" +
				"aws ec2 authorize-security-group-ingress --region " + s.region + " --group-id " + phEndpoint +
				" \\\n  --protocol tcp --port 443 --source-group " + phNodeSG, Lang: "shell"},
		{Title: "Endpoint policy", Text: "Only kubesentry's role, only the inference action and the models. Save it as endpoint-policy.json.",
			Code: s.endpointPolicy(), Lang: "json"},
		{Title: "Create the interface VPC endpoint", Text: "Service " + s.serviceName() + " in the nodes' private subnets, with private DNS on: " +
			s.hostname() + " then resolves to private addresses inside the VPC, so no endpoint override is needed and no traffic leaves the VPC.",
			Code: "aws ec2 create-vpc-endpoint --region " + s.region + " --vpc-id " + phVPC + " \\\n  --vpc-endpoint-type Interface --service-name " +
				s.serviceName() + " \\\n  --subnet-ids " + phSubnets + " --security-group-ids " + phEndpoint +
				" \\\n  --private-dns-enabled --policy-document file://endpoint-policy.json", Lang: "shell"},
	}
}

func (s setup) createRole(trustFile string) Step {
	return Step{Title: "Create the role", Text: "Create the role with the trust policy and attach the inference policy.",
		Code: "aws iam create-role --role-name " + s.roleName + " \\\n  --assume-role-policy-document file://" + trustFile + "\n" +
			"aws iam put-role-policy --role-name " + s.roleName + " --policy-name kubesentry-investigator \\\n  --policy-document file://investigator-policy.json",
		Lang: "shell"}
}

func (s setup) testStep() Step {
	return Step{Title: "Test the connection", Text: "Restart kubesentry so its pods pick up the role (kubectl -n " + s.ns +
		" rollout restart deployment), then press Test connection above: it shows the role kubesentry runs as and sends a one-token request to the model. Turn the investigator on when it passes."}
}

func (s setup) bedrockValues(extra string) string {
	v := extra
	v += "incidents:\n  enabled: true\n  investigator:\n    provider: bedrock\n    bedrockAPI: " + s.api + "\n"
	if s.region != phRegion {
		v += "    region: " + s.region + "\n"
	}
	v += "    # enabled: true and acknowledgeDataEgress: true here, or turn it on in Settings\n" +
		"    # settings: locked   # GitOps: Helm is the only source, the Settings page is read-only\n"
	return v
}

// ---- tabs ----

func (s setup) irsaTab() Tab {
	issuer := Step{Title: "The cluster's OIDC issuer", Text: "IRSA trusts the cluster's OIDC provider."}
	if s.issuerKnown {
		issuer.Text += " The issuer is " + s.issuer + "."
	} else {
		issuer.Text += " kubesentry does not know it: look it up, and replace " + phIssuer + " below with it (without https://). " +
			"Create the IAM OIDC provider once per cluster if it does not exist (eksctl utils associate-iam-oidc-provider)."
		issuer.Code = "aws eks describe-cluster --name " + s.cluster + " --region " + s.region +
			" \\\n  --query cluster.identity.oidc.issuer --output text"
		issuer.Lang = "shell"
	}
	steps := []Step{s.modelAccess()}
	steps = append(steps, s.vpcEndpointSteps()...)
	steps = append(steps, s.rolePolicyStep(), issuer,
		Step{Title: "Trust policy (IRSA)", Text: "Only kubesentry's service account " + s.ns + "/" + s.sa + " may assume the role. Save it as trust-irsa.json.",
			Code: s.irsaTrust(), Lang: "json"},
		s.createRole("trust-irsa.json"),
		Step{Title: "Helm values", Text: "Annotate kubesentry's service account with the role.",
			Code: s.bedrockValues("serviceAccount:\n  annotations:\n    eks.amazonaws.com/role-arn: " + s.roleARN + "\n"), Lang: "yaml"},
		s.testStep())
	return Tab{ID: TabIRSA, Title: "EKS: IRSA",
		Summary: "No keys: kubesentry's service account assumes an IAM role through the cluster's OIDC provider, and reaches Bedrock through a VPC endpoint.",
		Steps:   steps}
}

func (s setup) podIdentityTab() Tab {
	steps := []Step{s.modelAccess()}
	steps = append(steps, s.vpcEndpointSteps()...)
	steps = append(steps, s.rolePolicyStep(),
		Step{Title: "Trust policy (Pod Identity)", Text: "The EKS Pod Identity service assumes the role for the pod. Save it as trust-pod-identity.json.",
			Code: s.podIdentityTrust(), Lang: "json"},
		s.createRole("trust-pod-identity.json"),
		Step{Title: "Associate the role with kubesentry's service account",
			Text: "Needs the Amazon EKS Pod Identity Agent add-on (and, in private clusters, the com.amazonaws." + s.region + ".eks-auth endpoint). No annotation is needed.",
			Code: "aws eks create-pod-identity-association --region " + s.region + " --cluster-name " + s.cluster +
				" \\\n  --namespace " + s.ns + " --service-account " + s.sa + " \\\n  --role-arn " + s.roleARN, Lang: "shell"},
		Step{Title: "Helm values", Text: "Nothing to add for the role; point the investigator at Bedrock.", Code: s.bedrockValues(""), Lang: "yaml"},
		s.testStep())
	return Tab{ID: TabPodIdentity, Title: "EKS: Pod Identity",
		Summary: "No keys: an EKS Pod Identity association gives kubesentry's service account an IAM role; Bedrock through a VPC endpoint.",
		Steps:   steps}
}

func (s setup) outsideTab() Tab {
	ctx := or(s.in.Env.KubeContext, "<KUBE_CONTEXT>")
	steps := []Step{s.modelAccess(),
		Step{Title: "Grant your identity the inference action",
			Text: "From a laptop kubesentry calls Bedrock as you: add this statement to your IAM Identity Center permission set (or the role your profile assumes).",
			Code: s.rolePolicy(), Lang: "json"},
		Step{Title: "Sign in with your AWS profile", Text: "Remote mode reads the AWS profile like the AWS CLI does; with IAM Identity Center, sign in first. The session expires: sign in again when Test connection says the credentials expired.",
			Code: "aws sso login --profile " + s.profile + "\nexport AWS_PROFILE=" + s.profile, Lang: "shell"},
		Step{Title: "Run kubesentry", Text: "Remote mode, with incidents on; then turn the investigator on in Settings, or with flags.",
			Code: "kubesentry -kube-context " + ctx + " -incidents -aws-region " + s.region +
				" \\\n  -investigator-bedrock-api " + s.api, Lang: "shell"},
		Step{Title: "Other clusters: a Kubernetes Secret",
			Text: "In a cluster outside AWS there is no pod role. Prefer short-lived credentials (IAM Roles Anywhere); otherwise put a dedicated, least-privilege user's keys in a Secret you manage and rotate. kubesentry never stores them: the chart mounts them as environment variables.",
			Code: "kubectl -n " + s.ns + " create secret generic kubesentry-aws \\\n  --from-literal=AWS_ACCESS_KEY_ID=\"$AWS_ACCESS_KEY_ID\" \\\n  --from-literal=AWS_SECRET_ACCESS_KEY=\"$AWS_SECRET_ACCESS_KEY\"",
			Lang: "shell"},
		Step{Title: "Helm values for the Secret", Text: "The server reads the keys from its environment.",
			Code: "extraEnv:\n  - name: AWS_ACCESS_KEY_ID\n    valueFrom:\n      secretKeyRef: {name: kubesentry-aws, key: AWS_ACCESS_KEY_ID}\n" +
				"  - name: AWS_SECRET_ACCESS_KEY\n    valueFrom:\n      secretKeyRef: {name: kubesentry-aws, key: AWS_SECRET_ACCESS_KEY}\n" +
				s.bedrockValues(""), Lang: "yaml"},
		Step{Title: "Test the connection", Text: "Press Test connection above: it shows the identity kubesentry runs as and sends a one-token request to the model."},
	}
	return Tab{ID: TabOutsideEKS, Title: "Outside EKS",
		Summary: "From a laptop (remote mode) with your AWS profile or SSO sign-in, or in another cluster with a Kubernetes Secret the chart mounts.",
		Steps:   steps}
}

func (s setup) anthropicTab() Tab {
	key := "The key comes only from the ANTHROPIC_API_KEY environment variable, set from a Kubernetes Secret: kubesentry never stores it and the Settings page never takes it."
	if s.in.Creds.AnthropicKey {
		key += " ANTHROPIC_API_KEY is set in this server's environment."
	} else {
		key += " ANTHROPIC_API_KEY is not set in this server's environment yet."
	}
	steps := []Step{
		{Title: "Create the Secret", Text: key,
			Code: "kubectl -n " + s.ns + " create secret generic kubesentry-anthropic \\\n  --from-literal=api-key=\"$ANTHROPIC_API_KEY\"", Lang: "shell"},
		{Title: "Helm values", Text: "The chart sets ANTHROPIC_API_KEY from the Secret. Restart kubesentry after the first install of the Secret.",
			Code: "incidents:\n  enabled: true\n  investigator:\n    provider: anthropic\n    existingSecret: kubesentry-anthropic\n    # apiKeyKey: api-key\n", Lang: "yaml"},
		{Title: "Network", Text: "The pods need egress on 443 to api.anthropic.com (an egress proxy through HTTPS_PROXY in extraEnv works). Requests leave your network: the recommended setup is Bedrock through a VPC endpoint."},
		{Title: "Test the connection", Text: "Choose the Anthropic API as the provider above, save, and press Test connection: a missing or wrong key answers 401."},
	}
	if s.in.Env.Kind == EnvRemote {
		steps[0] = Step{Title: "Set the key", Text: "In remote mode kubesentry reads ANTHROPIC_API_KEY from the shell that starts it; never type it into the Settings page.",
			Code: "export ANTHROPIC_API_KEY=… # from your secret store", Lang: "shell"}
		steps[1] = Step{Title: "Run kubesentry", Text: "With incidents on; then choose the Anthropic API in Settings.",
			Code: fmt.Sprintf("kubesentry -kube-context %s -incidents", or(s.in.Env.KubeContext, "<KUBE_CONTEXT>")), Lang: "shell"}
	}
	return Tab{ID: TabAnthropic, Title: "Anthropic API",
		Summary: "The alternative: Claude on the Anthropic API with an API key from a Kubernetes Secret.", Steps: steps}
}
