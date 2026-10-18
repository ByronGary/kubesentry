package settings

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
)

// Credential sources, in the order the AWS SDK's default chain tries them
// (a Bedrock API key comes before all of them for Bedrock).
const (
	CredBedrockAPIKey = "bedrock-api-key" // AWS_BEARER_TOKEN_BEDROCK
	CredProfile       = "profile"         // AWS_PROFILE or the default profile (SSO included)
	CredEnvKeys       = "env-keys"        // AWS_ACCESS_KEY_ID, e.g. from a mounted Secret
	CredIRSA          = "irsa"            // AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE
	CredPodIdentity   = "pod-identity"    // AWS_CONTAINER_CREDENTIALS_FULL_URI (EKS Pod Identity)
	CredContainer     = "container"       // AWS_CONTAINER_CREDENTIALS_RELATIVE_URI (ECS task role)
	CredInstanceRole  = "instance-role"   // the EC2 instance profile, through IMDS
	CredNone          = "none"
)

// Credentials says where the AWS credentials come from, never what they
// are: only the kind and identifiers that are not secret.
type Credentials struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	// RoleARN is the IRSA role (AWS_ROLE_ARN), or the profile's role_arn.
	RoleARN string `json:"roleArn,omitempty"`
	// Profile is the shared-config profile in use.
	Profile string `json:"profile,omitempty"`
	// SSO is a profile that signs in through IAM Identity Center.
	SSO  bool   `json:"sso,omitempty"`
	Note string `json:"note,omitempty"`
	// AnthropicKey is true when ANTHROPIC_API_KEY is set.
	AnthropicKey bool `json:"anthropicKey"`
	// AccountID is the account of RoleARN, when there is one.
	AccountID string `json:"accountId,omitempty"`
}

// CredentialEnv is what DetectCredentials reads: the environment, the AWS
// shared config file (for profile names, SSO and role_arn only; the
// credentials file is never read), and whether files exist.
type CredentialEnv struct {
	Getenv   func(string) string
	ReadFile func(string) ([]byte, error)
	Exists   func(string) bool
	Home     string
}

func (e CredentialEnv) get(k string) string {
	if e.Getenv == nil {
		return ""
	}
	return strings.TrimSpace(e.Getenv(k))
}

func (e CredentialEnv) exists(p string) bool { return p != "" && e.Exists != nil && e.Exists(p) }

// DetectCredentials reports the credential source the AWS SDK would use, in
// its order: an explicit profile (AWS_PROFILE), environment keys, IRSA's web identity, the
// default profile, the container credentials (EKS Pod Identity, ECS), then
// the instance role. A Bedrock API key is reported first: Bedrock uses it
// instead of all of them.
func DetectCredentials(e CredentialEnv) Credentials {
	c := Credentials{AnthropicKey: e.get("ANTHROPIC_API_KEY") != ""}
	explicit := e.get("AWS_PROFILE")
	if explicit == "" {
		explicit = e.get("AWS_DEFAULT_PROFILE")
	}
	switch {
	case e.get("AWS_BEARER_TOKEN_BEDROCK") != "":
		c.Kind, c.Label = CredBedrockAPIKey, "Bedrock API key (AWS_BEARER_TOKEN_BEDROCK)"
		c.Note = "Bedrock uses this key instead of the IAM role; prefer the role (IRSA or Pod Identity)."
	case explicit != "":
		c.profile(e, explicit)
	case e.get("AWS_ACCESS_KEY_ID") != "":
		c.Kind, c.Label = CredEnvKeys, "Access keys in the environment (AWS_ACCESS_KEY_ID)"
		if e.get("AWS_SESSION_TOKEN") == "" {
			c.Note = "Long-lived keys: prefer a role (IRSA, Pod Identity) or SSO; rotate them if you keep them."
		}
	case e.get("AWS_ROLE_ARN") != "" && e.get("AWS_WEB_IDENTITY_TOKEN_FILE") != "":
		c.Kind, c.Label, c.RoleARN = CredIRSA, "IRSA (IAM role for the service account)", e.get("AWS_ROLE_ARN")
	case e.defaultProfile():
		c.profile(e, "default")
	case e.get("AWS_CONTAINER_CREDENTIALS_FULL_URI") != "":
		if e.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") != "" || strings.Contains(e.get("AWS_CONTAINER_CREDENTIALS_FULL_URI"), "169.254.170.23") {
			c.Kind, c.Label = CredPodIdentity, "EKS Pod Identity"
		} else {
			c.Kind, c.Label = CredContainer, "Container credentials (AWS_CONTAINER_CREDENTIALS_FULL_URI)"
		}
	case e.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "":
		c.Kind, c.Label = CredContainer, "Container credentials (ECS task role)"
	case !strings.EqualFold(e.get("AWS_EC2_METADATA_DISABLED"), "true"):
		c.Kind, c.Label = CredInstanceRole, "Instance role (EC2 instance metadata), if there is one"
		c.Note = "No other source is configured; the AWS SDK falls back to the node's instance profile. On EKS, give kubesentry its own role (IRSA or Pod Identity) instead."
	default:
		c.Kind, c.Label = CredNone, "No AWS credentials found"
	}
	c.AccountID = accountOf(c.RoleARN)
	return c
}

func (c *Credentials) profile(e CredentialEnv, name string) {
	c.Kind, c.Profile = CredProfile, name
	c.Label = "AWS profile " + name
	sec := e.profileSection(name)
	if sec["sso_session"] != "" || sec["sso_start_url"] != "" {
		c.SSO = true
		c.Label = "AWS profile " + name + " (IAM Identity Center / SSO)"
		c.Note = "Sign in with aws sso login --profile " + name + " before starting kubesentry; the session expires."
	}
	if r := sec["role_arn"]; strings.HasPrefix(r, "arn:") {
		c.RoleARN = r
	}
}

// configFile is the shared config file's path.
func (e CredentialEnv) configFile() string {
	if p := e.get("AWS_CONFIG_FILE"); p != "" {
		return p
	}
	if e.Home == "" {
		return ""
	}
	return filepath.Join(e.Home, ".aws", "config")
}

func (e CredentialEnv) credentialsFile() string {
	if p := e.get("AWS_SHARED_CREDENTIALS_FILE"); p != "" {
		return p
	}
	if e.Home == "" {
		return ""
	}
	return filepath.Join(e.Home, ".aws", "credentials")
}

// defaultProfile reports whether the shared files hold a default profile:
// a [default] section in the config file, or a credentials file (which is
// never opened).
func (e CredentialEnv) defaultProfile() bool {
	if e.exists(e.credentialsFile()) {
		return true
	}
	_, ok := e.sections()["default"]
	return ok
}

// profileSection is a profile's keys from the config file; only the keys
// kubesentry reports on (sso_*, role_arn) are kept.
func (e CredentialEnv) profileSection(name string) map[string]string {
	if s, ok := e.sections()[name]; ok {
		return s
	}
	return map[string]string{}
}

// sections parses the config file's profile sections, keeping only
// non-secret keys.
func (e CredentialEnv) sections() map[string]map[string]string {
	out := map[string]map[string]string{}
	p := e.configFile()
	if p == "" || e.ReadFile == nil || !e.exists(p) {
		return out
	}
	b, err := e.ReadFile(p)
	if err != nil {
		return out
	}
	keep := map[string]bool{"sso_session": true, "sso_start_url": true, "role_arn": true}
	var cur map[string]string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			name := strings.TrimSpace(line[1 : len(line)-1])
			name = strings.TrimSpace(strings.TrimPrefix(name, "profile "))
			if strings.HasPrefix(name, "sso-session ") || strings.HasPrefix(name, "services ") {
				cur = nil
				continue
			}
			cur = map[string]string{}
			out[name] = cur
		case cur != nil:
			k, v, ok := strings.Cut(line, "=")
			if k = strings.TrimSpace(k); ok && keep[k] {
				cur[k] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

// accountOf is the account ID in an IAM ARN.
func accountOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 && parts[0] == "arn" && len(parts[4]) == 12 {
		return parts[4]
	}
	return ""
}

// RoleName is the role's name in a role ARN (arn:aws:iam::1:role/path/name).
func RoleName(arn string) string {
	_, rest, ok := strings.Cut(arn, ":role/")
	if !ok {
		return ""
	}
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		return rest[i+1:]
	}
	return rest
}
