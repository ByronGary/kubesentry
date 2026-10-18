package settings

import (
	"errors"
	"strings"
	"testing"
)

func credEnv(env map[string]string, files map[string]string) CredentialEnv {
	return CredentialEnv{
		Getenv: func(k string) string { return env[k] },
		ReadFile: func(p string) ([]byte, error) {
			if p == "/home/u/.aws/credentials" {
				panic("the credentials file must never be read")
			}
			if s, ok := files[p]; ok {
				return []byte(s), nil
			}
			return nil, errors.New("no such file")
		},
		Exists: func(p string) bool { _, ok := files[p]; return ok },
		Home:   "/home/u",
	}
}

const ssoConfig = `# comment
[default]
region = us-east-1
[profile platform-admin]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = Admin
[profile deploy]
role_arn = arn:aws:iam::444455556666:role/deployer
source_profile = default
[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
`

func TestDetectCredentials(t *testing.T) {
	const roleARN = "arn:aws:iam::111122223333:role/kubesentry"
	for _, tc := range []struct {
		name  string
		env   map[string]string
		files map[string]string
		want  Credentials
	}{
		{"irsa", map[string]string{"AWS_ROLE_ARN": roleARN, "AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"}, nil,
			Credentials{Kind: CredIRSA, RoleARN: roleARN, AccountID: "111122223333"}},
		{"pod identity", map[string]string{"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials",
			"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token"}, nil,
			Credentials{Kind: CredPodIdentity}},
		{"ecs", map[string]string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/x"}, nil, Credentials{Kind: CredContainer}},
		{"env keys", map[string]string{"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_SECRET_ACCESS_KEY": "secret"}, nil, Credentials{Kind: CredEnvKeys}},
		// Keys beat IRSA, as in the SDK's chain.
		{"keys over irsa", map[string]string{"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_ROLE_ARN": roleARN, "AWS_WEB_IDENTITY_TOKEN_FILE": "/t"}, nil,
			Credentials{Kind: CredEnvKeys}},
		{"sso profile", map[string]string{"AWS_PROFILE": "platform-admin"}, map[string]string{"/home/u/.aws/config": ssoConfig},
			Credentials{Kind: CredProfile, Profile: "platform-admin", SSO: true}},
		// An explicit profile beats the keys.
		{"profile over keys", map[string]string{"AWS_PROFILE": "deploy", "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE"}, map[string]string{"/home/u/.aws/config": ssoConfig},
			Credentials{Kind: CredProfile, Profile: "deploy", RoleARN: "arn:aws:iam::444455556666:role/deployer", AccountID: "444455556666"}},
		{"config file from env", map[string]string{"AWS_DEFAULT_PROFILE": "platform-admin", "AWS_CONFIG_FILE": "/etc/aws.conf"},
			map[string]string{"/etc/aws.conf": ssoConfig}, Credentials{Kind: CredProfile, Profile: "platform-admin", SSO: true}},
		{"default profile from the credentials file", nil, map[string]string{"/home/u/.aws/credentials": "never read"},
			Credentials{Kind: CredProfile, Profile: "default"}},
		{"default profile from the config", nil, map[string]string{"/home/u/.aws/config": ssoConfig}, Credentials{Kind: CredProfile, Profile: "default"}},
		{"bedrock api key", map[string]string{"AWS_BEARER_TOKEN_BEDROCK": "bedrock-key", "AWS_ROLE_ARN": roleARN}, nil, Credentials{Kind: CredBedrockAPIKey}},
		{"instance role", nil, nil, Credentials{Kind: CredInstanceRole}},
		{"none", map[string]string{"AWS_EC2_METADATA_DISABLED": "true"}, nil, Credentials{Kind: CredNone}},
		{"anthropic key", map[string]string{"AWS_EC2_METADATA_DISABLED": "true", "ANTHROPIC_API_KEY": "sk-ant-x"}, nil, Credentials{Kind: CredNone, AnthropicKey: true}},
	} {
		got := DetectCredentials(credEnv(tc.env, tc.files))
		if got.Kind != tc.want.Kind || got.RoleARN != tc.want.RoleARN || got.Profile != tc.want.Profile || got.SSO != tc.want.SSO ||
			got.AccountID != tc.want.AccountID || got.AnthropicKey != tc.want.AnthropicKey || got.Label == "" {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
		// Never a secret value.
		for _, secret := range []string{"secret", "AKIAEXAMPLE", "bedrock-key", "sk-ant-x", "never read"} {
			for _, s := range []string{got.Label, got.Note, got.RoleARN, got.Profile} {
				if strings.Contains(s, secret) {
					t.Errorf("%s: reports %q", tc.name, secret)
				}
			}
		}
	}
	if RoleName("arn:aws:iam::1:role/path/to/kubesentry") != "kubesentry" || RoleName("nope") != "" {
		t.Error("RoleName")
	}
}
