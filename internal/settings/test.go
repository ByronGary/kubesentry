package settings

import "time"

// TestResult is a connection test's outcome (internal/llm's ProbeResult as
// the Settings page shows it): who kubesentry is to AWS, where the request
// went, and what failed. It never holds a provider's response body beyond
// the API's short error message.
type TestResult struct {
	OK       bool   `json:"ok"`
	Provider string `json:"provider"`
	Region   string `json:"region,omitempty"`
	Endpoint string `json:"endpoint"`
	Model    string `json:"model"`
	// IdentityARN is STS GetCallerIdentity's ARN (Bedrock).
	IdentityARN string `json:"identityArn,omitempty"`
	Account     string `json:"account,omitempty"`
	// CredentialSource is the detected credential kind (Credentials.Kind).
	CredentialSource string     `json:"credentialSource,omitempty"`
	LatencyMs        int64      `json:"latencyMs"`
	At               time.Time  `json:"at"`
	Error            *TestError `json:"error,omitempty"`
}

// TestError says what failed and what to do.
type TestError struct {
	// Kind: no_credentials, access_denied, model_access,
	// model_unavailable, network, auth, throttled, config, other.
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	// Action is the denied IAM action, when known.
	Action string `json:"action,omitempty"`
	Status int    `json:"status,omitempty"`
}
