// Package settings holds kubesentry's settings that admins change at run
// time from the Settings page (docs/contracts.md "Settings (M7b)"): today the
// AI investigator. Flags (the Helm chart) give the initial values; in "ui"
// mode the values an admin saves win over them field by field, are stored in
// kubesentry's store (memory, or Postgres for every replica), audited (who,
// when, old → new) and applied live by every replica. In "locked" mode the
// flags are the only source and writes are refused.
//
// The package is stdlib only: it never reads secret values. It reports
// where the AWS credentials come from (DetectCredentials) and generates
// the setup steps for the environment kubesentry runs in (Setup).
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Providers, Bedrock APIs and fallback values (the same strings as
// internal/llm's; cmd/server checks that they agree).
const (
	ProviderAnthropic = "anthropic"
	ProviderBedrock   = "bedrock"
	BedrockMantle     = "mantle"
	BedrockRuntime    = "runtime"
	FallbackAuto      = "auto"
	FallbackOff       = "off"

	DefaultAnthropicModel = "claude-opus-5-5"
	DefaultBedrockModel   = "anthropic.claude-opus-5-5"
)

// Efforts the model takes (investigate.Efforts).
var Efforts = []string{"low", "medium", "high", "xhigh", "max"}

// Name is the stored settings' name.
const Name = "investigator"

// Investigator is the AI investigator's settings.
type Investigator struct {
	// Enabled turns the investigator on. It needs incidents, and the data
	// egress acknowledgement (from the platform, or by the admin enabling it).
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"` // anthropic or bedrock
	// Model is the model ID; empty takes the provider's default.
	Model  string `json:"model"`
	Effort string `json:"effort"`
	// Region is the Bedrock region; empty takes -aws-region, then AWS_REGION.
	Region     string `json:"region"`
	BedrockAPI string `json:"bedrockAPI"` // mantle or runtime
	// Endpoint overrides the model API's base URL (a VPC endpoint without
	// private DNS, or a proxy).
	Endpoint string `json:"endpoint"`
	Fallback string `json:"fallback"` // auto, off or a model ID
	Limits   Limits `json:"limits"`
}

// Limits are the investigator's quotas and budgets.
type Limits struct {
	PerHour      int      `json:"perHour"`
	PerHourTotal int      `json:"perHourTotal"`
	Concurrency  int      `json:"concurrency"`
	MaxTurns     int      `json:"maxTurns"`
	MaxToolCalls int      `json:"maxToolCalls"`
	MaxTokens    int64    `json:"maxTokens"`
	Timeout      Duration `json:"timeout"`
}

// ModelID is Model, or the provider's default.
func (s Investigator) ModelID() string {
	switch {
	case s.Model != "":
		return s.Model
	case s.Provider == ProviderBedrock:
		return DefaultBedrockModel
	}
	return DefaultAnthropicModel
}

// BedrockAPIOrDefault is BedrockAPI, or mantle.
func (s Investigator) BedrockAPIOrDefault() string {
	if s.BedrockAPI == "" {
		return BedrockMantle
	}
	return s.BedrockAPI
}

// RegionOr is Region, or def.
func (s Investigator) RegionOr(def string) string {
	if r := strings.TrimSpace(s.Region); r != "" {
		return r
	}
	return strings.TrimSpace(def)
}

// Duration is a time.Duration written as "10m", "90s" or "1h30m".
type Duration time.Duration

// String formats d without trailing zero units ("10m", not "10m0s").
func (d Duration) String() string {
	s := time.Duration(d).String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// UnmarshalJSON reads a Go duration string ("10m").
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("a duration such as \"10m\"")
	}
	v, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("duration %q: use a duration such as 10m or 1h", s)
	}
	*d = Duration(v)
	return nil
}

// Env is what validation needs to know about where kubesentry runs.
type Env struct {
	// Incidents is true when -incidents is on: the investigator needs it.
	Incidents bool
	// AnthropicKey is true when ANTHROPIC_API_KEY is set (never its value).
	AnthropicKey bool
	// DefaultRegion is -aws-region, then AWS_REGION and AWS_DEFAULT_REGION.
	DefaultRegion string
}

// FieldError is one invalid field: its name as in Fields ("limits.timeout")
// and what is wrong with it ("must be between 1m and 1h").
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e FieldError) Error() string { return e.Field + " " + e.Message }

// ValidationError lists every invalid field.
type ValidationError struct {
	Fields []FieldError `json:"fields"`
}

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		parts[i] = f.Error()
	}
	return strings.Join(parts, "; ")
}

var (
	modelRe  = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,200}$`)
	regionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$`)
)

// Validate checks the values (the rules of the -investigator* flags) and,
// when Enabled, what turning it on needs from the environment: incidents,
// the Anthropic API key for anthropic, a region for bedrock. It returns a
// *ValidationError or nil.
func (s Investigator) Validate(env Env) error {
	var errs []FieldError
	bad := func(field, msg string) { errs = append(errs, FieldError{Field: field, Message: msg}) }
	switch s.Provider {
	case ProviderAnthropic, ProviderBedrock:
	default:
		bad("provider", "must be anthropic or bedrock")
	}
	if s.Model != "" && !modelRe.MatchString(s.Model) {
		bad("model", "must be a model ID, an inference-profile ID or an ARN (letters, digits and . _ : / @ -)")
	}
	if !contains(Efforts, s.Effort) {
		bad("effort", "must be one of "+strings.Join(Efforts, ", "))
	}
	if s.Region != "" && !regionRe.MatchString(s.Region) {
		bad("region", "must be an AWS region such as us-east-1")
	}
	switch s.BedrockAPI {
	case "", BedrockMantle, BedrockRuntime:
	default:
		bad("bedrockAPI", "must be mantle or runtime")
	}
	if s.Endpoint != "" {
		if u, err := url.Parse(s.Endpoint); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			bad("endpoint", "must be an http(s) URL")
		}
	}
	if fb := strings.TrimSpace(s.Fallback); fb == "" {
		bad("fallback", "must be auto, off or a model ID")
	} else if fb != FallbackAuto && fb != FallbackOff && !modelRe.MatchString(fb) {
		bad("fallback", "must be auto, off or a model ID")
	}
	l := s.Limits
	if t := time.Duration(l.Timeout); t < time.Minute || t > time.Hour {
		bad("limits.timeout", "must be between 1m and 1h")
	}
	if l.MaxTurns < 1 || l.MaxTurns > 100 {
		bad("limits.maxTurns", "must be between 1 and 100")
	}
	if l.MaxToolCalls < 1 || l.MaxToolCalls > 200 {
		bad("limits.maxToolCalls", "must be between 1 and 200")
	}
	if l.MaxTokens < 10_000 || l.MaxTokens > 100_000_000 {
		bad("limits.maxTokens", "must be between 10000 and 100000000")
	}
	if l.PerHour < 1 || l.PerHour > 10_000 {
		bad("limits.perHour", "must be between 1 and 10000")
	}
	if l.PerHourTotal < 1 || l.PerHourTotal > 100_000 {
		bad("limits.perHourTotal", "must be between 1 and 100000")
	}
	if l.Concurrency < 1 || l.Concurrency > 100 {
		bad("limits.concurrency", "must be between 1 and 100")
	}
	if s.Enabled {
		switch {
		case !env.Incidents:
			bad("enabled", "needs incidents (-incidents, incidents.enabled): the investigator investigates incidents")
		case s.Provider == ProviderAnthropic && !env.AnthropicKey:
			bad("enabled", "needs the Anthropic API key in the ANTHROPIC_API_KEY environment variable, from a Kubernetes Secret (incidents.investigator.existingSecret)")
		case s.Provider == ProviderBedrock && s.RegionOr(env.DefaultRegion) == "":
			bad("region", "is needed for Bedrock: set it here, or -aws-region (eks.region)")
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return &ValidationError{Fields: errs}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
