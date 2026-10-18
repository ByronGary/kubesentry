package settings

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// helmDefaults are the flags' defaults with Bedrock.
func helmDefaults() Investigator {
	return Investigator{Provider: ProviderBedrock, Effort: "high", BedrockAPI: BedrockMantle, Fallback: FallbackAuto,
		Limits: Limits{PerHour: 10, PerHourTotal: 60, Concurrency: 2, MaxTurns: 16, MaxToolCalls: 24, MaxTokens: 1_500_000,
			Timeout: Duration(10 * time.Minute)}}
}

var okEnv = Env{Incidents: true, AnthropicKey: true, DefaultRegion: "us-east-1"}

func fieldsOf(err error) []string {
	var ve *ValidationError
	if !errors.As(err, &ve) {
		return nil
	}
	var out []string
	for _, f := range ve.Fields {
		out = append(out, f.Field)
	}
	return out
}

func TestValidate(t *testing.T) {
	if err := helmDefaults().Validate(Env{}); err != nil {
		t.Fatalf("defaults, off: %v", err)
	}
	on := helmDefaults()
	on.Enabled = true
	if err := on.Validate(okEnv); err != nil {
		t.Fatalf("on: %v", err)
	}
	for name, tc := range map[string]struct {
		mut  func(*Investigator)
		env  Env
		want string
	}{
		"provider":       {func(i *Investigator) { i.Provider = "openai" }, okEnv, "provider"},
		"effort":         {func(i *Investigator) { i.Effort = "extreme" }, okEnv, "effort"},
		"model":          {func(i *Investigator) { i.Model = "claude opus" }, okEnv, "model"},
		"region":         {func(i *Investigator) { i.Region = "Mars-1" }, okEnv, "region"},
		"api":            {func(i *Investigator) { i.BedrockAPI = "converse" }, okEnv, "bedrockAPI"},
		"endpoint":       {func(i *Investigator) { i.Endpoint = "ftp://proxy" }, okEnv, "endpoint"},
		"endpoint creds": {func(i *Investigator) { i.Endpoint = "https://u:p@proxy" }, okEnv, "endpoint"},
		"fallback":       {func(i *Investigator) { i.Fallback = " " }, okEnv, "fallback"},
		"timeout":        {func(i *Investigator) { i.Limits.Timeout = Duration(30 * time.Second) }, okEnv, "limits.timeout"},
		"turns":          {func(i *Investigator) { i.Limits.MaxTurns = 0 }, okEnv, "limits.maxTurns"},
		"tools":          {func(i *Investigator) { i.Limits.MaxToolCalls = 201 }, okEnv, "limits.maxToolCalls"},
		"tokens":         {func(i *Investigator) { i.Limits.MaxTokens = 10 }, okEnv, "limits.maxTokens"},
		"per hour":       {func(i *Investigator) { i.Limits.PerHour = 0 }, okEnv, "limits.perHour"},
		"total":          {func(i *Investigator) { i.Limits.PerHourTotal = 0 }, okEnv, "limits.perHourTotal"},
		"concurrency":    {func(i *Investigator) { i.Limits.Concurrency = 0 }, okEnv, "limits.concurrency"},
		"no incidents":   {func(i *Investigator) {}, Env{AnthropicKey: true, DefaultRegion: "us-east-1"}, "enabled"},
		"no key":         {func(i *Investigator) { i.Provider = ProviderAnthropic }, Env{Incidents: true}, "enabled"},
		"no region":      {func(i *Investigator) {}, Env{Incidents: true}, "region"},
	} {
		v := on
		tc.mut(&v)
		got := fieldsOf(v.Validate(tc.env))
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s: invalid fields %v, want [%s]", name, got, tc.want)
		}
	}
	// The region of the settings themselves is enough; a key is not needed
	// for Bedrock.
	v := on
	v.Region = "eu-west-1"
	if err := v.Validate(Env{Incidents: true}); err != nil {
		t.Errorf("region in the settings: %v", err)
	}
	// Off, the environment does not matter.
	v.Enabled, v.Provider = false, ProviderAnthropic
	if err := v.Validate(Env{}); err != nil {
		t.Errorf("off: %v", err)
	}
	err := Investigator{}.Validate(Env{})
	if !strings.Contains(err.Error(), "provider must be anthropic or bedrock") {
		t.Errorf("message %q", err)
	}
}

func TestDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{10 * time.Minute: "10m", 90 * time.Second: "1m30s", time.Hour: "1h", 90 * time.Minute: "1h30m", 45 * time.Second: "45s"} {
		if got := Duration(d).String(); got != want {
			t.Errorf("%v = %q, want %q", d, got, want)
		}
		b, _ := json.Marshal(Duration(d))
		var back Duration
		if err := json.Unmarshal(b, &back); err != nil || time.Duration(back) != d {
			t.Errorf("round trip %s: %v %v", b, back, err)
		}
	}
	var d Duration
	for _, bad := range []string{`600`, `"ten minutes"`, `null`} {
		if err := json.Unmarshal([]byte(bad), &d); err == nil && bad != `null` {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestModelAndRegionDefaults(t *testing.T) {
	i := Investigator{Provider: ProviderBedrock}
	if i.ModelID() != DefaultBedrockModel || i.BedrockAPIOrDefault() != BedrockMantle || i.RegionOr(" eu-west-1 ") != "eu-west-1" {
		t.Errorf("bedrock defaults %q %q", i.ModelID(), i.BedrockAPIOrDefault())
	}
	i.Provider = ProviderAnthropic
	if i.ModelID() != DefaultAnthropicModel {
		t.Errorf("anthropic default %q", i.ModelID())
	}
	i.Model, i.Region = "us.anthropic.claude-opus-5-5", "us-west-2"
	if i.ModelID() != "us.anthropic.claude-opus-5-5" || i.RegionOr("eu-west-1") != "us-west-2" {
		t.Errorf("given %q %q", i.ModelID(), i.RegionOr(""))
	}
}

func TestPrecedence(t *testing.T) {
	helm := helmDefaults()
	at := time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)
	eff, src := Effective(helm, nil)
	if len(Changes(eff, helm)) != 0 || src["model"].Source != SourceHelm || len(src) != len(Fields()) {
		t.Fatalf("nothing stored: %+v %v", eff, src)
	}
	// alice turns it on and picks a model.
	next := helm
	next.Enabled, next.Model = true, "us.anthropic.claude-opus-5-5"
	st, ch := Save(helm, nil, next, "alice", at)
	if len(ch) != 2 || ch[0] != (Change{Field: "enabled", Old: "false", New: "true"}) || ch[1].Field != "model" || ch[1].New != "us.anthropic.claude-opus-5-5" {
		t.Errorf("changes %+v", ch)
	}
	if len(st.Fields) != 2 || st.Fields["model"].By != "alice" {
		t.Errorf("overrides %+v", st.Fields)
	}
	// Helm moves on: a field the UI never touched follows it; an
	// overridden one keeps the UI's value.
	helm2 := helm
	helm2.Effort, helm2.Model = "max", "anthropic.claude-opus-5-5"
	eff, src = Effective(helm2, st)
	if eff.Effort != "max" || eff.Model != "us.anthropic.claude-opus-5-5" || !eff.Enabled || src["effort"].Source != SourceHelm ||
		src["model"].Source != SourceUI || src["model"].By != "alice" || !src["model"].At.Equal(at) {
		t.Errorf("after the Helm change: %+v %+v", eff, src)
	}
	// bob changes the timeout only: alice's marks stay; a field set back to
	// its Helm value follows Helm again.
	next = eff
	next.Limits.Timeout = Duration(20 * time.Minute)
	next.Model = helm2.Model
	st2, ch := Save(helm2, st, next, "bob", at.Add(time.Hour))
	if len(ch) != 2 || st2.Fields["enabled"].By != "alice" || st2.Fields["limits.timeout"].By != "bob" {
		t.Errorf("bob: changes %+v marks %+v", ch, st2.Fields)
	}
	if _, ok := st2.Fields["model"]; ok {
		t.Error("a field back at its Helm value still overrides")
	}
	// Reset: Helm alone.
	st3, ch := Reset(helm2, st2)
	eff, _ = Effective(helm2, st3)
	if len(st3.Fields) != 0 || len(Changes(eff, helm2)) != 0 || len(ch) != 2 {
		t.Errorf("reset: %+v changes %+v", st3, ch)
	}
}
