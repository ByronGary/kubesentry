// Package investigate is the AI investigator: an agent that reads a
// redacted digest of one incident, pulls more evidence through read-only
// tools bounded to the incident's padded window and to the starting user's
// permissions, and submits a structured report (root cause with confidence,
// timeline, read-only checks, evidence refs).
//
// Stdlib only (plus kubesentry's stdlib packages): the model is reached
// through the LLM interface, which internal/llm implements over the
// Anthropic SDK; cmd/server wires them. See docs/contracts.md "AI
// investigator" and web/src/types.ts Investigation*.
package investigate

import (
	"encoding/json"
	"time"

	"github.com/ByronGary/kubesentry/internal/incidents"
)

// Status of a run.
type Status string

const (
	Running   Status = "running"
	Completed Status = "completed"
	Refused   Status = "refused"
	Failed    Status = "failed"
	Cancelled Status = "cancelled"
)

// Access is what the starting user may see inside the incident, frozen at
// start and stored with the run (web/src/types.ts InvestigationAccess):
// Logs is ViewPodLogs in the incident's namespace, Audit ViewAudit there
// (ViewClusterAudit for node and cluster incidents), CloudTrail
// ViewCloudTrail, Nodes ViewNodes.
type Access struct {
	Logs       bool `json:"logs"`
	Audit      bool `json:"audit"`
	CloudTrail bool `json:"cloudtrail"`
	Nodes      bool `json:"nodes"`
}

// Covers reports whether a holds every capability b holds: a reader with
// access a may read a run started with access b.
func (a Access) Covers(b Access) bool {
	return (a.Logs || !b.Logs) && (a.Audit || !b.Audit) && (a.CloudTrail || !b.CloudTrail) && (a.Nodes || !b.Nodes)
}

// Omitted names the sections the access leaves out, as "forbidden".
func (a Access) Omitted() map[string]string {
	out := map[string]string{}
	if !a.Logs {
		out[incidents.SectionLogs] = "forbidden"
	}
	if !a.Audit {
		out[incidents.SectionAudit] = "forbidden"
	}
	if !a.CloudTrail {
		out[incidents.SectionCloudTrail] = "forbidden"
	}
	if !a.Nodes {
		out[SectionNodes] = "forbidden"
	}
	return out
}

// SectionNodes is the omitted key for Node events and node conditions.
const SectionNodes = "nodes"

// Step kinds and results (web/src/types.ts InvestigationStep).
const (
	StepTurn = "turn"
	StepTool = "tool"
	StepNote = "note"

	ResultOK      = "ok"
	ResultError   = "error"
	ResultDenied  = "denied"
	ResultInvalid = "invalid"
)

// Step is one line of progress for people. Text is never raw tool input.
type Step struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Tool   string    `json:"tool,omitempty"`
	Text   string    `json:"text"`
	Result string    `json:"result,omitempty"`
}

// Evidence is one entry of a run's evidence index
// (web/src/types.ts InvestigationEvidence).
type Evidence struct {
	Ref     string    `json:"ref"`
	Kind    string    `json:"kind"`
	Time    time.Time `json:"time,omitzero"`
	Object  string    `json:"object,omitempty"`
	Snippet string    `json:"snippet,omitempty"`
}

// Report statuses and confidences.
const (
	RootCauseIdentified = "root_cause_identified"
	LikelyCause         = "likely_cause"
	Inconclusive        = "inconclusive"
)

// Report is what the model submits, validated and capped
// (web/src/types.ts InvestigationReport).
type Report struct {
	Summary             string          `json:"summary"`
	Status              string          `json:"status"`
	RootCause           RootCause       `json:"root_cause"`
	ContributingFactors []Factor        `json:"contributing_factors"`
	Timeline            []TimelineEntry `json:"timeline"`
	Impact              string          `json:"impact"`
	SuggestedChecks     []Check         `json:"suggested_checks"`
	RemediationIdeas    []Remediation   `json:"remediation_ideas"`
	OpenQuestions       []string        `json:"open_questions"`
	DataGaps            []string        `json:"data_gaps"`
	// Unverified are the refs the model cited that the run never showed it
	// (set by the server; the refs stay where they were cited).
	Unverified []string `json:"unverified,omitempty"`
}

// RootCause is the report's main finding.
type RootCause struct {
	Statement  string   `json:"statement"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

// Factor is a contributing factor.
type Factor struct {
	Statement string   `json:"statement"`
	Evidence  []string `json:"evidence"`
}

// TimelineEntry is one point of the report's timeline.
type TimelineEntry struct {
	Time     string   `json:"time"`
	Event    string   `json:"event"`
	Evidence []string `json:"evidence"`
}

// Check is a read-only check for a person to run.
type Check struct {
	Description string `json:"description"`
	Command     string `json:"command"`
}

// Remediation is a change for people to consider.
type Remediation struct {
	Description string `json:"description"`
	Risk        string `json:"risk"`
}

// Investigation is one run (web/src/types.ts Investigation). Fields tagged
// "-" are kept by the store but not served.
type Investigation struct {
	ID            string            `json:"id"`
	IncidentID    string            `json:"incidentId"`
	Namespace     string            `json:"-"`
	Status        Status            `json:"status"`
	RequestedBy   string            `json:"requestedBy"`
	CreatedAt     time.Time         `json:"createdAt"`
	UpdatedAt     time.Time         `json:"-"`
	FinishedAt    *time.Time        `json:"finishedAt,omitempty"`
	Provider      string            `json:"provider"`
	Model         string            `json:"model"`
	Effort        string            `json:"effort"`
	PromptVersion string            `json:"-"`
	InputSHA256   string            `json:"-"`
	CachedFrom    string            `json:"cachedFrom,omitempty"`
	Access        Access            `json:"access"`
	Omitted       map[string]string `json:"omitted,omitempty"`
	Steps         []Step            `json:"steps"`
	Report        *Report           `json:"report,omitempty"`
	Evidence      []Evidence        `json:"evidence,omitempty"`
	Refusal       *Refusal          `json:"refusal,omitempty"`
	Error         string            `json:"error,omitempty"`
	Usage         Usage             `json:"usage"`
	Turns         int               `json:"turns"`
	ToolCalls     int               `json:"toolCalls"`
}

// MarshalJSON adds the summary's outcome and confidence, taken from the
// report.
func (i Investigation) MarshalJSON() ([]byte, error) {
	type plain Investigation
	out := struct {
		plain
		Outcome    string `json:"outcome,omitempty"`
		Confidence string `json:"confidence,omitempty"`
	}{plain: plain(i)}
	if out.Steps == nil {
		out.Steps = []Step{}
	}
	if i.Report != nil {
		out.Outcome, out.Confidence = i.Report.Status, i.Report.RootCause.Confidence
	}
	return json.Marshal(out)
}

// Summary is a list item (web/src/types.ts InvestigationSummary).
type Summary struct {
	ID          string     `json:"id"`
	IncidentID  string     `json:"incidentId"`
	Status      Status     `json:"status"`
	RequestedBy string     `json:"requestedBy"`
	CreatedAt   time.Time  `json:"createdAt"`
	FinishedAt  *time.Time `json:"finishedAt,omitempty"`
	Provider    string     `json:"provider"`
	Model       string     `json:"model"`
	Effort      string     `json:"effort"`
	Outcome     string     `json:"outcome,omitempty"`
	Confidence  string     `json:"confidence,omitempty"`
	CachedFrom  string     `json:"cachedFrom,omitempty"`
}

// Summary returns the run's list item.
func (i *Investigation) Summary() Summary {
	s := Summary{ID: i.ID, IncidentID: i.IncidentID, Status: i.Status, RequestedBy: i.RequestedBy, CreatedAt: i.CreatedAt,
		FinishedAt: i.FinishedAt, Provider: i.Provider, Model: i.Model, Effort: i.Effort, CachedFrom: i.CachedFrom}
	if i.Report != nil {
		s.Outcome, s.Confidence = i.Report.Status, i.Report.RootCause.Confidence
	}
	return s
}

// Clone returns a deep copy.
func (i *Investigation) Clone() *Investigation {
	if i == nil {
		return nil
	}
	c := *i
	if i.FinishedAt != nil {
		t := *i.FinishedAt
		c.FinishedAt = &t
	}
	if i.Omitted != nil {
		c.Omitted = make(map[string]string, len(i.Omitted))
		for k, v := range i.Omitted {
			c.Omitted[k] = v
		}
	}
	c.Steps = append([]Step(nil), i.Steps...)
	c.Evidence = append([]Evidence(nil), i.Evidence...)
	if i.Report != nil {
		c.Report = i.Report.clone()
	}
	if i.Refusal != nil {
		r := *i.Refusal
		c.Refusal = &r
	}
	return &c
}

func (r *Report) clone() *Report {
	c := *r
	strs := func(l []string) []string {
		if l == nil {
			return nil
		}
		return append([]string{}, l...)
	}
	c.RootCause.Evidence = strs(r.RootCause.Evidence)
	if r.ContributingFactors != nil {
		c.ContributingFactors = make([]Factor, len(r.ContributingFactors))
		for i, f := range r.ContributingFactors {
			f.Evidence = strs(f.Evidence)
			c.ContributingFactors[i] = f
		}
	}
	if r.Timeline != nil {
		c.Timeline = make([]TimelineEntry, len(r.Timeline))
		for i, t := range r.Timeline {
			t.Evidence = strs(t.Evidence)
			c.Timeline[i] = t
		}
	}
	if r.SuggestedChecks != nil {
		c.SuggestedChecks = append([]Check{}, r.SuggestedChecks...)
	}
	if r.RemediationIdeas != nil {
		c.RemediationIdeas = append([]Remediation{}, r.RemediationIdeas...)
	}
	c.OpenQuestions = strs(r.OpenQuestions)
	c.DataGaps = strs(r.DataGaps)
	c.Unverified = strs(r.Unverified)
	return &c
}
