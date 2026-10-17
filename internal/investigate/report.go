package investigate

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func refsProp(what string) *schema {
	return &schema{Type: "array", MaxItems: capRefs, Items: &schema{Type: "string"},
		Description: "Refs (from the digest or tool results) that support " + what + "."}
}

func strObject(desc string, fields ...prop) *schema {
	req := make([]string, len(fields))
	for i, f := range fields {
		req[i] = f.Name
	}
	return &schema{Type: "object", Description: desc, Required: req, Props: fields}
}

// reportSchema is the report the model submits (submit_report's input, and
// the structured output of the fallback final turn): strict, every field
// required, no other fields. web/src/types.ts InvestigationReport mirrors
// it, plus the server's unverified.
var reportSchema = strObject("",
	prop{"summary", &schema{Type: "string", Description: "Two to four sentences for the on-call engineer: what happened, the most likely cause and how sure you are."}},
	prop{"status", &schema{Type: "string", Enum: []string{RootCauseIdentified, LikelyCause, Inconclusive},
		Description: "root_cause_identified only when the evidence directly shows the cause."}},
	prop{"root_cause", strObject("The most likely cause.",
		prop{"statement", &schema{Type: "string"}},
		prop{"confidence", &schema{Type: "string", Enum: []string{"high", "medium", "low"}}},
		prop{"evidence", refsProp("the root cause")},
	)},
	prop{"contributing_factors", &schema{Type: "array", MaxItems: capFactors, Items: strObject("",
		prop{"statement", &schema{Type: "string"}},
		prop{"evidence", refsProp("the factor")},
	)}},
	prop{"timeline", &schema{Type: "array", MaxItems: capTimeline, Items: strObject("",
		prop{"time", &schema{Type: "string", Format: "date-time", Description: "RFC 3339, UTC."}},
		prop{"event", &schema{Type: "string"}},
		prop{"evidence", refsProp("the entry")},
	)}},
	prop{"impact", &schema{Type: "string", Description: "Who or what was affected, and for how long, as far as the evidence shows."}},
	prop{"suggested_checks", &schema{Type: "array", MaxItems: capChecks, Items: strObject("A check for a person to run; kubesentry never runs it.",
		prop{"description", &schema{Type: "string"}},
		prop{"command", &schema{Type: "string", Description: "One read-only command, or empty."}},
	)}},
	prop{"remediation_ideas", &schema{Type: "array", MaxItems: capRemediation, Items: strObject("A change for people to consider; kubesentry never applies it.",
		prop{"description", &schema{Type: "string"}},
		prop{"risk", &schema{Type: "string"}},
	)}},
	prop{"open_questions", &schema{Type: "array", MaxItems: capQuestions, Items: &schema{Type: "string"}}},
	prop{"data_gaps", &schema{Type: "array", MaxItems: capGaps, Items: &schema{Type: "string"},
		Description: "Evidence that was missing, not permitted or cut short."}},
)

// ReportSchema is the report's JSON Schema, as the model is given it.
func ReportSchema() json.RawMessage { return reportSchema.JSON(true) }

// Report caps: longer strings are cut, longer lists dropped from the end.
const (
	capSummary     = 2000
	capStatement   = 1000
	capText        = 500
	capCommand     = 300
	capItem        = 300
	capFactors     = 10
	capTimeline    = 40
	capChecks      = 10
	capRemediation = 10
	capQuestions   = 10
	capGaps        = 10
	capRefs        = 20
	capRef         = 200
)

// timelineSlack is how far outside the window a timeline entry may lie.
const timelineSlack = time.Hour

// commandRemoved is appended to a check whose command was not read-only.
const commandRemoved = " (command removed: not read-only)"

// parseReport checks a submitted report against the schema and the few
// rules a schema cannot say; the error is what the model is told.
func parseReport(raw []byte) (*Report, error) {
	if err := reportSchema.check(raw, false); err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, errors.New("not valid JSON")
	}
	var errs validationError
	if strings.TrimSpace(r.Summary) == "" {
		errs = append(errs, "summary: must not be empty")
	}
	if strings.TrimSpace(r.RootCause.Statement) == "" {
		errs = append(errs, "root_cause.statement: must not be empty")
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return &r, nil
}

// finishReport caps and cleans a parsed report: text through the egress
// filter, refs the run never showed listed as unverified, timeline entries
// more than an hour outside [from, to] dropped, commands that are not
// read-only removed. It returns the evidence index: the ledger entries of
// the verified refs the report cites, in the order cited.
func finishReport(r *Report, led *Ledger, eg *Egress, from, to time.Time) (*Report, []Evidence) {
	out := &Report{
		Summary: eg.Text(r.Summary, capSummary),
		Status:  r.Status,
		Impact:  eg.Text(r.Impact, capStatement),
	}
	var evidence []Evidence
	cited := map[string]bool{}
	unverified := map[string]bool{}
	out.Unverified = []string{}
	refs := func(l []string) []string {
		res := []string{}
		seen := map[string]bool{}
		for _, ref := range l {
			ref = eg.Line(strings.TrimSpace(ref), capRef)
			if ref == "" || seen[ref] {
				continue
			}
			if len(res) >= capRefs {
				break
			}
			seen[ref] = true
			res = append(res, ref)
			if e, ok := led.Get(ref); ok {
				if !cited[ref] {
					cited[ref] = true
					evidence = append(evidence, e)
				}
			} else if !unverified[ref] {
				unverified[ref] = true
				out.Unverified = append(out.Unverified, ref)
			}
		}
		return res
	}
	out.RootCause = RootCause{Statement: eg.Text(r.RootCause.Statement, capStatement), Confidence: r.RootCause.Confidence,
		Evidence: refs(r.RootCause.Evidence)}
	out.ContributingFactors = []Factor{}
	for _, f := range r.ContributingFactors {
		if len(out.ContributingFactors) >= capFactors {
			break
		}
		out.ContributingFactors = append(out.ContributingFactors, Factor{Statement: eg.Text(f.Statement, capStatement), Evidence: refs(f.Evidence)})
	}
	out.Timeline = []TimelineEntry{}
	for _, te := range r.Timeline {
		if len(out.Timeline) >= capTimeline {
			break
		}
		at, err := time.Parse(time.RFC3339, te.Time)
		if err != nil || at.Before(from.Add(-timelineSlack)) || at.After(to.Add(timelineSlack)) {
			continue
		}
		out.Timeline = append(out.Timeline, TimelineEntry{Time: at.UTC().Format(time.RFC3339), Event: eg.Text(te.Event, capText),
			Evidence: refs(te.Evidence)})
	}
	out.SuggestedChecks = []Check{}
	for _, c := range r.SuggestedChecks {
		if len(out.SuggestedChecks) >= capChecks {
			break
		}
		ch := Check{Description: eg.Text(c.Description, capText)}
		cmd := strings.TrimSpace(c.Command)
		switch {
		case cmd == "":
		case ReadOnlyCommand(cmd) && len(cmd) <= capCommand:
			ch.Command = eg.Line(cmd, capCommand)
		default:
			ch.Description += commandRemoved
		}
		out.SuggestedChecks = append(out.SuggestedChecks, ch)
	}
	out.RemediationIdeas = []Remediation{}
	for _, m := range r.RemediationIdeas {
		if len(out.RemediationIdeas) >= capRemediation {
			break
		}
		out.RemediationIdeas = append(out.RemediationIdeas, Remediation{Description: eg.Text(m.Description, capText), Risk: eg.Text(m.Risk, capItem)})
	}
	list := func(l []string, n int) []string {
		res := []string{}
		for _, s := range l {
			if len(res) >= n {
				break
			}
			if s = eg.Text(strings.TrimSpace(s), capItem); s != "" {
				res = append(res, s)
			}
		}
		return res
	}
	out.OpenQuestions = list(r.OpenQuestions, capQuestions)
	out.DataGaps = list(r.DataGaps, capGaps)
	if len(out.Unverified) == 0 {
		out.Unverified = nil
	}
	return out, evidence
}
