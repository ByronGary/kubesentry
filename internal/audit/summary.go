package audit

import (
	"sort"
	"time"
)

// UserSummary aggregates one principal's activity.
type UserSummary struct {
	Username     string    `json:"username"`
	ActorKind    string    `json:"actorKind"`
	Total        int       `json:"total"`
	Writes       int       `json:"writes"`
	Execs        int       `json:"execs"`
	SecretAccess int       `json:"secretAccess"`
	Denied       int       `json:"denied"`
	LastSeen     time.Time `json:"lastSeen"`
}

// Summary is an overview of a set of events.
type Summary struct {
	TotalEvents int            `json:"totalEvents"`
	ByTag       map[string]int `json:"byTag"`
	Users       []UserSummary  `json:"users"` // most active first
}

// Summarize aggregates events by tag and by user.
func Summarize(events []Event) Summary {
	var b SummaryBuilder
	for i := range events {
		b.Add(&events[i])
	}
	return b.Summary()
}

// SummaryBuilder accumulates a Summary from events, or from rows a database
// already grouped by (username, actor kind) and by tag. Every Store builds its
// summaries through it, so they agree on the details: a user's ActorKind is
// the one of their most recent event, and users are ordered by Total, then
// Username. The zero value is ready to use.
type SummaryBuilder struct {
	total int
	byTag map[string]int
	users map[userKindKey]*UserSummary
}

type userKindKey struct{ user, kind string }

func (b *SummaryBuilder) init() {
	if b.byTag == nil {
		b.byTag = map[string]int{}
		b.users = map[userKindKey]*UserSummary{}
	}
}

// Add counts one event.
func (b *SummaryBuilder) Add(e *Event) {
	b.init()
	b.total++
	k := userKindKey{e.Username, e.ActorKind}
	u, ok := b.users[k]
	if !ok {
		u = &UserSummary{Username: e.Username, ActorKind: e.ActorKind}
		b.users[k] = u
	}
	u.Total++
	if isWrite(e.Verb) {
		u.Writes++
	}
	if e.Time.After(u.LastSeen) {
		u.LastSeen = e.Time
	}
	for _, t := range e.Tags {
		b.byTag[t]++
		switch t {
		case TagExec:
			u.Execs++
		case TagSecretAccess:
			u.SecretAccess++
		case TagDenied:
			u.Denied++
		}
	}
}

// AddUser adds the pre-aggregated counts of one (Username, ActorKind) group;
// its Total also counts towards TotalEvents.
func (b *SummaryBuilder) AddUser(g UserSummary) {
	b.init()
	b.total += g.Total
	k := userKindKey{g.Username, g.ActorKind}
	u, ok := b.users[k]
	if !ok {
		u = &UserSummary{Username: g.Username, ActorKind: g.ActorKind}
		b.users[k] = u
	}
	u.Total += g.Total
	u.Writes += g.Writes
	u.Execs += g.Execs
	u.SecretAccess += g.SecretAccess
	u.Denied += g.Denied
	if g.LastSeen.After(u.LastSeen) {
		u.LastSeen = g.LastSeen
	}
}

// AddTag adds n occurrences of tag to ByTag.
func (b *SummaryBuilder) AddTag(tag string, n int) {
	b.init()
	b.byTag[tag] += n
}

// Summary returns the result. A user seen under several actor kinds (the
// system prefixes changed between ingests) is merged into one entry.
func (b *SummaryBuilder) Summary() Summary {
	s := Summary{TotalEvents: b.total, ByTag: map[string]int{}, Users: []UserSummary{}}
	for t, n := range b.byTag {
		s.ByTag[t] = n
	}
	merged := map[string]*UserSummary{}
	var kindSeen = map[string]time.Time{}
	for _, g := range b.users {
		u, ok := merged[g.Username]
		if !ok {
			c := *g
			merged[g.Username] = &c
			kindSeen[g.Username] = g.LastSeen
			continue
		}
		u.Total += g.Total
		u.Writes += g.Writes
		u.Execs += g.Execs
		u.SecretAccess += g.SecretAccess
		u.Denied += g.Denied
		last := kindSeen[g.Username]
		if g.LastSeen.After(last) || (g.LastSeen.Equal(last) && g.ActorKind < u.ActorKind) {
			u.ActorKind = g.ActorKind
			kindSeen[g.Username] = g.LastSeen
		}
		if g.LastSeen.After(u.LastSeen) {
			u.LastSeen = g.LastSeen
		}
	}
	for _, u := range merged {
		s.Users = append(s.Users, *u)
	}
	sort.Slice(s.Users, func(i, j int) bool {
		if s.Users[i].Total != s.Users[j].Total {
			return s.Users[i].Total > s.Users[j].Total
		}
		return s.Users[i].Username < s.Users[j].Username
	})
	return s
}
