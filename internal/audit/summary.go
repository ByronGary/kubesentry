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
	s := Summary{TotalEvents: len(events), ByTag: map[string]int{}, Users: []UserSummary{}}
	byUser := map[string]*UserSummary{}
	for _, e := range events {
		u, ok := byUser[e.Username]
		if !ok {
			u = &UserSummary{Username: e.Username, ActorKind: e.ActorKind}
			byUser[e.Username] = u
		}
		u.Total++
		if isWrite(e.Verb) {
			u.Writes++
		}
		if e.Time.After(u.LastSeen) {
			u.LastSeen = e.Time
		}
		for _, t := range e.Tags {
			s.ByTag[t]++
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
	for _, u := range byUser {
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
