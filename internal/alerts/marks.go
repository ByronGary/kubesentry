package alerts

// Acknowledgements and silences. People act on findings through an
// append-only log (Store.AddAction, any replica). The log, not the finding
// row, is the truth: the leader rewrites alert_findings from its own memory
// on every commit, so a follower that wrote the row directly would be
// undone. Every replica folds the log into marks and applies them to the
// findings it holds with one pure function, applyMarks: the leader's
// evaluator before it notifies, the others when they refresh their board.

import (
	"context"
	"errors"
	"slices"
	"sort"
	"sync"
	"time"
)

// ActionKind is what a person did to a finding.
type ActionKind string

// Actions.
const (
	// ActionAck acknowledges the finding's current episode (its FirstSeen).
	// It keeps notifying, with acknowledged_by and acknowledged_at.
	ActionAck ActionKind = "ack"
	// ActionUnack lifts an acknowledgement.
	ActionUnack ActionKind = "unack"
	// ActionSilence stops notifying about the finding's key until Until,
	// across resolve and reopen.
	ActionSilence ActionKind = "silence"
	// ActionUnsilence lifts a silence: the finding fires again at once.
	ActionUnsilence ActionKind = "unsilence"
)

// Valid reports whether k is one of the actions.
func (k ActionKind) Valid() bool {
	switch k {
	case ActionAck, ActionUnack, ActionSilence, ActionUnsilence:
		return true
	}
	return false
}

// Action is one entry of the actions log (table alert_actions). Mirrored
// in web/src/types.ts AlertAction.
type Action struct {
	ID  int64  `json:"id"`
	Key string `json:"key"`
	// FirstSeen is the episode acted on (the finding's FirstSeen then).
	FirstSeen time.Time  `json:"firstSeen"`
	Action    ActionKind `json:"action"`
	Actor     string     `json:"actor"`
	Reason    string     `json:"reason,omitempty"`
	// Until ends a silence.
	Until *time.Time `json:"until,omitempty"`
	// Severity is the finding's severity when the action was taken: an ack
	// taken at warning does not cover the finding while it is critical.
	Severity string    `json:"severity"`
	At       time.Time `json:"at"`
}

// Silence durations: at least MinSilence, at most Options.MaxSilence
// (default DefaultMaxSilence), which may not exceed MaxSilenceCap. A silence
// whose Until lies further out than MaxSilenceCap after it was set ends then.
const (
	MinSilence        = 5 * time.Minute
	DefaultMaxSilence = 7 * 24 * time.Hour
	MaxSilenceCap     = 30 * 24 * time.Hour
)

// Why an action cannot be taken (Runner.Act).
var (
	// ErrNotFound: no such finding on the board.
	ErrNotFound = errors.New("not found")
	// ErrResolved: the finding is resolved (only a silence may still be
	// lifted).
	ErrResolved = errors.New("resolved")
	// ErrInvalid: the action does not apply to the finding as it is (unack
	// without an ack, unsilence without a silence, a silence ending in the
	// past).
	ErrInvalid = errors.New("invalid")
)

// marks is what the actions log says about one key now: the latest ack and
// the latest silence that no later unack or unsilence lifted.
type marks struct {
	ack, silence *Action
}

// foldMarks folds one key's actions, in ID order, into its marks (copies:
// the log's slices move on).
func foldMarks(acts []Action) marks {
	var m marks
	for _, a := range acts {
		switch a.Action {
		case ActionAck:
			m.ack = &a
		case ActionUnack:
			m.ack = nil
		case ActionSilence:
			m.silence = &a
		case ActionUnsilence:
			m.silence = nil
		}
	}
	return m
}

// silenceEnd is when silence a ends: its Until, but no later than
// MaxSilenceCap after it was set.
func silenceEnd(a *Action) time.Time {
	end := a.At.Add(MaxSilenceCap)
	if a.Until != nil && a.Until.Before(end) {
		end = *a.Until
	}
	return end
}

// applyMarks sets f's acknowledgement and silence from m as of now, and its
// state when it is not resolved: silenced while a silence lasts (whatever
// the episode), else acknowledged while an ack covers the current episode
// (the same FirstSeen, and not taken at warning while f is critical), else
// open. A resolved finding stays resolved but shows a silence that still
// lasts (it applies when the finding reopens). It sets only f's own fields,
// never what they point to or a map, so it may run on a shallow copy.
func applyMarks(f *Finding, m marks, now time.Time) {
	f.AckBy, f.AckAt = "", nil
	f.SilencedBy, f.SilencedAt, f.SilenceReason, f.SilencedUntil = "", nil, "", nil
	silenced := false
	if s := m.silence; s != nil {
		if end := silenceEnd(s); now.Before(end) {
			silenced = true
			f.SilencedBy, f.SilenceReason = s.Actor, s.Reason
			f.SilencedAt, f.SilencedUntil = timePtr(s.At), timePtr(end)
		}
	}
	acked := false
	if a := m.ack; a != nil && NormalTime(a.FirstSeen).Equal(NormalTime(f.FirstSeen)) &&
		(a.Severity == SeverityCritical || f.Severity != SeverityCritical) {
		acked = true
		f.AckBy, f.AckAt = a.Actor, timePtr(a.At)
	}
	switch {
	case f.Resolved():
	case silenced:
		f.State = StateSilenced
	case acked:
		f.State = StateAcknowledged
	default:
		f.State = StateOpen
	}
}

// checkAction reports why a cannot be taken on f as it is now (f carries
// its marks), or nil.
func checkAction(f *Finding, a *Action, now time.Time) error {
	if f.Resolved() && !(a.Action == ActionUnsilence && f.SilencedBy != "") {
		return ErrResolved
	}
	switch a.Action {
	case ActionUnack:
		if f.AckBy == "" {
			return ErrInvalid
		}
	case ActionUnsilence:
		if f.SilencedBy == "" {
			return ErrInvalid
		}
	case ActionSilence:
		if a.Until == nil || !a.Until.After(now) {
			return ErrInvalid
		}
	case ActionAck:
	default:
		return ErrInvalid
	}
	return nil
}

// settleWindow: actions are read again for this long after they were taken.
// Two inserts can commit out of ID order (a bigserial is taken before the
// commit), so reading only past the highest ID seen could skip one for good.
const settleWindow = 5 * time.Minute

// actionLog is the actions log as this replica has read it, kept in memory
// for the retention: applyMarks needs every action on a key, and GET
// /api/v1/alerts/actions lists them. Safe for concurrent use.
type actionLog struct {
	mu    sync.Mutex
	byKey map[string][]Action // each in ID order
	all   []Action            // in ID order
	seen  map[int64]bool
	// after is where the next read starts: the newest ID taken more than
	// settleWindow ago.
	after int64
}

func newActionLog() *actionLog {
	return &actionLog{byKey: map[string][]Action{}, seen: map[int64]bool{}}
}

// sync reads what st holds after the log's position and merges it.
func (l *actionLog) sync(ctx context.Context, st Store, now time.Time) error {
	l.mu.Lock()
	after := l.after
	l.mu.Unlock()
	acts, err := st.Actions(ctx, after)
	if err != nil {
		return err
	}
	l.merge(acts, now)
	return nil
}

// merge adds actions not seen before, forgets those past the retention and
// moves the read position on.
func (l *actionLog) merge(acts []Action, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range acts {
		if l.seen[a.ID] {
			continue
		}
		l.seen[a.ID] = true
		l.byKey[a.Key] = insertByID(l.byKey[a.Key], a)
		l.all = insertByID(l.all, a)
	}
	// Forget what the store prunes (Retention plus a day).
	cutoff := now.Add(-Retention - 24*time.Hour)
	drop := 0
	for drop < len(l.all) && l.all[drop].At.Before(cutoff) {
		drop++
	}
	if drop > 0 {
		for _, a := range l.all[:drop] {
			delete(l.seen, a.ID)
			kept := slices.DeleteFunc(l.byKey[a.Key], func(b Action) bool { return b.ID == a.ID })
			if len(kept) == 0 {
				delete(l.byKey, a.Key)
			} else {
				l.byKey[a.Key] = kept
			}
		}
		l.all = slices.Clone(l.all[drop:])
	}
	settled := now.Add(-settleWindow)
	for i := len(l.all) - 1; i >= 0; i-- {
		if l.all[i].At.Before(settled) {
			l.after = max(l.after, l.all[i].ID)
			break
		}
	}
}

// insertByID inserts a into s, which is in ID order.
func insertByID(s []Action, a Action) []Action {
	if n := len(s); n == 0 || s[n-1].ID < a.ID {
		return append(s, a)
	}
	i := sort.Search(len(s), func(i int) bool { return s[i].ID > a.ID })
	return slices.Insert(s, i, a)
}

// mark folds key's actions.
func (l *actionLog) mark(key string) marks {
	if l == nil {
		return marks{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return foldMarks(l.byKey[key])
}

// list returns key's actions (every key's when key is ""), newest first,
// at most limit, those keep accepts.
func (l *actionLog) list(key string, limit int, keep func(*Action) bool) []Action {
	l.mu.Lock()
	defer l.mu.Unlock()
	src := l.all
	if key != "" {
		src = l.byKey[key]
	}
	out := []Action{}
	for i := len(src) - 1; i >= 0 && len(out) < limit; i-- {
		if keep == nil || keep(&src[i]) {
			out = append(out, src[i])
		}
	}
	return out
}
