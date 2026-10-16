import { describe, expect, it } from 'vitest'
import {
  ackText,
  alertHref,
  alertQuery,
  alertsHref,
  alertsPath,
  alertsWidget,
  annotationRows,
  bulkPlan,
  canSelect,
  checkDuration,
  checkLabel,
  checkReason,
  chunks,
  DEFAULT_MAX_SILENCE_MS,
  durationText,
  filterAlerts,
  goDuration,
  historyRows,
  isNarrowed,
  keyMissing,
  linkLabel,
  matches,
  MAX_SILENCE_CAP_MS,
  maxSilenceMs,
  objectText,
  optionsOf,
  outcomeOf,
  parseDuration,
  patchAlertFilter,
  presetAllowed,
  readAlertFilter,
  requestErrorText,
  rowActions,
  rowId,
  selectionOf,
  severityStatus,
  silenceText,
  STATE_WORD,
  tabCounts,
  toggleAll,
  toggleKey,
  type AlertFilter,
} from './alerts'
import type { AlertAction, AlertActionResult, AlertFinding } from './types'

const NOW = Date.parse('2026-10-16T12:00:00Z')
const M = 60_000
const H = 60 * M
const D = 24 * H
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString()

function finding(p: Partial<AlertFinding> & Pick<AlertFinding, 'key'>): AlertFinding {
  const [check, kind, namespace, name] = p.key.split('/')
  return {
    alert: 'KubesentryWorkloadUnhealthy',
    check,
    kind,
    namespace: namespace || undefined,
    name,
    severity: 'warning',
    title: `${kind} ${name}`,
    owner: 'team-shop',
    production: false,
    labels: {},
    annotations: {},
    state: 'open',
    firstSeen: iso(H),
    lastSeen: iso(0),
    actionable: true,
    ...p,
  }
}

const recs = finding({ key: 'workload-unhealthy/Deployment/prod/recommendations', severity: 'critical', title: 'Deployment prod/recommendations: CrashLoopBackOff ×1', state: 'acknowledged', ackBy: 'dave', ackAt: iso(38 * M), incidentId: 'inc-1' })
const grafana = finding({ key: 'nodeport/Service/monitoring/grafana', owner: 'team-platform', title: 'Exposure change: new NodePort service: Service monitoring/grafana' })
const leak = finding({ key: 'memory-leak/StatefulSet/staging/search-indexer', state: 'silenced', silencedBy: 'erin', silencedAt: iso(4 * H), silencedUntil: new Date(NOW + 68 * H).toISOString(), silenceReason: 'fix ships Thursday' })
const admin = finding({ key: 'cluster-admin/ClusterRoleBinding//erin-cluster-admin', severity: 'critical', owner: 'team-platform', title: 'RBAC drift: new cluster-admin binding: ClusterRoleBinding erin-cluster-admin' })
const bob = finding({ key: 'audit-rbac-change/User//bob', state: 'resolved', resolvedAt: iso(3 * H), ackBy: 'carol', ackAt: iso(5 * H), owner: 'team-platform' })
const quiet = finding({ key: 'cert-expiring/Certificate/staging/search-staging-tls', quiet: true })
const theirs = finding({ key: 'workload-unhealthy/Deployment/payments/api', owner: 'payments', actionable: false })
const all = [recs, grafana, leak, admin, bob, quiet, theirs]

const q = (s: string) => new URLSearchParams(s)
const filter = (p: Partial<AlertFilter> = {}): AlertFilter => ({ ...readAlertFilter(q('')), ...p })

describe('the filter in the address', () => {
  it('starts on Open, or on every state when it names one finding', () => {
    expect(readAlertFilter(q(''))).toEqual({ state: 'open', namespace: '', owner: '', severity: '', check: '', q: '', key: '' })
    expect(readAlertFilter(q('key=a/b/c/d')).state).toBe('all')
    expect(readAlertFilter(q('key=a/b/c/d&state=silenced')).state).toBe('silenced')
  })
  it('drops values it does not know', () => {
    const f = readAlertFilter(q('state=firing&severity=info&owner=%20team-shop%20'))
    expect(f.state).toBe('open')
    expect(f.severity).toBe('')
    expect(f.owner).toBe('team-shop')
    expect(readAlertFilter(q(`q=${'x'.repeat(500)}`)).q).toHaveLength(200)
  })
  it('writes back only what differs from the defaults', () => {
    expect(alertQuery(filter())).toEqual({ key: undefined, state: undefined, namespace: undefined, owner: undefined, severity: undefined, check: undefined, q: undefined })
    expect(patchAlertFilter(filter(), { state: 'resolved', owner: 'team-shop' })).toMatchObject({ state: 'resolved', owner: 'team-shop' })
    // With a key the default is "all", so Open must be written out.
    expect(alertQuery(filter({ key: 'k/K/n/x', state: 'open' })).state).toBe('open')
    expect(alertQuery(filter({ key: 'k/K/n/x', state: 'all' })).state).toBeUndefined()
  })
  it('asks the server for every state, narrowed by namespace and owner', () => {
    expect(alertsPath(filter())).toBe('/api/v1/alerts')
    expect(alertsPath(filter({ namespace: 'prod', owner: 'team shop', state: 'resolved' }))).toBe('/api/v1/alerts?namespace=prod&owner=team+shop')
  })
  it('links to the page', () => {
    expect(alertsHref({})).toBe('#/alerts')
    expect(alertsHref({ owner: 'team-shop', state: 'acknowledged' })).toBe('#/alerts?state=acknowledged&owner=team-shop')
    expect(alertHref('audit-rbac-change/User//bob')).toBe('#/alerts?key=audit-rbac-change%2FUser%2F%2Fbob')
  })
  it('counts as narrowed only for the filters beyond the tab', () => {
    expect(isNarrowed(filter({ state: 'resolved', key: 'x' }))).toBe(false)
    expect(isNarrowed(filter({ check: 'nodeport' }))).toBe(true)
    expect(isNarrowed(filter({ q: '   ' }))).toBe(false)
  })
})

describe('filtering and the tabs', () => {
  it('filters by state, severity, check, namespace, owner and text', () => {
    expect(filterAlerts(all, filter()).map((a) => a.name)).toEqual(['grafana', 'erin-cluster-admin', 'search-staging-tls', 'api'])
    expect(filterAlerts(all, filter({ state: 'all', severity: 'critical' })).map((a) => a.name)).toEqual(['recommendations', 'erin-cluster-admin'])
    expect(filterAlerts(all, filter({ state: 'all', check: 'memory-leak' }))).toEqual([leak])
    expect(filterAlerts(all, filter({ state: 'all', namespace: 'staging' })).map((a) => a.name)).toEqual(['search-indexer', 'search-staging-tls'])
    expect(filterAlerts(all, filter({ state: 'all', owner: 'team-platform' })).map((a) => a.name)).toEqual(['grafana', 'erin-cluster-admin', 'bob'])
    // Every word must match, anywhere in title, object, check, owner or key.
    expect(filterAlerts(all, filter({ state: 'all', q: 'CLUSTER-admin erin' }))).toEqual([admin])
    expect(filterAlerts(all, filter({ state: 'all', q: 'nodeport' }))).toEqual([grafana])
    expect(matches(bob, filter({ state: 'all', namespace: 'prod' }))).toBe(false)
  })
  it("uses the server's counts without filters, the rows' with them", () => {
    const server = { open: 40, acknowledged: 2, silenced: 3, resolved: 5 }
    expect(tabCounts(all, filter(), server)).toEqual({ ...server, all: 50 })
    expect(tabCounts(all, filter({ state: 'resolved' }), server).open).toBe(40)
    expect(tabCounts(all, filter({ owner: 'team-platform' }), server)).toEqual({ open: 2, acknowledged: 0, silenced: 0, resolved: 1, all: 3 })
    expect(tabCounts(all, filter())).toEqual({ open: 4, acknowledged: 1, silenced: 1, resolved: 1, all: 7 })
  })
  it('offers the values in the rows, keeping the selected one', () => {
    expect(optionsOf(all.map((a) => a.namespace), 'kube-system')).toEqual(['kube-system', 'monitoring', 'payments', 'prod', 'staging'])
  })
  it('notices a key that is not listed, once the list is whole', () => {
    expect(keyMissing({ key: 'gone/X/y/z' }, all, true)).toBe(true)
    expect(keyMissing({ key: 'gone/X/y/z' }, all, false)).toBe(false)
    expect(keyMissing({ key: recs.key }, all, true)).toBe(false)
    expect(keyMissing({ key: '' }, all, true)).toBe(false)
  })
  it('gives each row a stable DOM id', () => {
    expect(rowId(recs.key)).toBe(rowId(recs.key))
    expect(rowId(recs.key)).not.toBe(rowId(grafana.key))
    expect(rowId(recs.key)).toMatch(/^alert-[0-9a-z]+$/)
  })
})

describe('words', () => {
  it('names states, severities and checks', () => {
    expect(STATE_WORD.acknowledged).toBe('Acknowledged')
    expect(severityStatus('critical')).toBe('crit')
    expect(severityStatus('warning')).toBe('warn')
    expect(severityStatus('info')).toBe('unknown')
    expect(checkLabel('workload-unhealthy')).toBe('Workload unhealthy')
    expect(checkLabel('audit-exec')).toBe('Exec into pods')
    expect(checkLabel('some-new_check')).toBe('Some new check')
  })
  it('says what the finding is about and where its link goes', () => {
    expect(objectText(recs)).toBe('Deployment prod/recommendations')
    expect(objectText(admin)).toBe('ClusterRoleBinding erin-cluster-admin')
    expect(objectText(bob)).toBe('User bob')
    expect(objectText({ kind: 'User', namespace: 'prod', name: 'alice' })).toBe('User alice in prod')
    expect(linkLabel('#/workloads?namespace=prod&q=web')).toBe('Open in Workloads')
    expect(linkLabel('#/pods/prod/web-0')).toBe('Open in the pod page')
    expect(linkLabel('#/?owner=x')).toBe('Open in Overview')
    expect(linkLabel('javascript:alert(1)')).toBeUndefined()
    expect(linkLabel(undefined)).toBeUndefined()
  })
  it('says who acknowledged and who silenced, until when', () => {
    expect(ackText(recs, NOW)).toBe('Acknowledged by dave 38 minutes ago')
    expect(ackText(grafana, NOW)).toBeUndefined()
    expect(silenceText(leak, NOW)).toMatch(/^Silenced by erin until .+ \(2 days 20 hours left\)$/)
    expect(silenceText({ silencedBy: 'erin' }, NOW)).toBe('Silenced by erin')
    expect(silenceText(grafana, NOW)).toBeUndefined()
  })
})

describe('what a row may do', () => {
  it('follows actionable and the state', () => {
    expect(rowActions(grafana)).toEqual({ ack: true, unack: false, silence: true, unsilence: false })
    expect(rowActions(recs)).toEqual({ ack: false, unack: true, silence: true, unsilence: false })
    expect(rowActions(leak)).toEqual({ ack: true, unack: false, silence: false, unsilence: true })
    // Resolved: only a silence that still lasts may be lifted.
    expect(rowActions(bob)).toEqual({ ack: false, unack: false, silence: false, unsilence: false })
    expect(rowActions({ ...bob, silencedBy: 'erin' })).toEqual({ ack: false, unack: false, silence: false, unsilence: true })
    expect(rowActions(theirs)).toEqual({ ack: false, unack: false, silence: false, unsilence: false })
    expect(rowActions({ ...grafana, actionable: undefined }).ack).toBe(false)
  })
  it('selects only rows something applies to', () => {
    expect(canSelect(grafana)).toBe(true)
    expect(canSelect(bob)).toBe(false)
    expect(canSelect(theirs)).toBe(false)
  })
})

describe('bulk selection', () => {
  it('counts only selectable rows shown', () => {
    const s = selectionOf(all, new Set([recs.key, bob.key, 'elsewhere/X/y/z']))
    expect(s.keys).toEqual([recs.key])
    expect(s.selectable).toEqual([recs.key, grafana.key, leak.key, admin.key, quiet.key])
    expect(s.some).toBe(true)
    expect(s.all).toBe(false)
    expect(selectionOf([bob, theirs], new Set()).selectable).toEqual([])
    expect(selectionOf([bob], new Set([bob.key])).all).toBe(false)
  })
  it('toggles one key, and all of the rows shown', () => {
    const one = toggleKey(new Set(), grafana.key)
    expect([...one]).toEqual([grafana.key])
    expect([...toggleKey(one, grafana.key)]).toEqual([])
    const kept = new Set(['elsewhere/X/y/z'])
    const every = toggleAll([grafana, admin, bob], kept)
    expect([...every].sort()).toEqual(['elsewhere/X/y/z', admin.key, grafana.key].sort())
    // All selected: the same click clears them, and keeps what is selected elsewhere.
    expect([...toggleAll([grafana, admin, bob], every)]).toEqual(['elsewhere/X/y/z'])
  })
  it('plans each action over the selected rows it applies to', () => {
    const plan = bulkPlan(all, [recs.key, grafana.key, leak.key, bob.key, theirs.key])
    expect(plan.ack).toEqual([grafana.key, leak.key])
    expect(plan.unack).toEqual([recs.key])
    expect(plan.silence).toEqual([recs.key, grafana.key])
    expect(plan.unsilence).toEqual([leak.key])
  })
  it('sends at most 100 keys a request', () => {
    const keys = Array.from({ length: 230 }, (_, i) => `k${i}`)
    expect(chunks(keys).map((c) => c.length)).toEqual([100, 100, 30])
    expect(chunks([])).toEqual([])
  })
})

describe('silence duration', () => {
  it('parses what people type', () => {
    expect(parseDuration('90m')).toBe(90 * M)
    expect(parseDuration('6h')).toBe(6 * H)
    expect(parseDuration('2d')).toBe(2 * D)
    expect(parseDuration('1d12h')).toBe(36 * H)
    expect(parseDuration(' 2 days 6 hours ')).toBe(54 * H)
    expect(parseDuration('1.5h')).toBe(90 * M)
    expect(parseDuration('1H30M')).toBe(90 * M)
    expect(parseDuration('90')).toBeUndefined()
    expect(parseDuration('1h30')).toBeUndefined()
    expect(parseDuration('3 weeks')).toBeUndefined()
    expect(parseDuration('')).toBeUndefined()
    expect(parseDuration('0m')).toBeUndefined()
    expect(parseDuration('-1h')).toBeUndefined()
  })
  it('writes it as the server parses it, and as people read it', () => {
    expect(goDuration(36 * H)).toBe('1d12h')
    expect(goDuration(7 * D)).toBe('7d')
    expect(goDuration(90 * M)).toBe('1h30m')
    expect(goDuration(45 * M)).toBe('45m')
    expect(durationText(36 * H)).toBe('1 day 12 hours')
    expect(durationText(H + M)).toBe('1 hour 1 minute')
    expect(durationText(2 * D + 20 * H + 5 * M, 2)).toBe('2 days 20 hours')
    expect(durationText(10_000)).toBe('less than a minute')
  })
  it('checks presets and custom lengths against the bounds', () => {
    expect(checkDuration('4h', '', DEFAULT_MAX_SILENCE_MS)).toEqual({ ok: true, ms: 4 * H, go: '4h', text: '4 hours' })
    expect(checkDuration('custom', '90m', DEFAULT_MAX_SILENCE_MS)).toEqual({ ok: true, ms: 90 * M, go: '1h30m', text: '1 hour 30 minutes' })
    expect(checkDuration('custom', '', DEFAULT_MAX_SILENCE_MS)).toMatchObject({ ok: false, error: expect.stringMatching(/Enter how long/) })
    expect(checkDuration('custom', 'soon', DEFAULT_MAX_SILENCE_MS)).toMatchObject({ ok: false, error: expect.stringMatching(/minutes, hours or days/) })
    expect(checkDuration('custom', '4m', DEFAULT_MAX_SILENCE_MS)).toMatchObject({ ok: false, error: 'A silence lasts at least 5 minutes.' })
    expect(checkDuration('custom', '8d', DEFAULT_MAX_SILENCE_MS)).toMatchObject({ ok: false, error: 'This server allows at most 7 days.' })
    expect(checkDuration('7d', '', D)).toMatchObject({ ok: false, error: 'This server allows at most 1 day.' })
    expect(checkDuration('2w', '', DEFAULT_MAX_SILENCE_MS).ok).toBe(false)
  })
  it("takes the server's maximum from /info, capped at 30 days", () => {
    expect(maxSilenceMs(undefined)).toBe(DEFAULT_MAX_SILENCE_MS)
    expect(maxSilenceMs({ alerts: { enabled: true, sink: 'none' } })).toBe(DEFAULT_MAX_SILENCE_MS)
    expect(maxSilenceMs({ alerts: { enabled: true, sink: 'none', maxSilenceSeconds: 86_400 } })).toBe(D)
    expect(maxSilenceMs({ alerts: { enabled: true, sink: 'none', maxSilenceSeconds: 90 * 86_400 } })).toBe(MAX_SILENCE_CAP_MS)
    expect(presetAllowed('7d', DEFAULT_MAX_SILENCE_MS)).toBe(true)
    expect(presetAllowed('7d', D)).toBe(false)
    expect(presetAllowed('24h', D)).toBe(true)
    expect(presetAllowed('nope', D)).toBe(false)
  })
})

describe('silence reason', () => {
  it('needs 3 to 500 characters, trimmed, counted as the server counts', () => {
    expect(checkReason('')).toMatchObject({ ok: false, length: 0, error: expect.stringMatching(/Say why/) })
    expect(checkReason('  ok  ')).toMatchObject({ ok: false, length: 2, error: 'At least 3 characters.' })
    expect(checkReason('fix')).toEqual({ ok: true, length: 3 })
    // Emoji are one character each, as utf8.RuneCountInString counts them.
    expect(checkReason('🔥🔥🔥').ok).toBe(true)
    expect(checkReason('x'.repeat(500)).ok).toBe(true)
    expect(checkReason('x'.repeat(501))).toMatchObject({ ok: false, error: 'At most 500 characters (now 501).' })
  })
})

describe('what an action did', () => {
  const titles = new Map(all.map((a) => [a.key, a.title]))
  const ok = (key: string): AlertActionResult => ({ key, ok: true })
  const bad = (key: string, error: AlertActionResult['error']): AlertActionResult => ({ key, ok: false, error })
  it('says how many it was taken on', () => {
    expect(outcomeOf('ack', [ok('a'), ok('b')], titles)).toEqual({ tone: 'ok', text: 'Acknowledged 2 alerts.', details: [] })
    expect(outcomeOf('silence', [ok('a')], titles, { forText: '4 hours' }).text).toBe('Silenced 1 alert for 4 hours.')
    expect(outcomeOf('unsilence', [ok('a')], titles).text).toBe('Lifted the silence on 1 alert.')
    expect(outcomeOf('unack', [ok('a')], titles).text).toBe('Removed the acknowledgement from 1 alert.')
  })
  it('explains each result that failed', () => {
    const o = outcomeOf('unack', [ok(recs.key), bad(grafana.key, 'invalid'), bad('gone/X/y/z', 'not found'), bad(theirs.key, 'forbidden'), bad(bob.key, 'resolved')], titles)
    expect(o.tone).toBe('warn')
    expect(o.text).toBe('Removed the acknowledgement from 1 alert. 1 skipped, 1 not found, 1 forbidden, 1 resolved.')
    expect(o.details).toEqual([
      `${grafana.title}: it is not acknowledged`,
      'gone/X/y/z: not found: it may have left the list, or you can no longer see it',
      `${theirs.title}: not allowed: acting on it needs the alerts responder role in its namespace`,
      `${bob.title}: already resolved`,
    ])
    expect(outcomeOf('ack', [bad('x', 'not found')], titles)).toMatchObject({ tone: 'crit', text: 'No alert was changed. 1 not found.' })
  })
  it('mentions selected rows the action did not apply to', () => {
    expect(outcomeOf('ack', [ok('a')], titles, { skipped: 2 })).toMatchObject({ tone: 'warn', text: 'Acknowledged 1 alert. 2 alerts selected did not apply and were left out.' })
  })
  it('explains a refused request', () => {
    expect(requestErrorText(403, 'forbidden')).toMatch(/alerts responder role/)
    expect(requestErrorText(400, 'reason must be 3 to 500 characters')).toBe('The server refused the request: reason must be 3 to 500 characters.')
    expect(requestErrorText(503, 'the actions could not be recorded; try again')).toMatch(/Try again in a moment/)
    expect(requestErrorText(500, '')).toBe('The request failed.')
  })
})

describe('details and history', () => {
  it('shows the annotations worth reading, the runbook first, URLs only when safe', () => {
    const rows = annotationRows({
      summary: 's', description: 'd', dedupe_key: 'k', kubesentry_url: 'https://x/#/a', incident_url: 'https://x/#/incidents/1',
      runbook_url: 'https://github.com/x/docs/alerts.md#a', examples: 'one\ntwo', predicted_oom: '2026-10-17T03:00:00Z', evil_url: 'javascript:alert(1)',
    })
    expect(rows.map((r) => r.key)).toEqual(['runbook_url', 'evil_url', 'examples', 'predicted_oom'])
    expect(rows[0]).toEqual({ key: 'runbook_url', label: 'Runbook', value: 'https://github.com/x/docs/alerts.md#a', href: 'https://github.com/x/docs/alerts.md#a' })
    expect(rows[1].href).toBeUndefined()
    expect(rows[1].label).toBe('Evil url')
    expect(rows[3].label).toBe('Predicted OOM kill')
    expect(annotationRows(undefined)).toEqual([])
  })
  it('tells the history in words, marking earlier episodes', () => {
    const first = iso(H)
    const acts: AlertAction[] = [
      { id: 3, key: recs.key, firstSeen: first, action: 'silence', actor: 'erin', reason: 'known', until: new Date(NOW + 4 * H).toISOString(), severity: 'critical', at: iso(0) },
      { id: 2, key: recs.key, firstSeen: first, action: 'unack', actor: 'dave', severity: 'critical', at: iso(10 * M) },
      { id: 1, key: recs.key, firstSeen: iso(30 * H), action: 'ack', actor: '', severity: 'warning', at: iso(29 * H) },
    ]
    const rows = historyRows(acts, first)
    expect(rows.map((r) => [r.actor, r.what.replace(/, until .*/, ''), r.earlier])).toEqual([
      ['erin', 'silenced for 4 hours', false],
      ['dave', 'removed the acknowledgement', false],
      ['someone', 'acknowledged', true],
    ])
    expect(rows[0].reason).toBe('known')
    expect(rows[1].reason).toBeUndefined()
  })
})

describe('the Overview widget', () => {
  it('links each state and owner to the Alerts page, busiest owner first', () => {
    const w = alertsWidget({ open: 7, acknowledged: 1, silenced: 1, byOwner: { 'team-platform': 3, 'team-shop': 5, 'team-data': 1, '': 2, gone: 0 } })
    expect(w.total).toBe(9)
    expect(w.href).toBe('#/alerts')
    expect(w.states).toEqual([
      { key: 'open', label: 'open', count: 7, href: '#/alerts?state=open' },
      { key: 'acknowledged', label: 'acknowledged', count: 1, href: '#/alerts?state=acknowledged' },
      { key: 'silenced', label: 'silenced', count: 1, href: '#/alerts?state=silenced' },
    ])
    expect(w.owners).toEqual([
      { owner: 'team-shop', label: 'team-shop', count: 5, href: '#/alerts?owner=team-shop' },
      { owner: 'team-platform', label: 'team-platform', count: 3, href: '#/alerts?owner=team-platform' },
      { owner: '', label: 'no owner', count: 2, href: undefined },
      { owner: 'team-data', label: 'team-data', count: 1, href: '#/alerts?owner=team-data' },
    ])
  })
  it("keeps the Overview's namespace and owner in its links", () => {
    const w = alertsWidget({ open: 1, acknowledged: 0, silenced: 0, byOwner: { 'team-shop': 1 } }, { namespace: 'prod', owner: 'team-shop' })
    expect(w.states[0].href).toBe('#/alerts?state=open&namespace=prod&owner=team-shop')
    expect(w.owners[0].href).toBe('#/alerts?namespace=prod&owner=team-shop')
    expect(w.href).toBe('#/alerts?namespace=prod&owner=team-shop')
  })
})
