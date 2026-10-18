// The AI investigator on the incident page, kept free of React so it is testable:
// what an evidence ref does when pressed, the range a timeline entry selects,
// the words and shapes for a run and its steps, the error texts, and when to
// poll. The model's words are only ever shown as plain text: nothing here
// builds markup or links from them.

import { can } from './access'
import type { Range } from './chartMath'
import { formatClock, formatDateTime, plural } from './format'
import type {
  Info,
  Investigation,
  InvestigationEvidence,
  InvestigationReport,
  InvestigationStatus,
  InvestigationStep,
  InvestigationSummary,
  Status,
} from './types'

/** A status shape (ui.tsx GlyphKind): ok, warn, crit, unknown, or the neutral info. */
export type Glyph = Status | 'info'

// ---- Whether to offer it, and what it sends where ----

/** The Investigate button shows when the server runs the investigator and the user may start runs somewhere. */
export function investigatorOn(info: Pick<Info, 'investigator' | 'capabilities'> | undefined): boolean {
  return info?.investigator?.enabled === true && can(info, 'investigate')
}

const PROVIDER: Record<string, string> = { anthropic: 'Anthropic', bedrock: 'Amazon Bedrock', demo: 'the demo investigator' }

export function providerName(p: string): string {
  return PROVIDER[p] ?? p
}

/** The data notice shown before the first run of an incident. */
export function egressNotice(inv: Info['investigator']): string {
  if (!inv) return ''
  if (inv.provider === 'demo') {
    return `This demo uses the offline demo investigator (${inv.model}): a scripted model inside this server, so nothing leaves it. Suggested commands are never run.`
  }
  return `Sends a redacted digest of this incident, and the logs, events, audit and CloudTrail records you may see, to ${providerName(inv.provider)} (${inv.model}). Suggested commands are never run.`
}

// ---- Routes ----

export function investigationsPath(incidentId: string): string {
  return `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigations`
}

export function investigationPath(incidentId: string, runId: string): string {
  return `${investigationsPath(incidentId)}/${encodeURIComponent(runId)}`
}

export function cancelPath(incidentId: string, runId: string): string {
  return `${investigationPath(incidentId, runId)}/cancel`
}

// ---- Polling ----

/** How often a running run is asked for again (docs/contracts.md: every 2s). */
export const POLL_MS = 2_000

export function isTerminal(s: InvestigationStatus | undefined): boolean {
  return s === 'completed' || s === 'refused' || s === 'failed' || s === 'cancelled'
}

/** The polling interval for a run: 2s while it runs, none once it has ended (or before it is known). */
export function pollMs(run: Pick<Investigation, 'status'> | undefined): number | undefined {
  return run?.status === 'running' ? POLL_MS : undefined
}

// ---- Words and shapes ----

export interface Look {
  word: string
  glyph: Glyph
}

export const RUN_STATUS: Record<InvestigationStatus, Look> = {
  running: { word: 'Running', glyph: 'unknown' },
  completed: { word: 'Completed', glyph: 'ok' },
  refused: { word: 'Declined by the model', glyph: 'warn' },
  failed: { word: 'Failed', glyph: 'crit' },
  cancelled: { word: 'Cancelled', glyph: 'unknown' },
}

export function runStatus(s: string): Look {
  return RUN_STATUS[s as InvestigationStatus] ?? { word: s || 'Unknown', glyph: 'unknown' }
}

export const OUTCOME: Record<InvestigationReport['status'], Look> = {
  root_cause_identified: { word: 'Root cause identified', glyph: 'ok' },
  likely_cause: { word: 'Likely cause', glyph: 'info' },
  inconclusive: { word: 'Inconclusive', glyph: 'unknown' },
}

export function outcome(s: string | undefined): Look | undefined {
  if (!s) return undefined
  return OUTCOME[s as InvestigationReport['status']] ?? { word: s.replace(/_/g, ' '), glyph: 'unknown' }
}

/** Confidence as a word and a meter of filled dots out of three (shape, not colour). */
export interface ConfidenceLook {
  word: string
  dots: number
}

export const CONFIDENCE: Record<InvestigationReport['root_cause']['confidence'], ConfidenceLook> = {
  high: { word: 'High confidence', dots: 3 },
  medium: { word: 'Medium confidence', dots: 2 },
  low: { word: 'Low confidence', dots: 1 },
}

export function confidence(c: string | undefined): ConfidenceLook | undefined {
  if (!c) return undefined
  return CONFIDENCE[c as keyof typeof CONFIDENCE] ?? { word: `${c} confidence`, dots: 0 }
}

/** "Likely cause, medium confidence" for a past run's line. */
export function outcomeText(s: Pick<InvestigationSummary, 'outcome' | 'confidence'>): string | undefined {
  const o = outcome(s.outcome)
  if (!o) return undefined
  const c = confidence(s.confidence)
  return c ? `${o.word}, ${c.word.toLowerCase()}` : o.word
}

// ---- Progress steps ----

export interface StepView {
  key: string
  kind: InvestigationStep['kind']
  /** The server's line, with "UTC" after its time span (the server writes UTC). */
  text: string
  glyph: Glyph
  /** What the shape means, for the label (visible unless it just says done). */
  word: string
  /** Show the word: anything but a tool call that worked. */
  loud: boolean
}

const STEP_RESULT: Record<string, Look> = {
  ok: { word: 'done', glyph: 'ok' },
  error: { word: 'failed', glyph: 'crit' },
  denied: { word: 'not permitted', glyph: 'warn' },
  invalid: { word: 'invalid input', glyph: 'warn' },
}

const SPAN = /((?:[A-Z][a-z]{2} \d{1,2} )?\d{2}:\d{2}–(?:[A-Z][a-z]{2} \d{1,2} )?\d{2}:\d{2})(?! UTC)/

/** Mark the time span in a step's text as UTC: "get_logs api error 12:01–12:20 UTC: 48 lines". */
export function utcSpan(text: string): string {
  return text.replace(SPAN, '$1 UTC')
}

export function stepView(s: InvestigationStep, i: number): StepView {
  const base = { key: `${i}:${s.at}`, kind: s.kind, text: utcSpan(s.text) }
  if (s.result && STEP_RESULT[s.result]) {
    const r = STEP_RESULT[s.result]
    return { ...base, ...r, loud: s.result !== 'ok' }
  }
  if (s.kind === 'turn') return { ...base, word: 'model turn', glyph: 'info', loud: false }
  if (s.kind === 'note') return { ...base, word: 'note', glyph: 'unknown', loud: false }
  return { ...base, word: 'done', glyph: 'ok', loud: false }
}

// ---- What a failed, declined or cached run says ----

/** A failed run's reason in words (the server's short reason stays visible in parentheses where it helps). */
export function failedText(error: string | undefined): string {
  const e = (error ?? '').trim()
  if (!e) return 'It stopped without saying why.'
  if (e === 'timeout') return 'It ran out of time (-investigator-timeout).'
  if (e === 'interrupted') return 'It was interrupted: the server running it stopped or restarted.'
  const budget = /^budget: (.+)$/.exec(e)
  if (budget) return `Its budget of ${budget[1]} ran out before the model gave a valid report.`
  if (e === 'no valid report') return 'The model did not give a valid report.'
  if (e.startsWith('max_tokens')) return 'A reply of the model exceeded the output limit twice.'
  if (e === 'context window exceeded') return "The conversation outgrew the model's context window."
  if (e === 'model request failed') return 'The model provider could not be reached.'
  if (/^HTTP \d{3}/.test(e)) return `The model provider answered ${e}.`
  return `${e[0].toUpperCase()}${e.slice(1)}.`
}

/** The model that answered when the requested one declined, from the run's notes. */
export interface Fallback {
  turn: number
  declined: string
  model: string
}

const FALLBACK = /^turn (\d+): (.+) declined; the fallback model (.+) answered$/

export function fallbacks(steps: readonly InvestigationStep[] | undefined): Fallback[] {
  const out: Fallback[] = []
  for (const s of steps ?? []) {
    if (s.kind !== 'note') continue
    const m = FALLBACK.exec(s.text)
    if (m) out.push({ turn: Number(m[1]), declined: m[2], model: m[3] })
  }
  return out
}

/** "demo-scripted on the demo investigator, effort high", and which turns a fallback model answered. */
export function modelText(run: Pick<Investigation, 'provider' | 'model' | 'effort' | 'steps'>): string {
  let s = `${run.model} on ${providerName(run.provider)}, effort ${run.effort}`
  const fb = fallbacks(run.steps)
  if (fb.length) {
    const models = [...new Set(fb.map((f) => f.model))].join(', ')
    const turns = fb.map((f) => f.turn).join(', ')
    s += `; ${models} answered ${plural(fb.length, 'turn', 'turns')} ${turns} after ${run.model} declined`
  }
  return s
}

/** "3 turns, 4 tool calls, 31,615 tokens (17,391 read from the cache)". */
export function usageText(run: Pick<Investigation, 'turns' | 'toolCalls' | 'usage' | 'cachedFrom'>): string {
  const n = (x: number) => x.toLocaleString('en-US')
  const parts = `${n(run.turns)} ${plural(run.turns, 'turn', 'turns')}, ${n(run.toolCalls)} ${plural(run.toolCalls, 'tool call', 'tool calls')}`
  const u = run.usage ?? { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }
  const total = u.input + u.output + u.cacheRead + u.cacheWrite
  if (run.cachedFrom && total === 0) return `${parts} in the earlier run; no new tokens`
  let s = `${parts}, ${n(total)} ${plural(total, 'token', 'tokens')}`
  if (u.cacheRead > 0) s += ` (${n(u.cacheRead)} read from the prompt cache)`
  return s
}

/** The creation time a run's ID starts with (20261016T120102Z-…), or undefined. */
export function idTime(id: string): number | undefined {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z-/.exec(id)
  if (!m) return undefined
  const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6])
  return Number.isNaN(t) ? undefined : t
}

/** When the run a cached copy came from was made: from the list when it is there, else from its ID. */
export function cachedFromTime(run: Pick<Investigation, 'cachedFrom'>, runs: readonly InvestigationSummary[] = []): number | undefined {
  if (!run.cachedFrom) return undefined
  const orig = runs.find((r) => r.id === run.cachedFrom)
  const t = orig ? Date.parse(orig.createdAt) : NaN
  return Number.isFinite(t) ? t : idTime(run.cachedFrom)
}

/** "From an earlier run at Oct 17, 16:04, with the same input: no new model call." */
export function cachedText(run: Pick<Investigation, 'cachedFrom'>, runs: readonly InvestigationSummary[] = []): string | undefined {
  if (!run.cachedFrom) return undefined
  const t = cachedFromTime(run, runs)
  const at = t !== undefined ? ` at ${formatDateTime(t)}` : ''
  return `From an earlier run${at}, with the same input: no new model call, and it did not count against the hourly limit.`
}

/** Sections a run left out: "Logs: not permitted for you". */
const SECTION: Record<string, string> = {
  logs: 'Logs',
  audit: 'Audit log',
  cloudtrail: 'CloudTrail',
  nodes: 'Node events and conditions',
  events: 'Kubernetes events',
  series: 'Metrics',
}

export function omittedRows(omitted: Record<string, string> | undefined): string[] {
  return Object.entries(omitted ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${SECTION[k] ?? k}: ${v === 'forbidden' ? 'not permitted for you' : v}`)
}

/** Who may cancel: the starter. Without an identity (an unrestricted server) the server decides. */
export function canCancel(run: Pick<Investigation, 'status' | 'requestedBy'>, user: string | undefined, startedHere: boolean): boolean {
  if (run.status !== 'running') return false
  return startedHere || user === undefined || user === run.requestedBy
}

/** What the live region says when a run changes state. */
export function announceText(run: Pick<Investigation, 'status' | 'error' | 'refusal' | 'cachedFrom' | 'outcome' | 'confidence'>): string {
  switch (run.status) {
    case 'running':
      return 'Investigation running.'
    case 'completed': {
      const o = outcomeText(run)
      return `Investigation ${run.cachedFrom ? 'answered from an earlier run' : 'completed'}${o ? `: ${o.toLowerCase()}` : ''}.`
    }
    case 'refused':
      return `The model declined the investigation${run.refusal?.category ? ` (${run.refusal.category})` : ''}.`
    case 'failed':
      return `Investigation failed: ${failedText(run.error)}`
    case 'cancelled':
      return 'Investigation cancelled.'
  }
  return ''
}

// ---- Errors from starting and cancelling ----

export interface Failure {
  status?: number
  message: string
  retryAfterMs?: number
}

/** "40 seconds", "12 minutes", "2 hours", rounded up. */
export function waitText(ms: number | undefined): string | undefined {
  if (ms === undefined || !Number.isFinite(ms) || ms <= 0) return undefined
  const s = Math.ceil(ms / 1000)
  if (s < 60) return `${s} ${plural(s, 'second', 'seconds')}`
  const m = Math.ceil(s / 60)
  if (m < 90) return `${m} ${plural(m, 'minute', 'minutes')}`
  const h = Math.ceil(m / 60)
  return `${h} ${plural(h, 'hour', 'hours')}`
}

function sentence(msg: string): string {
  const m = msg.replace(/^investigate:\s*/, '').trim()
  if (!m) return ''
  return `${m[0].toUpperCase()}${m.slice(1)}`.replace(/[.;\s]+$/, '')
}

/** Why a start failed, in words, with when to try again where the server said. */
export function startErrorText(e: Failure): string {
  const wait = waitText(e.retryAfterMs)
  const again = wait ? ` Try again in ${wait}.` : ' Try again later.'
  switch (e.status) {
    case 403:
      return `You may not investigate this incident: ${sentence(e.message).replace(/^./, (c) => c.toLowerCase()) || 'that needs the kubesentry investigator role'}.`
    case 404:
      return 'This incident is no longer stored, or this server does not run the investigator.'
    case 409:
      return 'An investigation of this incident is already running.'
    case 429:
      return `${sentence(e.message) || 'The hourly limit of investigations is reached'}.${again}`
    case 503:
      return `This server is running as many investigations as it may.${wait ? ` Try again in ${wait}.` : ' Try again shortly.'}`
    case 400:
    case 413:
    case 415:
      return `The server refused the request: ${sentence(e.message)}.`
    case 401:
      return 'Your sign-in expired. Reload the page to sign in again.'
  }
  return sentence(e.message) ? `${sentence(e.message)}.` : 'The request failed.'
}

export function cancelErrorText(e: Failure): string {
  switch (e.status) {
    case 403:
      return 'Only the person who started an investigation may cancel it.'
    case 404:
      return 'The investigation is gone.'
    case 409:
      return 'The investigation has already finished.'
  }
  return startErrorText(e)
}

// ---- Evidence refs ----

export type RefKind = 'signal' | 'event' | 'log' | 'logtpl' | 'audit' | 'cloudtrail' | 'metric'

const KINDS = new Set<string>(['signal', 'event', 'log', 'logtpl', 'audit', 'cloudtrail', 'metric'])
const METRICS = new Set(['memory', 'requests', 'errors'])

export interface ParsedRef {
  ref: string
  kind: RefKind | 'unknown'
  /** Everything after the kind. */
  id: string
  /** metric refs: the metric and the series label (which may hold colons). */
  metric?: string
  label?: string
}

export function parseRef(ref: string): ParsedRef {
  const i = ref.indexOf(':')
  const k = i > 0 ? ref.slice(0, i) : ''
  const id = i > 0 ? ref.slice(i + 1) : ref
  if (!KINDS.has(k) || id === '') return { ref, kind: 'unknown', id: ref }
  if (k === 'metric') {
    const j = id.indexOf(':')
    if (j > 0 && METRICS.has(id.slice(0, j)) && j < id.length - 1) return { ref, kind: 'metric', id, metric: id.slice(0, j), label: id.slice(j + 1) }
    return { ref, kind: 'metric', id, label: id }
  }
  return { ref, kind: k as RefKind, id }
}

/**
 * The incident page's lane item a ref points at (mergeTimeline's keys): a
 * k8s-event or audit-change signal shows as its event or audit record when the
 * page has it; a CloudTrail record is its signal.
 */
export function laneKeyOf(p: ParsedRef, keys: ReadonlySet<string>): string | undefined {
  const tries: string[] = []
  switch (p.kind) {
    case 'signal':
      if (p.id.startsWith('events:')) tries.push(`event:${p.id.slice(7).replace(/#\d+$/, '')}`)
      if (p.id.startsWith('audit:')) tries.push(`audit:${p.id.slice(6)}`)
      tries.push(`signal:${p.id}`)
      break
    case 'event':
      tries.push(`event:${p.id}`)
      break
    case 'audit':
      tries.push(`audit:${p.id}`, `signal:audit:${p.id}`)
      break
    case 'cloudtrail':
      tries.push(`signal:cloudtrail:${p.id}`)
      break
    default:
      return undefined
  }
  for (const t of tries) if (keys.has(t)) return t
  if (p.kind === 'event') {
    const prefix = `signal:events:${p.id}#`
    for (const k of keys) if (k.startsWith(prefix)) return k
  }
  return undefined
}

/** How the log panel narrows for a log ref. */
export interface LogFocus {
  pod?: string
  container?: string
  /** Search text (a template's longest literal part). */
  q?: string
}

/**
 * What pressing an evidence ref does on the page:
 * - lane: highlight that item in the lanes and move the crosshair to it (signals, events);
 * - logs: narrow the log panel (pod, container, search) and select ±2 minutes around the line (log), or the whole window (logtpl);
 * - charts: select ±2 minutes around a metric's peak;
 * - record: open the evidence record in place (audit, CloudTrail), with its lane item when the page shows it;
 * - text: nothing to show; `unverified` refs were never shown to the model.
 */
export type RefAction =
  | { kind: 'lane'; key: string; t?: number }
  | { kind: 'logs'; focus: LogFocus; range: Range | null; t?: number }
  | { kind: 'charts'; range: Range; metric?: string; label?: string }
  | { kind: 'record'; evidence: InvestigationEvidence; key?: string; t?: number }
  | { kind: 'text'; reason: 'unverified' | 'missing' }

export interface RefContext {
  evidence: ReadonlyMap<string, InvestigationEvidence>
  unverified: ReadonlySet<string>
  laneKeys: ReadonlySet<string>
  domain: Range
}

function evTime(ev: InvestigationEvidence | undefined): number | undefined {
  const t = ev?.time ? Date.parse(ev.time) : NaN
  return Number.isFinite(t) ? t : undefined
}

/** "pod/container" → its parts. */
function podContainer(object: string | undefined): { pod?: string; container?: string } {
  const o = (object ?? '').trim()
  if (!o) return {}
  const i = o.indexOf('/')
  return i < 0 ? { pod: o } : { pod: o.slice(0, i) || undefined, container: o.slice(i + 1) || undefined }
}

const PLACEHOLDER = /\{(?:ts|uuid|ip|hex|n)\}|\[REDACTED[^\]]*\]|…/

/** The longest literal part of a log template, to search the log panel with; undefined when too short to help. */
export function templateSearch(template: string | undefined): string | undefined {
  if (!template) return undefined
  let best = ''
  for (const part of template.split(new RegExp(PLACEHOLDER, 'g'))) {
    const p = part.replace(/^[\s:;,]+|[\s:;,]+$/g, '')
    if (p.length > best.length) best = p
  }
  if (best.length < 6) return undefined
  return best.length > 120 ? best.slice(0, 120).trimEnd() : best
}

export function refAction(ref: string, c: RefContext): RefAction {
  const p = parseRef(ref)
  if (c.unverified.has(ref) || p.kind === 'unknown') return { kind: 'text', reason: 'unverified' }
  const ev = c.evidence.get(ref)
  const t = evTime(ev)
  switch (p.kind) {
    case 'signal':
    case 'event': {
      const key = laneKeyOf(p, c.laneKeys)
      if (key) return { kind: 'lane', key, t }
      return ev ? { kind: 'record', evidence: ev, t } : { kind: 'text', reason: 'missing' }
    }
    case 'audit':
    case 'cloudtrail': {
      const key = laneKeyOf(p, c.laneKeys)
      if (ev) return { kind: 'record', evidence: ev, key, t }
      return key ? { kind: 'lane', key, t } : { kind: 'text', reason: 'missing' }
    }
    case 'log': {
      if (!ev) return { kind: 'text', reason: 'missing' }
      return { kind: 'logs', focus: podContainer(ev.object), range: t !== undefined ? brushAround(t, c.domain) : null, t }
    }
    case 'logtpl': {
      if (!ev) return { kind: 'text', reason: 'missing' }
      const pods = (ev.object ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
      return { kind: 'logs', focus: { pod: pods.length === 1 ? pods[0] : undefined, q: templateSearch(ev.snippet) }, range: null, t }
    }
    case 'metric': {
      const range = t !== undefined ? brushAround(t, c.domain) : null
      return range ? { kind: 'charts', range, metric: p.metric, label: p.label } : { kind: 'text', reason: 'missing' }
    }
  }
}

const KIND_WORD: Record<RefKind, string> = {
  signal: 'Signal',
  event: 'Event',
  log: 'Log line',
  logtpl: 'Log pattern',
  audit: 'Audit',
  cloudtrail: 'CloudTrail',
  metric: 'Metric',
}

const METRIC_WORD: Record<string, string> = { memory: 'Memory', requests: 'Requests', errors: 'Error rate' }

function cut(s: string, n: number): string {
  const t = s.replace(/\s+/g, ' ').trim()
  return t.length > n ? `${t.slice(0, n - 1).trimEnd()}…` : t
}

/** A ref's button: a kind word and a short text from the evidence index. */
export interface RefLabel {
  kind: string
  text: string
  /** The whole snippet and the ref, for the title. */
  title: string
}

export function refLabel(ref: string, ev: InvestigationEvidence | undefined): RefLabel {
  const p = parseRef(ref)
  const t = evTime(ev)
  const clock = t !== undefined ? formatClock(t) : ''
  const title = [ref, ev?.object, ev?.snippet].filter(Boolean).join('\n')
  if (p.kind === 'unknown') return { kind: 'Ref', text: cut(ref, 70), title: ref }
  const kind = KIND_WORD[p.kind]
  let text: string
  switch (p.kind) {
    case 'metric':
      text = `${METRIC_WORD[p.metric ?? ''] ?? p.metric ?? ''} ${p.label ?? ''}`.trim() + (clock ? `, peak ${clock}` : '')
      break
    case 'log':
      text = [clock, ev?.object].filter(Boolean).join(' ') || p.id
      break
    case 'logtpl':
      text = ev?.snippet ? cut(ev.snippet, 70) : `pattern ${p.id}`
      break
    default:
      text = ev?.snippet ? cut(ev.snippet, 70) : cut(p.id, 70)
      if (clock && (p.kind === 'audit' || p.kind === 'cloudtrail' || p.kind === 'event')) text = `${clock} ${text}`
  }
  return { kind, text: cut(text, 90), title }
}

// ---- Timeline entries and suggested checks ----

/** ±2 minutes around t, inside the domain: moved (not cut) at its edges while the domain is wide enough. */
export function brushAround(t: number, domain: Range, halfMs = 120_000): Range | null {
  if (!Number.isFinite(t) || !(domain[1] > domain[0])) return null
  const c = Math.min(domain[1], Math.max(domain[0], t))
  let a = c - halfMs
  let b = c + halfMs
  if (a < domain[0]) {
    b = Math.min(domain[1], b + (domain[0] - a))
    a = domain[0]
  }
  if (b > domain[1]) {
    a = Math.max(domain[0], a - (b - domain[1]))
    b = domain[1]
  }
  return [a, b]
}

/** The range a timeline entry selects on the charts; null when its time is unreadable. */
export function timelineRange(time: string, domain: Range): Range | null {
  return brushAround(Date.parse(time), domain)
}

export const COMMAND_REMOVED = '(command removed: not read-only)'

export interface CheckView {
  description: string
  command?: string
  /** The server removed a command that was not read-only. */
  removed: boolean
}

export function checkView(c: { description: string; command: string }): CheckView {
  const d = c.description.trim()
  if (d.endsWith(COMMAND_REMOVED)) return { description: d.slice(0, -COMMAND_REMOVED.length).trim(), removed: true }
  const cmd = c.command.trim()
  return { description: d, command: cmd || undefined, removed: false }
}

// ---- Past runs ----

/** The run to show: the one asked for when it is listed or just started, else the newest. */
export function chosenRun(items: readonly InvestigationSummary[], asked: string | undefined, started?: string): string | undefined {
  if (asked && (asked === started || items.some((i) => i.id === asked))) return asked
  return items[0]?.id
}

/** "kubesentry:anonymous, Oct 17, 16:04" and whether it came from the cache. */
export function runByline(s: Pick<InvestigationSummary, 'requestedBy' | 'createdAt' | 'cachedFrom'>): string {
  return `${s.requestedBy}, ${formatDateTime(s.createdAt)}${s.cachedFrom ? ', from an earlier run' : ''}`
}

/** The note under the past runs when some used data this user cannot see. */
export function hiddenRunsText(hidden: number): string | undefined {
  if (!(hidden > 0)) return undefined
  return `${hidden} other ${plural(hidden, 'investigation', 'investigations')} of this incident used data you may not see (logs, audit, CloudTrail or nodes), so ${plural(hidden, 'it is', 'they are')} not listed.`
}
