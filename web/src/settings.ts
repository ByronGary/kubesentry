// The Settings page's logic, kept free of React so it is testable: the
// form for the AI investigator's settings, where each value comes from,
// what a save sends and what its answer means, and how a connection test
// reads. The server checks everything again (internal/settings).

import type {
  ConnectionTestResult,
  InvestigatorSettings,
  InvestigatorValues,
  SettingChange,
  SettingSource,
  SettingsAuditEntry,
  SettingsCredentials,
  SetupTab,
} from './types'
import { formatDateTime } from './format'

/** Readable names of the fields, as the server names them. */
export const FIELD_LABEL: Record<string, string> = {
  enabled: 'AI investigator',
  provider: 'Provider',
  model: 'Model',
  effort: 'Effort',
  region: 'Region',
  bedrockAPI: 'Bedrock API',
  endpoint: 'Endpoint',
  fallback: 'Refusal fallback',
  'limits.perHour': 'Runs per person per hour',
  'limits.perHourTotal': 'Runs per hour, everyone',
  'limits.concurrency': 'Runs at once per replica',
  'limits.maxTurns': 'Model turns per run',
  'limits.maxToolCalls': 'Tool calls per run',
  'limits.maxTokens': 'Tokens per run',
  'limits.timeout': 'Time per run',
}

export const PROVIDER_LABEL: Record<string, string> = {
  bedrock: 'Amazon Bedrock',
  anthropic: 'Anthropic API',
  demo: 'Demo (scripted)',
}

export const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'] as const

/** "from Helm", or "changed by alice on 18 Oct 2026, 09:00". */
export function sourceText(src: SettingSource | undefined): string {
  if (!src || src.source !== 'ui') return 'from Helm'
  const who = src.by ? ` by ${src.by}` : ''
  const when = src.at ? ` on ${formatDateTime(src.at)}` : ''
  return `changed${who}${when}`
}

/** A value as the page shows it: the default spelled out when empty. */
export function valueText(field: string, v: string, values?: Pick<InvestigatorValues, 'provider'>, defaultRegion?: string): string {
  if (v !== '') {
    if (field === 'enabled') return v === 'true' ? 'on' : 'off'
    if (field === 'provider') return PROVIDER_LABEL[v] ?? v
    return v
  }
  switch (field) {
    case 'model':
      if (!values) return 'default'
      return values.provider === 'bedrock' ? `default (${DEFAULT_BEDROCK_MODEL})` : `default (${DEFAULT_ANTHROPIC_MODEL})`
    case 'region':
      return defaultRegion ? `default (${defaultRegion})` : 'default'
    case 'bedrockAPI':
      return 'default (mantle)'
    case 'endpoint':
      return 'none'
  }
  return '(empty)'
}

export const DEFAULT_BEDROCK_MODEL = 'anthropic.claude-opus-5-5'
export const DEFAULT_ANTHROPIC_MODEL = 'claude-opus-5-5'

// ---- the form ----

/** The form keeps numbers as text, as typed. */
export interface Form {
  provider: string
  model: string
  effort: string
  region: string
  bedrockAPI: string
  endpoint: string
  fallback: string
  perHour: string
  perHourTotal: string
  concurrency: string
  maxTurns: string
  maxToolCalls: string
  maxTokens: string
  timeout: string
}

export function toForm(v: InvestigatorValues): Form {
  const l = v.limits
  return {
    provider: v.provider,
    model: v.model,
    effort: v.effort,
    region: v.region,
    bedrockAPI: v.bedrockAPI || 'mantle',
    endpoint: v.endpoint,
    fallback: v.fallback,
    perHour: String(l.perHour),
    perHourTotal: String(l.perHourTotal),
    concurrency: String(l.concurrency),
    maxTurns: String(l.maxTurns),
    maxToolCalls: String(l.maxToolCalls),
    maxTokens: String(l.maxTokens),
    timeout: l.timeout,
  }
}

/** Which field of the server's a form field is. */
export const FORM_FIELD: Record<keyof Form, string> = {
  provider: 'provider',
  model: 'model',
  effort: 'effort',
  region: 'region',
  bedrockAPI: 'bedrockAPI',
  endpoint: 'endpoint',
  fallback: 'fallback',
  perHour: 'limits.perHour',
  perHourTotal: 'limits.perHourTotal',
  concurrency: 'limits.concurrency',
  maxTurns: 'limits.maxTurns',
  maxToolCalls: 'limits.maxToolCalls',
  maxTokens: 'limits.maxTokens',
  timeout: 'limits.timeout',
}

const INT_RANGE: Partial<Record<keyof Form, [number, number]>> = {
  perHour: [1, 10_000],
  perHourTotal: [1, 100_000],
  concurrency: [1, 100],
  maxTurns: [1, 100],
  maxToolCalls: [1, 200],
  maxTokens: [10_000, 100_000_000],
}

/** Go-style durations the server accepts: "10m", "90s", "1h30m". */
export function parseDuration(s: string): number | undefined {
  const t = s.trim()
  if (!/^(\d+(\.\d+)?(h|m|s|ms))+$/.test(t)) return undefined
  let ms = 0
  for (const m of t.matchAll(/(\d+(?:\.\d+)?)(ms|h|m|s)/g)) {
    const n = Number(m[1])
    ms += m[2] === 'h' ? n * 3_600_000 : m[2] === 'm' ? n * 60_000 : m[2] === 's' ? n * 1000 : n
  }
  return ms
}

const MODEL_RE = /^[A-Za-z0-9._:/@-]{1,200}$/
const REGION_RE = /^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$/

/**
 * The values a form stands for, on top of `base` (the saved values, whose
 * `enabled` it keeps), and what is wrong with it, by server field name.
 */
export function fromForm(f: Form, base: InvestigatorValues): { values: InvestigatorValues; errors: Record<string, string> } {
  const errors: Record<string, string> = {}
  const int = (k: keyof Form): number => {
    const raw = f[k].trim()
    const n = Number(raw)
    const [lo, hi] = INT_RANGE[k] ?? [0, Number.MAX_SAFE_INTEGER]
    if (raw === '' || !Number.isInteger(n) || n < lo || n > hi) {
      errors[FORM_FIELD[k]] = `Must be a whole number from ${lo.toLocaleString('en-US')} to ${hi.toLocaleString('en-US')}.`
    }
    return Number.isFinite(n) ? n : 0
  }
  if (f.provider !== 'anthropic' && f.provider !== 'bedrock') errors.provider = 'Choose Amazon Bedrock or the Anthropic API.'
  const model = f.model.trim()
  if (model !== '' && !MODEL_RE.test(model)) errors.model = 'A model ID, an inference-profile ID or an ARN: letters, digits and . _ : / @ -'
  if (!(EFFORTS as readonly string[]).includes(f.effort)) errors.effort = 'Choose an effort.'
  const region = f.region.trim()
  if (region !== '' && !REGION_RE.test(region)) errors.region = 'An AWS region such as us-east-1.'
  if (f.bedrockAPI !== 'mantle' && f.bedrockAPI !== 'runtime') errors.bedrockAPI = 'Choose mantle or runtime.'
  const endpoint = f.endpoint.trim()
  if (endpoint !== '') {
    let ok = false
    try {
      const u = new URL(endpoint)
      ok = (u.protocol === 'https:' || u.protocol === 'http:') && u.host !== '' && u.username === '' && u.password === ''
    } catch {
      ok = false
    }
    if (!ok) errors.endpoint = 'An http(s) URL, without credentials.'
  }
  const fallback = f.fallback.trim()
  if (fallback === '' || (fallback !== 'auto' && fallback !== 'off' && !MODEL_RE.test(fallback))) errors.fallback = 'auto, off or a model ID.'
  const timeoutMs = parseDuration(f.timeout)
  if (timeoutMs === undefined || timeoutMs < 60_000 || timeoutMs > 3_600_000) errors['limits.timeout'] = 'Between 1m and 1h, e.g. 10m.'
  const values: InvestigatorValues = {
    enabled: base.enabled,
    provider: f.provider as InvestigatorValues['provider'],
    model,
    effort: f.effort as InvestigatorValues['effort'],
    region,
    bedrockAPI: f.bedrockAPI as InvestigatorValues['bedrockAPI'],
    endpoint,
    fallback,
    limits: {
      perHour: int('perHour'),
      perHourTotal: int('perHourTotal'),
      concurrency: int('concurrency'),
      maxTurns: int('maxTurns'),
      maxToolCalls: int('maxToolCalls'),
      maxTokens: int('maxTokens'),
      timeout: f.timeout.trim(),
    },
  }
  return { values, errors }
}

/** A field's value as text, by server name (as Change carries it). */
export function fieldValue(v: InvestigatorValues, field: string): string {
  if (field === 'enabled') return String(v.enabled)
  if (field.startsWith('limits.')) return String(v.limits[field.slice(7) as keyof InvestigatorValues['limits']])
  return String(v[field as keyof Omit<InvestigatorValues, 'limits' | 'enabled'>] ?? '')
}

/** Durations compare by length: "60m" and "1h" are the same. */
function sameValue(field: string, a: string, b: string): boolean {
  if (field === 'limits.timeout') {
    const x = parseDuration(a)
    const y = parseDuration(b)
    if (x !== undefined && y !== undefined) return x === y
  }
  if (field === 'bedrockAPI') return (a || 'mantle') === (b || 'mantle')
  return a === b
}

/** The fields that differ, old → new. */
export function changes(from: InvestigatorValues, to: InvestigatorValues, fields: string[]): SettingChange[] {
  const out: SettingChange[] = []
  for (const f of fields) {
    const a = fieldValue(from, f)
    const b = fieldValue(to, f)
    if (!sameValue(f, a, b)) out.push({ field: f, old: a, new: b })
  }
  return out
}

/** Fields whose value comes from the UI, not Helm. */
export function overridden(s: Pick<InvestigatorSettings, 'sources'>): string[] {
  return Object.entries(s.sources)
    .filter(([, v]) => v.source === 'ui')
    .map(([k]) => k)
}

/** Turning it on needs the admin's acknowledgement unless the platform gave it. */
export function needsAck(s: Pick<InvestigatorSettings, 'values' | 'egressAckByPlatform'>, next: { enabled: boolean }): boolean {
  return next.enabled && !s.values.enabled && !s.egressAckByPlatform
}

/** Why the toggle cannot be used, or undefined. */
export function toggleBlocked(s: InvestigatorSettings): string | undefined {
  if (s.locked) return 'Locked by Helm: change incidents.investigator in the chart’s values.'
  if (!s.values.enabled && !s.incidents) return 'The investigator investigates incidents: turn incidents on first (-incidents, incidents.enabled).'
  return undefined
}

// ---- save answers ----

export interface SaveError {
  message: string
  /** Server field name → message. */
  fields: Record<string, string>
  conflict?: boolean
  locked?: boolean
  egressAckRequired?: boolean
}

/** What a failed save means, from the status and the JSON error body. */
export function saveError(status: number, message: string, body?: Record<string, unknown>): SaveError {
  const fields: Record<string, string> = {}
  if (Array.isArray(body?.fields)) {
    for (const f of body.fields as { field?: unknown; message?: unknown }[]) {
      if (typeof f.field === 'string' && typeof f.message === 'string') fields[f.field] = sentence(f.message)
    }
  }
  if (status === 409 && body?.locked === true) return { message: 'Locked by Helm: these settings can only change in the chart’s values.', fields, locked: true }
  if (status === 409) return { message: 'Someone else changed these settings since you loaded them. Reload to see their change, then try again.', fields, conflict: true }
  if (status === 400 && body?.egressAckRequired === true) {
    return { message: 'Turning the investigator on needs the data egress acknowledgement.', fields, egressAckRequired: true }
  }
  if (status === 403) return { message: 'You may not change the settings: it needs the kubesentry settings admin role.', fields }
  if (status === 422) return { message: `The settings could not be applied: ${message}`, fields }
  if (status === 400 && Object.keys(fields).length > 0) return { message: 'Some values are not valid; see the fields marked below.', fields }
  return { message: message || `The save failed (HTTP ${status}).`, fields }
}

function sentence(s: string): string {
  const t = s.trim()
  if (!t) return t
  return t[0].toUpperCase() + t.slice(1) + (/[.!?]$/.test(t) ? '' : '.')
}

// ---- connection ----

export function credentialText(c: SettingsCredentials): string {
  if (c.kind === 'irsa' && c.roleArn) return `${c.label}: ${c.roleArn}`
  if (c.kind === 'profile' && c.roleArn) return `${c.label}, role ${c.roleArn}`
  return c.label
}

export interface TestSummary {
  status: 'ok' | 'warn' | 'crit'
  title: string
  /** Label, value pairs. */
  facts: [string, string][]
  message?: string
  hint?: string
}

const TEST_TITLE: Record<string, string> = {
  no_credentials: 'No AWS credentials',
  access_denied: 'Access denied',
  model_access: 'Model access not enabled',
  model_unavailable: 'Model not available',
  network: 'Endpoint unreachable',
  auth: 'Anthropic API key missing or invalid',
  throttled: 'Throttled (the connection works)',
  config: 'Settings incomplete',
  other: 'The test failed',
}

/** How a test result reads. */
export function testSummary(r: ConnectionTestResult): TestSummary {
  const facts: [string, string][] = []
  if (r.identityArn) facts.push(['Identity', r.identityArn])
  if (r.credentialSource) facts.push(['Credentials', r.credentialSource])
  if (r.region) facts.push(['Region', r.region])
  facts.push(['Endpoint', r.endpoint])
  facts.push(['Model', r.model])
  if (r.error?.action) facts.push(['Denied action', r.error.action])
  facts.push(['Took', `${r.latencyMs.toLocaleString('en-US')} ms`])
  if (r.ok) return { status: 'ok', title: 'Connected: the model answered', facts }
  const e = r.error
  const kind = e?.kind ?? 'other'
  return { status: kind === 'throttled' ? 'warn' : 'crit', title: TEST_TITLE[kind] ?? TEST_TITLE.other, facts, message: e?.message, hint: e?.hint }
}

// ---- setup and audit ----

/** The tabs with the recommended one marked. */
export function setupTabs(s: Pick<InvestigatorSettings, 'setup'>): (SetupTab & { recommended: boolean })[] {
  return s.setup.tabs.map((t) => ({ ...t, recommended: t.id === s.setup.recommended }))
}

/** One audit entry as a line: "alice turned the AI investigator on, model … → …". */
export function auditLines(e: SettingsAuditEntry): string[] {
  if (e.changes.length === 0) return [e.action === 'reset' ? 'Reset to the Helm values (nothing changed).' : 'Saved (nothing changed).']
  return e.changes.map((c) => {
    if (c.field === 'enabled') return c.new === 'true' ? 'Turned the AI investigator on' : 'Turned the AI investigator off'
    const label = FIELD_LABEL[c.field] ?? c.field
    return `${label}: ${valueText(c.field, c.old)} → ${valueText(c.field, c.new)}`
  })
}

export function auditAck(e: SettingsAuditEntry): string | undefined {
  if (e.egressAcknowledged) return 'Acknowledged the data egress'
  if (e.egressAckByPlatform) return 'Data egress acknowledged by the platform (Helm)'
  return undefined
}
