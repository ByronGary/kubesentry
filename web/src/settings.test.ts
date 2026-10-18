import { describe, expect, it } from 'vitest'
import {
  auditAck,
  auditLines,
  changes,
  credentialText,
  fieldValue,
  fromForm,
  needsAck,
  overridden,
  parseDuration,
  saveError,
  setupTabs,
  sourceText,
  testSummary,
  toForm,
  toggleBlocked,
  valueText,
} from './settings'
import type { InvestigatorSettings, InvestigatorValues } from './types'

const FIELDS = [
  'enabled',
  'provider',
  'model',
  'effort',
  'region',
  'bedrockAPI',
  'endpoint',
  'fallback',
  'limits.perHour',
  'limits.perHourTotal',
  'limits.concurrency',
  'limits.maxTurns',
  'limits.maxToolCalls',
  'limits.maxTokens',
  'limits.timeout',
]

const helm: InvestigatorValues = {
  enabled: false,
  provider: 'bedrock',
  model: '',
  effort: 'high',
  region: 'us-east-1',
  bedrockAPI: 'mantle',
  endpoint: '',
  fallback: 'auto',
  limits: { perHour: 10, perHourTotal: 60, concurrency: 2, maxTurns: 16, maxToolCalls: 24, maxTokens: 1_500_000, timeout: '10m' },
}

function settings(over: Partial<InvestigatorSettings> = {}): InvestigatorSettings {
  return {
    values: helm,
    helm,
    sources: Object.fromEntries(FIELDS.map((f) => [f, { source: 'helm' as const }])),
    mode: 'ui',
    locked: false,
    version: 0,
    applied: { enabled: false },
    audit: [],
    egressAckByPlatform: false,
    incidents: true,
    anthropicKey: false,
    defaultRegion: 'us-east-1',
    environment: { kind: 'eks', label: 'In-cluster on Amazon EKS', cluster: 'demo-eks' },
    credentials: { kind: 'irsa', label: 'IRSA (IAM role for the service account)', roleArn: 'arn:aws:iam::111122223333:role/ks', anthropicKey: false },
    setup: {
      recommended: 'irsa',
      tabs: [
        { id: 'irsa', title: 'EKS: IRSA', summary: '', steps: [] },
        { id: 'anthropic', title: 'Anthropic API', summary: '', steps: [] },
      ],
    },
    options: { providers: ['bedrock', 'anthropic'], bedrockAPIs: ['mantle', 'runtime'], efforts: ['low', 'medium', 'high', 'xhigh', 'max'], fields: FIELDS },
    ...over,
  }
}

describe('sources and values', () => {
  it('says where a value comes from', () => {
    expect(sourceText(undefined)).toBe('from Helm')
    expect(sourceText({ source: 'helm' })).toBe('from Helm')
    const t = sourceText({ source: 'ui', by: 'alice', at: '2026-10-18T09:00:00Z' })
    expect(t).toMatch(/^changed by alice on /)
    expect(sourceText({ source: 'ui' })).toBe('changed')
  })
  it('spells out defaults', () => {
    expect(valueText('model', '', { provider: 'bedrock' })).toBe('default (anthropic.claude-opus-5-5)')
    expect(valueText('model', '', { provider: 'anthropic' })).toBe('default (claude-opus-5-5)')
    expect(valueText('region', '', undefined, 'eu-west-1')).toBe('default (eu-west-1)')
    expect(valueText('enabled', 'true')).toBe('on')
    expect(valueText('provider', 'bedrock')).toBe('Amazon Bedrock')
    expect(valueText('endpoint', '')).toBe('none')
  })
  it('lists the overridden fields', () => {
    const s = settings({ sources: { ...settings().sources, model: { source: 'ui', by: 'a' } } })
    expect(overridden(s)).toEqual(['model'])
  })
})

describe('the form', () => {
  it('round-trips the values', () => {
    const { values, errors } = fromForm(toForm(helm), helm)
    expect(errors).toEqual({})
    expect(values).toEqual(helm)
    expect(changes(helm, values, FIELDS)).toEqual([])
  })
  it('keeps enabled from the saved values', () => {
    expect(fromForm(toForm(helm), { ...helm, enabled: true }).values.enabled).toBe(true)
  })
  it('checks every field as the server does', () => {
    const f = {
      ...toForm(helm),
      provider: 'openai',
      model: 'claude opus',
      effort: 'extreme',
      region: 'Mars',
      bedrockAPI: 'converse',
      endpoint: 'ftp://proxy',
      fallback: '',
      perHour: '0',
      perHourTotal: '1.5',
      concurrency: '',
      maxTurns: '101',
      maxToolCalls: '201',
      maxTokens: '10',
      timeout: '30s',
    }
    const { errors } = fromForm(f, helm)
    expect(Object.keys(errors).sort()).toEqual(
      [
        'bedrockAPI',
        'effort',
        'endpoint',
        'fallback',
        'limits.concurrency',
        'limits.maxTokens',
        'limits.maxToolCalls',
        'limits.maxTurns',
        'limits.perHour',
        'limits.perHourTotal',
        'limits.timeout',
        'model',
        'provider',
        'region',
      ].sort(),
    )
    expect(fromForm({ ...toForm(helm), endpoint: 'https://u:p@proxy' }, helm).errors.endpoint).toBeDefined()
    expect(fromForm({ ...toForm(helm), model: 'arn:aws:bedrock:us-east-1:1:inference-profile/us.anthropic.claude-opus-5-5' }, helm).errors).toEqual({})
  })
  it('parses durations like Go', () => {
    expect(parseDuration('10m')).toBe(600_000)
    expect(parseDuration('1h30m')).toBe(5_400_000)
    expect(parseDuration('90s')).toBe(90_000)
    expect(parseDuration('10')).toBeUndefined()
    expect(parseDuration('ten')).toBeUndefined()
  })
  it('lists changes, durations by length', () => {
    const next = { ...helm, model: 'us.anthropic.claude-opus-5-5', limits: { ...helm.limits, timeout: '600s' } }
    expect(changes(helm, next, FIELDS)).toEqual([{ field: 'model', old: '', new: 'us.anthropic.claude-opus-5-5' }])
    expect(fieldValue(next, 'limits.maxTokens')).toBe('1500000')
    expect(fieldValue(next, 'enabled')).toBe('false')
  })
})

describe('the toggle', () => {
  it('needs the acknowledgement to turn on, unless the platform gave it', () => {
    expect(needsAck(settings(), { enabled: true })).toBe(true)
    expect(needsAck(settings({ egressAckByPlatform: true }), { enabled: true })).toBe(false)
    expect(needsAck(settings({ values: { ...helm, enabled: true } }), { enabled: false })).toBe(false)
  })
  it('is blocked when locked or without incidents', () => {
    expect(toggleBlocked(settings())).toBeUndefined()
    expect(toggleBlocked(settings({ locked: true }))).toMatch(/Locked by Helm/)
    expect(toggleBlocked(settings({ incidents: false }))).toMatch(/incidents/)
    expect(toggleBlocked(settings({ incidents: false, values: { ...helm, enabled: true } }))).toBeUndefined()
  })
})

describe('save errors', () => {
  it('reads every answer', () => {
    expect(saveError(409, 'x', { locked: true }).locked).toBe(true)
    expect(saveError(409, 'x', { version: 3 }).conflict).toBe(true)
    expect(saveError(400, 'x', { egressAckRequired: true }).egressAckRequired).toBe(true)
    const v = saveError(400, 'x', { fields: [{ field: 'limits.maxTurns', message: 'must be between 1 and 100' }] })
    expect(v.fields).toEqual({ 'limits.maxTurns': 'Must be between 1 and 100.' })
    expect(v.message).toMatch(/not valid/)
    expect(saveError(422, 'settings: could not apply: no credentials').message).toMatch(/could not be applied/)
    expect(saveError(403, 'x').message).toMatch(/settings admin/)
    expect(saveError(500, '').message).toBe('The save failed (HTTP 500).')
  })
})

describe('connection', () => {
  it('names the credential source', () => {
    expect(credentialText(settings().credentials)).toBe('IRSA (IAM role for the service account): arn:aws:iam::111122223333:role/ks')
    expect(credentialText({ kind: 'none', label: 'No AWS credentials found', anthropicKey: false })).toBe('No AWS credentials found')
  })
  it('reads a success', () => {
    const s = testSummary({
      ok: true,
      provider: 'bedrock',
      region: 'us-east-1',
      endpoint: 'https://bedrock-mantle.us-east-1.api.aws/anthropic',
      model: 'anthropic.claude-opus-5-5',
      identityArn: 'arn:aws:sts::1:assumed-role/ks/x',
      latencyMs: 1234,
      at: '2026-10-18T09:00:00Z',
    })
    expect(s.status).toBe('ok')
    expect(s.facts[0]).toEqual(['Identity', 'arn:aws:sts::1:assumed-role/ks/x'])
    expect(s.facts.at(-1)).toEqual(['Took', '1,234 ms'])
  })
  it('reads each error', () => {
    const base = { ok: false, provider: 'bedrock', endpoint: 'e', model: 'm', latencyMs: 5, at: '' }
    const denied = testSummary({ ...base, error: { kind: 'access_denied', message: 'denied', action: 'bedrock-mantle:CreateInference', hint: 'Allow it' } })
    expect(denied.status).toBe('crit')
    expect(denied.title).toBe('Access denied')
    expect(denied.facts).toContainEqual(['Denied action', 'bedrock-mantle:CreateInference'])
    expect(denied.hint).toBe('Allow it')
    expect(testSummary({ ...base, error: { kind: 'throttled', message: 'slow' } }).status).toBe('warn')
    expect(testSummary({ ...base, error: { kind: 'network', message: 'dns' } }).title).toBe('Endpoint unreachable')
    expect(testSummary({ ...base, error: { kind: 'auth', message: 'x' } }).title).toMatch(/Anthropic API key/)
    expect(testSummary({ ...base }).title).toBe('The test failed')
  })
})

describe('setup and audit', () => {
  it('marks the recommended tab', () => {
    expect(setupTabs(settings()).map((t) => [t.id, t.recommended])).toEqual([
      ['irsa', true],
      ['anthropic', false],
    ])
  })
  it('writes audit lines', () => {
    const e = {
      id: 1,
      at: '2026-10-18T09:00:00Z',
      actor: 'alice',
      action: 'save' as const,
      version: 1,
      egressAcknowledged: true,
      changes: [
        { field: 'enabled', old: 'false', new: 'true' },
        { field: 'model', old: '', new: 'us.anthropic.claude-opus-5-5' },
      ],
    }
    expect(auditLines(e)).toEqual(['Turned the AI investigator on', 'Model: default → us.anthropic.claude-opus-5-5'])
    expect(auditAck(e)).toBe('Acknowledged the data egress')
    expect(auditAck({ ...e, egressAcknowledged: false, egressAckByPlatform: true })).toMatch(/platform/)
    expect(auditLines({ ...e, action: 'reset', changes: [] })).toEqual(['Reset to the Helm values (nothing changed).'])
  })
})
