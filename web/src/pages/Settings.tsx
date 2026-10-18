import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { apiPost, apiPut, ApiError } from '../api'
import { Async, PageHead, StatusGlyph } from '../components/ui'
import { formatDateTime } from '../format'
import { trapTab } from '../nav'
import {
  auditAck,
  auditLines,
  changes,
  credentialText,
  DEFAULT_ANTHROPIC_MODEL,
  DEFAULT_BEDROCK_MODEL,
  FIELD_LABEL,
  fromForm,
  needsAck,
  overridden,
  PROVIDER_LABEL,
  saveError,
  setupTabs,
  sourceText,
  testSummary,
  toForm,
  toggleBlocked,
  valueText,
  type Form,
  type SaveError,
} from '../settings'
import type { ConnectionTestResult, Info, InvestigatorSettings, InvestigatorSettingsSave, InvestigatorValues, SetupStep } from '../types'
import { bumpAuth, useApi } from '../useApi'

const PATH = '/api/v1/settings/investigator'

/**
 * Settings: the AI investigator, turned on and off live, its provider,
 * model and limits, how kubesentry reaches the model (and a test of it),
 * the setup steps for where it runs, and who changed what.
 */
export function Settings({ info }: { info: Info }) {
  const state = useApi<InvestigatorSettings>(PATH)
  return (
    <>
      <PageHead
        title="Settings"
        lede="Changes apply at once on every kubesentry replica, without a restart, and are recorded with who made them. Helm gives the starting values."
      />
      <Async state={state} what="the settings">
        {(s) => <InvestigatorPanel loaded={s} demo={info.demo} reload={state.reload} />}
      </Async>
    </>
  )
}

function InvestigatorPanel({ loaded, demo, reload }: { loaded: InvestigatorSettings; demo: boolean; reload: () => void }) {
  const [s, setS] = useState(loaded)
  useEffect(() => setS(loaded), [loaded])
  const [dialog, setDialog] = useState<'on' | 'off'>()
  const [notice, setNotice] = useState<{ status: 'ok' | 'crit'; text: string }>()

  const save = async (body: InvestigatorSettingsSave): Promise<void> => {
    try {
      const next = await apiPut<InvestigatorSettings>(PATH, body)
      setS(next)
    } catch (e) {
      if (e instanceof ApiError) throw saveError(e.status, e.message, e.body)
      throw { message: e instanceof Error ? e.message : String(e), fields: {} } satisfies SaveError
    }
  }

  const on = s.values.enabled
  const blocked = toggleBlocked(s)
  return (
    <div className="set-page">
      {s.locked && (
        <div className="notice set-banner" role="note">
          <p>
            <StatusGlyph status="info" label={false} /> <strong>Locked by Helm.</strong> The settings come only from the chart’s values
            (incidents.investigator.settings: locked); this page is read-only. Change them in Git and roll out.
          </p>
        </div>
      )}
      {!s.incidents && (
        <div className="notice warn" role="note">
          <p>
            <StatusGlyph status="warn" label={false} /> <strong>Incidents are off.</strong> The investigator investigates incidents: turn them on first
            (-incidents, incidents.enabled).
          </p>
        </div>
      )}
      {demo && (
        <div className="notice" role="note">
          <p>
            <strong>Demo.</strong> The investigator here is scripted and sends nothing anywhere; the connection test answers as an EKS cluster with IRSA
            would. Turning it off hides Investigate on the incident pages.
          </p>
        </div>
      )}
      {s.applied.error && (
        <div className="notice crit" role="alert">
          <p>
            <StatusGlyph status="crit" label={false} /> <strong>Not applied on this replica.</strong> {s.applied.error}. It keeps what it ran before.
          </p>
        </div>
      )}

      <section className="panel set-card" aria-labelledby="set-inv-title">
        <div className="set-toggle-row">
          <div>
            <h2 id="set-inv-title">AI investigator</h2>
            <p className="muted small">
              Reads one incident and writes a root-cause report. Each run sends a redacted digest of the incident to the model provider.
            </p>
          </div>
          <div className="set-toggle">
            <button
              type="button"
              role="switch"
              aria-checked={on}
              aria-labelledby="set-inv-title"
              aria-describedby="set-toggle-src"
              className={`switch${on ? ' on' : ''}`}
              disabled={blocked !== undefined}
              title={blocked}
              onClick={() => setDialog(on ? 'off' : 'on')}
            >
              <span className="switch-track" aria-hidden="true">
                <span className="switch-thumb" />
              </span>
              <span className="switch-text">{on ? 'On' : 'Off'}</span>
            </button>
            <p id="set-toggle-src" className="field-hint">
              {sourceText(s.sources.enabled)}
              {s.sources.enabled?.source === 'ui' && ` (Helm: ${s.helm.enabled ? 'on' : 'off'})`}
              {blocked && !s.locked && <span className="set-block"> {blocked}</span>}
            </p>
          </div>
        </div>
        <p className="set-state" role="status">
          <StatusGlyph status={on ? 'ok' : 'unknown'} label={false} />{' '}
          {on
            ? `On: ${PROVIDER_LABEL[s.values.provider] ?? s.values.provider}, ${s.values.model || (s.values.provider === 'bedrock' ? DEFAULT_BEDROCK_MODEL : DEFAULT_ANTHROPIC_MODEL)}. People with the investigator role see Investigate on incident pages.`
            : 'Off: nobody can start an investigation. Past runs stay readable.'}
        </p>
        {notice && (
          <p className={`notice ${notice.status}`} role="status">
            {notice.text}
          </p>
        )}
        <SettingsForm s={s} onSave={save} onSaved={(t) => setNotice({ status: 'ok', text: t })} reload={reload} />
      </section>

      <Connection s={s} />
      <Setup s={s} />
      <Audit s={s} />

      {dialog && (
        <ToggleDialog
          s={s}
          turnOn={dialog === 'on'}
          onCancel={() => setDialog(undefined)}
          onConfirm={async (ack) => {
            await save({ version: s.version, values: { ...s.values, enabled: dialog === 'on' }, egressAcknowledged: ack || undefined })
            setDialog(undefined)
            setNotice({ status: 'ok', text: dialog === 'on' ? 'The AI investigator is on.' : 'The AI investigator is off. Running investigations finish.' })
            // /info and the pages that show Investigate pick it up at once.
            bumpAuth()
          }}
        />
      )}
    </div>
  )
}

// ---- the form ----

const LIMITS: { key: keyof Form; hint: string; inputMode: 'numeric' | 'text' }[] = [
  { key: 'perHour', hint: 'Cached answers are free.', inputMode: 'numeric' },
  { key: 'perHourTotal', hint: 'Everyone together.', inputMode: 'numeric' },
  { key: 'concurrency', hint: 'On each replica.', inputMode: 'numeric' },
  { key: 'maxTurns', hint: '1 to 100.', inputMode: 'numeric' },
  { key: 'maxToolCalls', hint: '1 to 200.', inputMode: 'numeric' },
  { key: 'maxTokens', hint: 'Every kind, summed.', inputMode: 'numeric' },
  { key: 'timeout', hint: '1m to 1h, e.g. 10m.', inputMode: 'text' },
]

const FORM_KEY: Partial<Record<keyof Form, string>> = {
  perHour: 'limits.perHour',
  perHourTotal: 'limits.perHourTotal',
  concurrency: 'limits.concurrency',
  maxTurns: 'limits.maxTurns',
  maxToolCalls: 'limits.maxToolCalls',
  maxTokens: 'limits.maxTokens',
  timeout: 'limits.timeout',
}

function fieldName(k: keyof Form): string {
  return FORM_KEY[k] ?? k
}

function SettingsForm({
  s,
  onSave,
  onSaved,
  reload,
}: {
  s: InvestigatorSettings
  onSave: (b: InvestigatorSettingsSave) => Promise<void>
  onSaved: (text: string) => void
  reload: () => void
}) {
  const [form, setForm] = useState<Form>(() => toForm(s.values))
  const [serverErr, setServerErr] = useState<SaveError>()
  const [tried, setTried] = useState(false)
  const [busy, setBusy] = useState(false)
  const version = s.version
  // A new version (saved here, by the toggle, or loaded) resets the form.
  useEffect(() => {
    setForm(toForm(s.values))
    setTried(false)
  }, [version, s.values])
  const { values, errors } = fromForm(form, s.values)
  const pending = changes(s.values, values, s.options.fields)
  const errs = { ...(tried ? errors : {}), ...(serverErr?.fields ?? {}) }
  const ui = overridden(s)
  const set = (k: keyof Form) => (v: string) => {
    setForm((f) => ({ ...f, [k]: v }))
    setServerErr(undefined)
  }

  const submit = async () => {
    setTried(true)
    if (Object.keys(errors).length > 0 || busy) return
    setBusy(true)
    setServerErr(undefined)
    try {
      await onSave({ version, values })
      onSaved(`Saved ${pending.length} ${pending.length === 1 ? 'change' : 'changes'}; every replica applies ${pending.length === 1 ? 'it' : 'them'} within 15 seconds.`)
    } catch (e) {
      setServerErr(e as SaveError)
    } finally {
      setBusy(false)
    }
  }
  const reset = async () => {
    setBusy(true)
    setServerErr(undefined)
    try {
      await onSave({ version, reset: true })
      onSaved('Reset to the Helm values.')
    } catch (e) {
      setServerErr(e as SaveError)
    } finally {
      setBusy(false)
    }
  }

  const field = (k: keyof Form, label: string, control: (id: string, describedBy: string) => ReactNode, hint?: ReactNode) => (
    <Field key={k} s={s} name={fieldName(k)} label={label} error={errs[fieldName(k)]} hint={hint}>
      {control}
    </Field>
  )
  const bedrock = form.provider === 'bedrock'
  return (
    <form
      className="set-form"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        void submit()
      }}
    >
      <fieldset disabled={s.locked} className="set-fieldset">
        <legend className="sr-only">AI investigator settings</legend>
        <fieldset className="set-choice">
          <legend>Provider</legend>
          <label>
            <input type="radio" name="provider" value="bedrock" checked={form.provider === 'bedrock'} onChange={() => set('provider')('bedrock')} />
            <span>
              Amazon Bedrock <span className="set-tag">recommended</span>
              <span className="field-hint set-block">Your AWS account and region, through a VPC endpoint; no API key.</span>
            </span>
          </label>
          <label>
            <input type="radio" name="provider" value="anthropic" checked={form.provider === 'anthropic'} onChange={() => set('provider')('anthropic')} />
            <span>
              Anthropic API
              <span className="field-hint set-block">
                api.anthropic.com with an API key from a Kubernetes Secret{s.anthropicKey ? ' (the key is set).' : ' (no key is set yet).'}
              </span>
            </span>
          </label>
          <SourceLine s={s} name="provider" />
          {errs.provider && <p className="al-error">{errs.provider}</p>}
        </fieldset>

        <div className="set-grid">
          {field(
            'model',
            'Model',
            (id, d) => (
              <input
                id={id}
                aria-describedby={d}
                type="text"
                value={form.model}
                autoComplete="off"
                spellCheck={false}
                placeholder={bedrock ? DEFAULT_BEDROCK_MODEL : DEFAULT_ANTHROPIC_MODEL}
                aria-invalid={errs.model ? true : undefined}
                onChange={(e) => set('model')(e.target.value)}
              />
            ),
            bedrock ? 'Empty: the default. A model ID, an inference profile (us.…, global.…) or its ARN.' : 'Empty: the default.',
          )}
          {field('effort', 'Effort', (id, d) => (
            <select id={id} aria-describedby={d} value={form.effort} onChange={(e) => set('effort')(e.target.value)}>
              {s.options.efforts.map((e) => (
                <option key={e} value={e}>
                  {e}
                </option>
              ))}
            </select>
          ))}
          {bedrock &&
            field(
              'region',
              'Region',
              (id, d) => (
                <input
                  id={id}
                  aria-describedby={d}
                  type="text"
                  value={form.region}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={s.defaultRegion ?? 'us-east-1'}
                  aria-invalid={errs.region ? true : undefined}
                  onChange={(e) => set('region')(e.target.value)}
                />
              ),
              s.defaultRegion ? `Empty: ${s.defaultRegion} (-aws-region).` : 'Empty: -aws-region, then AWS_REGION.',
            )}
          {bedrock && (
            <Field s={s} name="bedrockAPI" label="Bedrock API" error={errs.bedrockAPI} hint="mantle: the Messages API (bedrock-mantle:CreateInference). runtime: InvokeModel.">
              {(id, d) => (
                <select id={id} aria-describedby={d} value={form.bedrockAPI} onChange={(e) => set('bedrockAPI')(e.target.value)}>
                  <option value="mantle">mantle</option>
                  <option value="runtime">runtime</option>
                </select>
              )}
            </Field>
          )}
          {field(
            'endpoint',
            'Endpoint',
            (id, d) => (
              <input
                id={id}
                aria-describedby={d}
                type="url"
                value={form.endpoint}
                autoComplete="off"
                spellCheck={false}
                placeholder="none"
                aria-invalid={errs.endpoint ? true : undefined}
                onChange={(e) => set('endpoint')(e.target.value)}
              />
            ),
            bedrock ? 'Only without private DNS: the VPC endpoint’s DNS name (mantle: with /anthropic).' : 'A proxy in front of the API.',
          )}
          {field(
            'fallback',
            'Refusal fallback',
            (id, d) => (
              <input
                id={id}
                aria-describedby={d}
                type="text"
                value={form.fallback}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={errs.fallback ? true : undefined}
                onChange={(e) => set('fallback')(e.target.value)}
              />
            ),
            'auto, off, or the model that answers a declined turn.',
          )}
        </div>

        <fieldset className="set-limits">
          <legend>Limits</legend>
          <div className="set-grid">
            {LIMITS.map((l) =>
              field(
                l.key,
                FIELD_LABEL[fieldName(l.key)],
                (id, d) => (
                  <input
                    id={id}
                    aria-describedby={d}
                    type="text"
                    inputMode={l.inputMode}
                    value={form[l.key]}
                    autoComplete="off"
                    aria-invalid={errs[fieldName(l.key)] ? true : undefined}
                    onChange={(e) => set(l.key)(e.target.value)}
                  />
                ),
                l.hint,
              ),
            )}
          </div>
        </fieldset>
      </fieldset>

      {serverErr && (
        <div className="notice crit" role="alert">
          <p>{serverErr.message}</p>
          {serverErr.conflict && (
            <button type="button" className="btn" onClick={reload}>
              Reload
            </button>
          )}
        </div>
      )}
      {!s.locked && (
        <div className="set-actions">
          <button type="submit" className="btn primary" disabled={busy || pending.length === 0}>
            {busy ? 'Saving…' : pending.length > 0 ? `Save ${pending.length} ${pending.length === 1 ? 'change' : 'changes'}` : 'Save'}
          </button>
          <button type="button" className="btn" disabled={busy || pending.length === 0} onClick={() => setForm(toForm(s.values))}>
            Discard
          </button>
          <button
            type="button"
            className="btn quiet"
            disabled={busy || ui.length === 0}
            onClick={reset}
            title={ui.length === 0 ? 'Every value already comes from Helm.' : undefined}
          >
            Reset to Helm values{ui.length > 0 ? ` (${ui.length})` : ''}
          </button>
        </div>
      )}
    </form>
  )
}

function SourceLine({ s, name, id }: { s: InvestigatorSettings; name: string; id?: string }) {
  const src = s.sources[name]
  const ui = src?.source === 'ui'
  const helm = valueText(name, fieldOf(s.helm, name), s.helm, s.defaultRegion)
  return (
    <span id={id} className={`set-src${ui ? ' ui' : ''}`}>
      {ui && (
        <span aria-hidden="true" className="set-src-mark">
          ✎{' '}
        </span>
      )}
      {sourceText(src)}
      {ui && <span className="muted"> · Helm: {helm}</span>}
    </span>
  )
}

function fieldOf(v: InvestigatorValues, name: string): string {
  if (name === 'enabled') return String(v.enabled)
  if (name.startsWith('limits.')) return String(v.limits[name.slice(7) as keyof InvestigatorValues['limits']])
  return String(v[name as 'model'] ?? '')
}

function Field({
  s,
  name,
  label,
  error,
  hint,
  children,
}: {
  s: InvestigatorSettings
  name: string
  label: string
  error?: string
  hint?: ReactNode
  children: (id: string, describedBy: string) => ReactNode
}) {
  const id = useId()
  const hintId = `${id}-hint`
  const srcId = `${id}-src`
  const errId = `${id}-err`
  return (
    <div className={`set-field${s.sources[name]?.source === 'ui' ? ' changed' : ''}`}>
      <label htmlFor={id}>{label}</label>
      {children(id, [hint ? hintId : '', srcId, error ? errId : ''].filter(Boolean).join(' '))}
      {hint && (
        <span id={hintId} className="field-hint">
          {hint}
        </span>
      )}
      <SourceLine s={s} name={name} id={srcId} />
      {error && (
        <span id={errId} className="al-error">
          {error}
        </span>
      )}
    </div>
  )
}

// ---- the on/off dialog ----

const FOCUSABLE = 'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), a[href]'

/**
 * Confirms turning the investigator on (with the data egress
 * acknowledgement, unless the platform gave it) or off. A modal dialog:
 * the page behind is inert, Tab stays inside, Esc cancels, focus returns.
 */
function ToggleDialog({
  s,
  turnOn,
  onCancel,
  onConfirm,
}: {
  s: InvestigatorSettings
  turnOn: boolean
  onCancel: () => void
  onConfirm: (ack: boolean) => Promise<void>
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const [ack, setAck] = useState(false)
  const [tried, setTried] = useState(false)
  const [sending, setSending] = useState(false)
  const [error, setError] = useState<string>()
  const ackNeeded = needsAck(s, { enabled: turnOn })
  const v = s.values
  const where =
    v.provider === 'bedrock'
      ? `Amazon Bedrock in ${v.region || s.defaultRegion || 'your region'} (${v.bedrockAPI || 'mantle'}), as ${s.credentials.roleArn ?? s.credentials.label}`
      : 'the Anthropic API (api.anthropic.com)'

  useEffect(() => {
    const d = ref.current
    const back = document.activeElement as HTMLElement | null
    if (d && !d.open) d.showModal()
    d?.querySelector<HTMLElement>(ackNeeded ? 'input[type="checkbox"]' : '.btn.primary')?.focus()
    return () => {
      d?.close()
      back?.focus?.()
    }
  }, [ackNeeded])

  const onKeyDown = (e: KeyboardEvent<HTMLDialogElement>) => {
    if (e.key !== 'Tab' || !ref.current) return
    const els = [...ref.current.querySelectorAll<HTMLElement>(FOCUSABLE)]
    const next = trapTab(els.indexOf(document.activeElement as HTMLElement), els.length, e.shiftKey)
    if (next !== undefined) {
      e.preventDefault()
      els[next]?.focus()
    }
  }

  const submit = async () => {
    setTried(true)
    setError(undefined)
    if ((ackNeeded && !ack) || sending) return
    setSending(true)
    try {
      await onConfirm(ack)
    } catch (e) {
      const se = e as SaveError
      setError(se?.message ?? String(e))
      setSending(false)
    }
  }

  const ackMissing = tried && ackNeeded && !ack
  return (
    <dialog
      ref={ref}
      className="al-dialog set-dialog"
      aria-labelledby="set-dialog-title"
      aria-describedby="set-dialog-what"
      onCancel={(e) => {
        e.preventDefault()
        if (!sending) onCancel()
      }}
      onKeyDown={onKeyDown}
    >
      <form
        method="dialog"
        onSubmit={(e) => {
          e.preventDefault()
          void submit()
        }}
      >
        <h2 id="set-dialog-title">{turnOn ? 'Turn the AI investigator on?' : 'Turn the AI investigator off?'}</h2>
        {turnOn ? (
          <div id="set-dialog-what" className="set-dialog-what">
            <p>
              Each investigation sends to <strong>{where}</strong>:
            </p>
            <ul>
              <li>a redacted digest of the incident: signals, metric statistics, events, log templates, audit writes and CloudTrail changes;</li>
              <li>the logs, events, audit and CloudTrail records the person who starts it may see, as the model asks for them.</li>
            </ul>
            <p className="muted small">
              Redaction removes known secret formats, source IPs and user agents, but it is best effort: treat the provider as a processor of your incident
              data. Nothing runs by itself: a person starts each investigation. All replicas apply this within 15 seconds.
            </p>
          </div>
        ) : (
          <p id="set-dialog-what">
            Nobody can start a new investigation. Investigations running now finish; past runs stay stored and readable. You can turn it on again here.
          </p>
        )}
        {turnOn &&
          (ackNeeded ? (
            <label className={`set-ack${ackMissing ? ' invalid' : ''}`}>
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} aria-invalid={ackMissing || undefined} aria-describedby="set-ack-err" />
              <span>I acknowledge that investigations send redacted incident data to the model provider. Recorded with my name.</span>
            </label>
          ) : (
            <p className="set-ack-platform">
              <StatusGlyph status="ok" label={false} /> The data egress is acknowledged by the platform (Helm: acknowledgeDataEgress).
            </p>
          ))}
        {ackMissing && (
          <p id="set-ack-err" className="al-error" role="alert">
            Tick the acknowledgement to turn it on.
          </p>
        )}
        {error && (
          <p className="notice crit" role="alert">
            {error}
          </p>
        )}
        <div className="al-dialog-buttons">
          <button type="button" className="btn" onClick={onCancel} disabled={sending}>
            Cancel
          </button>
          <button type="submit" className="btn primary" disabled={sending}>
            {sending ? (turnOn ? 'Turning on…' : 'Turning off…') : turnOn ? 'Turn on' : 'Turn off'}
          </button>
        </div>
      </form>
    </dialog>
  )
}

// ---- connection ----

function Connection({ s }: { s: InvestigatorSettings }) {
  const [result, setResult] = useState<ConnectionTestResult>()
  const [error, setError] = useState<string>()
  const [testing, setTesting] = useState(false)
  const e = s.environment
  const c = s.credentials
  const test = async () => {
    setTesting(true)
    setError(undefined)
    try {
      setResult(await apiPost<ConnectionTestResult>(`${PATH}/test`, {}))
    } catch (err) {
      setResult(undefined)
      setError(err instanceof ApiError && err.status === 429 ? 'Test at most once every 10 seconds. Try again in a moment.' : err instanceof Error ? err.message : String(err))
    } finally {
      setTesting(false)
    }
  }
  const sum = result && testSummary(result)
  return (
    <section className="panel set-card" aria-labelledby="set-conn-title">
      <div className="panel-head">
        <h2 id="set-conn-title">Connection</h2>
        <button type="button" className="btn" onClick={test} disabled={testing}>
          {testing ? 'Testing…' : 'Test connection'}
        </button>
      </div>
      <dl className="set-facts">
        <dt>Runs</dt>
        <dd>
          {e.label}
          {e.cluster && ` · cluster ${e.cluster}`}
          {e.region && ` · ${e.region}`}
          {e.kubeContext && ` · context ${e.kubeContext}`}
        </dd>
        <dt>AWS credentials</dt>
        <dd>
          <StatusGlyph status={c.kind === 'none' ? 'warn' : c.kind === 'env-keys' || c.kind === 'instance-role' ? 'info' : 'ok'} label={false} />{' '}
          <span className="set-wrap">{credentialText(c)}</span>
          {c.note && <span className="field-hint set-block">{c.note}</span>}
        </dd>
        <dt>Anthropic API key</dt>
        <dd>{c.anthropicKey ? 'Set in the environment (from a Secret)' : 'Not set'}</dd>
      </dl>
      <p className="field-hint">
        The test uses the saved settings: for Bedrock it asks STS who kubesentry is, then sends a one-token request to the model. kubesentry never reads or
        stores AWS keys here.
      </p>
      <div aria-live="polite" className="set-test">
        {testing && <p className="muted">Testing the connection…</p>}
        {error && !testing && <p className="notice warn">{error}</p>}
        {sum && !testing && (
          <div className={`notice ${sum.status}`}>
            <p>
              <StatusGlyph status={sum.status} label={false} /> <strong>{sum.title}</strong>
              <span className="muted small"> · {formatDateTime(result!.at)}</span>
            </p>
            {sum.message && <p className="set-wrap">{sum.message}</p>}
            {sum.hint && <p className="set-wrap">{sum.hint}</p>}
            <dl className="set-facts compact">
              {sum.facts.map(([k, v]) => (
                <div key={k}>
                  <dt>{k}</dt>
                  <dd className="set-wrap">{v}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}
      </div>
    </section>
  )
}

// ---- setup ----

function Setup({ s }: { s: InvestigatorSettings }) {
  const tabs = setupTabs(s)
  const [active, setActive] = useState(s.setup.recommended)
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  const cur = tabs.find((t) => t.id === active) ?? tabs[0]
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = tabs.findIndex((t) => t.id === active)
    let j: number | undefined
    if (e.key === 'ArrowRight') j = (i + 1) % tabs.length
    else if (e.key === 'ArrowLeft') j = (i - 1 + tabs.length) % tabs.length
    else if (e.key === 'Home') j = 0
    else if (e.key === 'End') j = tabs.length - 1
    if (j === undefined) return
    e.preventDefault()
    setActive(tabs[j].id)
    refs.current[j]?.focus()
  }
  return (
    <section className="panel set-card" aria-labelledby="set-setup-title">
      <h2 id="set-setup-title">Set up</h2>
      <p className="muted small">
        Steps for where kubesentry runs ({s.environment.label.toLowerCase()}). kubesentry never asks for AWS keys: in EKS it uses its pod role; elsewhere your
        AWS profile, or a Secret you manage.
      </p>
      <div className="set-tabs" role="tablist" aria-label="Setup" onKeyDown={onKey}>
        {tabs.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => {
              refs.current[i] = el
            }}
            type="button"
            role="tab"
            id={`set-tab-${t.id}`}
            aria-selected={t.id === cur.id}
            aria-controls={`set-panel-${t.id}`}
            tabIndex={t.id === cur.id ? 0 : -1}
            onClick={() => setActive(t.id)}
          >
            {t.title}
            {t.recommended && <span className="set-tag">for you</span>}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`set-panel-${cur.id}`} aria-labelledby={`set-tab-${cur.id}`} className="set-tabpanel">
        <p>{cur.summary}</p>
        <ol className="set-steps">
          {cur.steps.map((st, i) => (
            <SetupStepItem key={`${cur.id}-${i}`} step={st} />
          ))}
        </ol>
      </div>
    </section>
  )
}

function SetupStepItem({ step }: { step: SetupStep }) {
  return (
    <li>
      <h3>{step.title}</h3>
      <p className="set-wrap">{step.text}</p>
      {step.code && <CodeBlock code={step.code} lang={step.lang} title={step.title} />}
    </li>
  )
}

/** A block to copy: commands, policies, Helm values. Nothing here runs. */
function CodeBlock({ code, lang, title }: { code: string; lang?: string; title: string }) {
  const [copied, setCopied] = useState<'yes' | 'no'>()
  useEffect(() => {
    if (!copied) return
    const id = setTimeout(() => setCopied(undefined), 2500)
    return () => clearTimeout(id)
  }, [copied])
  const copy = async () => {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(code)
      else {
        const ta = document.createElement('textarea')
        ta.value = code
        ta.setAttribute('readonly', '')
        ta.style.position = 'fixed'
        ta.style.opacity = '0'
        document.body.appendChild(ta)
        ta.select()
        const ok = document.execCommand('copy')
        ta.remove()
        if (!ok) throw new Error('copy refused')
      }
      setCopied('yes')
    } catch {
      setCopied('no')
    }
  }
  return (
    <div className="set-code">
      <div className="set-code-head">
        <span className="muted small">{lang === 'shell' ? 'Shell' : lang === 'json' ? 'JSON' : lang === 'yaml' ? 'YAML' : ''}</span>
        <button type="button" className="btn inv-copy" onClick={copy} aria-label={`Copy: ${title}`}>
          {copied === 'yes' ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre tabIndex={0} aria-label={`${title} (${lang ?? 'text'})`}>
        <code>{code}</code>
      </pre>
      <span className="sr-only" aria-live="polite">
        {copied === 'yes' ? 'Copied.' : copied === 'no' ? 'Could not copy; select the text instead.' : ''}
      </span>
    </div>
  )
}

// ---- audit ----

function Audit({ s }: { s: InvestigatorSettings }) {
  return (
    <section className="panel set-card" aria-labelledby="set-audit-title">
      <h2 id="set-audit-title">Changes</h2>
      {s.audit.length === 0 ? (
        <p className="muted">No changes on this page yet: every value comes from Helm.</p>
      ) : (
        <ol className="set-audit">
          {s.audit.map((e) => {
            const ack = auditAck(e)
            return (
              <li key={e.id}>
                <p className="set-audit-head">
                  <strong>{e.actor}</strong> <span className="muted">{e.action === 'reset' ? 'reset to the Helm values' : 'saved'}</span>{' '}
                  <time dateTime={e.at} className="muted small">
                    {formatDateTime(e.at)}
                  </time>{' '}
                  <span className="muted small">· version {e.version}</span>
                </p>
                <ul>
                  {auditLines(e).map((l, i) => (
                    <li key={i} className="set-wrap">
                      {l}
                    </li>
                  ))}
                  {ack && <li className="muted">{ack}</li>}
                </ul>
              </li>
            )
          })}
        </ol>
      )}
      {s.audit.length >= 20 && <p className="field-hint">The newest 20 changes.</p>}
    </section>
  )
}
