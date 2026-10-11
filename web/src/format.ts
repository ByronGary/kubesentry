const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'] as const

/** 1024-based, one decimal only when it helps: 512 MiB, 1.5 GiB. */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n)) return '-'
  let v = Math.abs(n)
  let i = 0
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024
    i++
  }
  const digits = v >= 100 || Number.isInteger(Math.round(v * 10) / 10) ? 0 : 1
  return `${(n < 0 ? -v : v).toFixed(digits)} ${UNITS[i]}`
}

export function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many
}

/** "3 hours", "40 minutes", "2 days" for a span given in hours. */
export function formatHours(h: number): string {
  if (h < 1) {
    const m = Math.max(1, Math.round(h * 60))
    return `${m} ${plural(m, 'minute', 'minutes')}`
  }
  if (h < 48) {
    const n = Math.round(h)
    return `${n} ${plural(n, 'hour', 'hours')}`
  }
  const d = Math.round(h / 24)
  return `${d} days`
}

/** Relative time such as "3 hours ago". */
export function ago(iso: string, now: number = Date.now()): string {
  const ms = now - new Date(iso).getTime()
  if (Number.isNaN(ms)) return '-'
  const mins = ms / 60000
  if (mins < 1) return 'just now'
  if (mins < 60) {
    const m = Math.floor(mins)
    return `${m} ${plural(m, 'minute', 'minutes')} ago`
  }
  const h = mins / 60
  if (h < 48) {
    const n = Math.floor(h)
    return `${n} ${plural(n, 'hour', 'hours')} ago`
  }
  return `${Math.floor(h / 24)} days ago`
}

export function formatUSD(n: number): string {
  if (n >= 100) return `$${Math.round(n).toLocaleString('en-US')}`
  return `$${n.toFixed(2)}`
}

const clock = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' })
const dayClock = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })

export function formatClock(ms: number): string {
  return clock.format(ms)
}

export function formatDateTime(isoOrMs: string | number): string {
  const d = new Date(isoOrMs)
  return Number.isNaN(d.getTime()) ? '-' : dayClock.format(d)
}

/** CPU in millicores: "45m" under one core, "1.2 cores" above. */
export function formatCPU(millicores: number): string {
  if (millicores < 1000) return `${Math.round(millicores)}m`
  return `${(millicores / 1000).toFixed(1)} cores`
}

/**
 * When a certificate expires, from hours left (negative once expired):
 * "in 20 days", "in 5 hours", "expired 3 days ago". "-" when unknown.
 */
export function formatExpiry(hoursLeft: number | undefined): string {
  if (hoursLeft === undefined || !Number.isFinite(hoursLeft)) return '-'
  return hoursLeft < 0 ? `expired ${formatHours(-hoursLeft)} ago` : `in ${formatHours(hoursLeft)}`
}

/** Hours from now until an ISO time; negative when it has passed. Undefined when unparseable. */
export function hoursUntil(iso: string | undefined, now: number = Date.now()): number | undefined {
  if (!iso) return undefined
  const t = new Date(iso).getTime()
  return Number.isNaN(t) ? undefined : (t - now) / 3_600_000
}

/** Compact age in the style of kubectl: "45s", "12m", "5h", "3d". */
export function formatAge(iso: string, now: number = Date.now()): string {
  const ms = now - new Date(iso).getTime()
  if (Number.isNaN(ms)) return '-'
  const s = Math.max(0, Math.floor(ms / 1000))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 48 * 3600) return `${Math.floor(s / 3600)}h`
  return `${Math.floor(s / 86400)}d`
}

/** Whole percent of `value` in `max`, clamped to 0..100. Undefined when there is no max. */
export function percent(value: number, max: number): number | undefined {
  if (!(max > 0) || !Number.isFinite(value)) return undefined
  return Math.min(100, Math.max(0, Math.round((value / max) * 100)))
}

/**
 * Shorten a name to `max` characters by cutting the middle, which keeps both
 * the recognisable prefix and the unique suffix of generated names.
 */
export function truncateMiddle(s: string, max: number): string {
  if (s.length <= max) return s
  if (max <= 1) return '…'.slice(0, max)
  const keep = max - 1
  const head = Math.ceil(keep / 2)
  return `${s.slice(0, head)}…${s.slice(s.length - (keep - head))}`
}

/** "a, b, c and 2 more" */
export function listSome(items: string[], max = 3): string {
  if (items.length <= max) return items.join(', ')
  return `${items.slice(0, max).join(', ')} and ${items.length - max} more`
}
