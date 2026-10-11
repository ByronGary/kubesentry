const TOKEN_KEY = 'kubesentry.token'

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
  }
}

export function getToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? ''
  } catch {
    return ''
  }
}

export function setToken(t: string): void {
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t)
    else sessionStorage.removeItem(TOKEN_KEY)
  } catch {
    /* storage unavailable: token lasts until reload */
  }
}

/** Build a query string, skipping empty values. */
export function qs(params: Record<string, string | number | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

export async function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  const token = getToken()
  const res = await fetch(path, {
    signal,
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
  })
  if (!res.ok) {
    let msg = res.statusText
    try {
      const body = await res.json()
      if (body?.error) msg = body.error
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, msg)
  }
  return (await res.json()) as T
}
