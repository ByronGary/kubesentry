// How storage costs are shown, kept free of React so it is testable.
//
// A cost is shown only when the server knows a price. EFS and FSx bill for
// data stored, so they get "billed by usage" rather than a made-up number.

import { formatUSD } from './format'
import type { ClaimSummary, ClassSummary, PriceSource, UnusedPVC } from './types'

export const PRICE_ANNOTATION = 'kubesentry.io/price-per-gib-month'

export type CostKind = 'known' | 'usage' | 'unknown'

export interface CostDisplay {
  text: string
  /** Where the price came from, or what to do about a missing one. */
  title: string
  kind: CostKind
}

const SOURCE_TEXT: Record<PriceSource, string> = {
  annotation: `Price from the StorageClass annotation ${PRICE_ANNOTATION}`,
  'class-price': 'Price from the server flag -pvc-class-prices',
  'ebs-table': 'Price from the EBS price table for the volume type',
  default: 'Price from the server flag -pvc-default-price',
  'usage-billed': 'Billed for data stored, not claim size',
  unknown: 'No price known',
}

export function priceSourceText(s: PriceSource | undefined): string {
  return s ? SOURCE_TEXT[s] ?? s : ''
}

export const USAGE_TITLE = 'EFS and FSx bill for the data stored, not the size of the claim, so there is no estimate.'
export const UNKNOWN_TITLE = `No price for this storage class. Set the StorageClass annotation ${PRICE_ANNOTATION} (for example "0.08") to estimate it.`

type Costed = Pick<ClaimSummary, 'estMonthlyCostUSD' | 'costKnown' | 'priceSource'>

/**
 * The cost cell for a claim. Undefined when the server sent no cost fields at
 * all (older servers), so the column can be left out.
 */
export function claimCost(c: Costed): CostDisplay | undefined {
  if (c.costKnown === undefined && c.priceSource === undefined && c.estMonthlyCostUSD === undefined) return undefined
  if (c.priceSource === 'usage-billed') return { text: 'billed by usage', title: USAGE_TITLE, kind: 'usage' }
  const known = c.costKnown ?? (c.priceSource !== undefined && c.priceSource !== 'unknown')
  if (known && c.estMonthlyCostUSD !== undefined && Number.isFinite(c.estMonthlyCostUSD)) {
    return { text: formatUSD(c.estMonthlyCostUSD), title: priceSourceText(c.priceSource) || 'Estimated monthly cost', kind: 'known' }
  }
  return { text: '—', title: UNKNOWN_TITLE, kind: 'unknown' }
}

/** The price cell for a storage class: "$0.08 /GiB-month". Undefined when the server sent nothing. */
export function classPrice(c: Pick<ClassSummary, 'pricePerGiBMonth' | 'priceSource'>): CostDisplay | undefined {
  if (c.pricePerGiBMonth === undefined && c.priceSource === undefined) return undefined
  if (c.priceSource === 'usage-billed') return { text: 'billed by usage', title: USAGE_TITLE, kind: 'usage' }
  if (c.pricePerGiBMonth !== undefined && c.priceSource !== 'unknown') {
    const v = c.pricePerGiBMonth
    const text = `$${v < 1 ? v.toFixed(3).replace(/0$/, '') : v.toFixed(2)} /GiB-month`
    return { text, title: priceSourceText(c.priceSource) || 'Price per GiB-month', kind: 'known' }
  }
  return { text: '—', title: UNKNOWN_TITLE, kind: 'unknown' }
}

/** Whether any row has cost fields, i.e. the server is new enough to show the column. */
export function anyCost(items: Costed[]): boolean {
  return items.some((c) => claimCost(c) !== undefined)
}

const key = (ns: string, name: string) => `${ns}/${name}`

/** Index claims by "namespace/name" so unused claims can borrow their price state. */
export function claimIndex(claims: ClaimSummary[]): Map<string, ClaimSummary> {
  return new Map(claims.map((c) => [key(c.namespace, c.name), c]))
}

/**
 * The cost cell for an unused claim. Newer servers say on the item whether a
 * price applies (`estMonthlyCostUSD` is 0 when it does not); for older ones
 * the matching claim is consulted, and failing that the estimate is shown as is.
 */
export function unusedCost(u: UnusedPVC, claims: Map<string, ClaimSummary>): CostDisplay {
  if (u.costKnown !== undefined || u.priceSource !== undefined) return claimCost(u)!
  const c = claims.get(key(u.namespace, u.name))
  const shown = c ? claimCost(c) : undefined
  if (shown && shown.kind !== 'known') return shown
  return { text: formatUSD(u.estMonthlyCostUSD), title: shown?.title ?? 'Estimated monthly cost', kind: 'known' }
}

/** Sum of known costs, and how many claims have none. */
export function unusedTotal(items: UnusedPVC[], claims: Map<string, ClaimSummary>): { total: number; unpriced: number } {
  let total = 0
  let unpriced = 0
  for (const u of items) {
    const c = unusedCost(u, claims)
    if (c.kind === 'known') total += u.estMonthlyCostUSD || 0
    else unpriced++
  }
  return { total, unpriced }
}
