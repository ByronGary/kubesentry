import { describe, expect, it } from 'vitest'
import { anyCost, claimCost, claimIndex, classPrice, PRICE_ANNOTATION, unusedCost, unusedTotal } from './cost'
import type { ClaimSummary, UnusedPVC } from './types'

const claim = (name: string, extra: Partial<ClaimSummary> = {}): ClaimSummary => ({
  namespace: 'shop',
  name,
  phase: 'Bound',
  storageClass: 'gp3',
  capacityBytes: 100 * 2 ** 30,
  usedBy: [],
  status: 'ok',
  detail: '',
  created: '2026-01-01T00:00:00Z',
  ...extra,
})

const unused = (name: string, cost: number, extra: Partial<UnusedPVC> = {}): UnusedPVC => ({
  namespace: 'shop',
  name,
  storageClass: 'gp3',
  phase: 'Bound',
  capacityBytes: 100 * 2 ** 30,
  created: '2026-01-01T00:00:00Z',
  ageHours: 400,
  estMonthlyCostUSD: cost,
  ...extra,
})

describe('claimCost', () => {
  it('leaves the column out for servers that send no cost fields', () => {
    expect(claimCost(claim('a'))).toBeUndefined()
    expect(anyCost([claim('a'), claim('b')])).toBe(false)
  })
  it('shows a known cost with where the price came from', () => {
    const c = claimCost(claim('a', { estMonthlyCostUSD: 8, costKnown: true, priceSource: 'ebs-table' }))
    expect(c).toEqual({ text: '$8.00', title: 'Price from the EBS price table for the volume type', kind: 'known' })
    expect(claimCost(claim('a', { estMonthlyCostUSD: 1, costKnown: true, priceSource: 'annotation' }))!.title).toContain(PRICE_ANNOTATION)
    expect(anyCost([claim('a'), claim('b', { costKnown: true, estMonthlyCostUSD: 1 })])).toBe(true)
  })
  it('says "billed by usage" for EFS and FSx, never a number', () => {
    const c = claimCost(claim('a', { estMonthlyCostUSD: 0, costKnown: false, priceSource: 'usage-billed' }))
    expect(c).toMatchObject({ text: 'billed by usage', kind: 'usage' })
  })
  it('shows a dash and how to set a price when none is known', () => {
    const c = claimCost(claim('a', { estMonthlyCostUSD: 0, costKnown: false, priceSource: 'unknown' }))!
    expect(c.text).toBe('—')
    expect(c.kind).toBe('unknown')
    expect(c.title).toContain(PRICE_ANNOTATION)
    // A cost flagged unknown is not shown even if a number came with it.
    expect(claimCost(claim('a', { estMonthlyCostUSD: 5, costKnown: false }))!.text).toBe('—')
  })
})

describe('classPrice', () => {
  it('shows the price per GiB-month, usage billing, or a dash', () => {
    expect(classPrice({ pricePerGiBMonth: 0.08, priceSource: 'ebs-table' })!.text).toBe('$0.08 /GiB-month')
    expect(classPrice({ pricePerGiBMonth: 0.125, priceSource: 'class-price' })!.text).toBe('$0.125 /GiB-month')
    expect(classPrice({ priceSource: 'usage-billed' })!.text).toBe('billed by usage')
    expect(classPrice({ priceSource: 'unknown' })!.text).toBe('—')
    expect(classPrice({})).toBeUndefined()
  })
})

describe('unused claims', () => {
  it('use their own price state on newer servers', () => {
    const none = claimIndex([])
    expect(unusedCost(unused('a', 8, { costKnown: true, priceSource: 'default' }), none)).toMatchObject({ text: '$8.00', kind: 'known' })
    expect(unusedCost(unused('b', 0, { costKnown: false, priceSource: 'usage-billed' }), none)).toMatchObject({ text: 'billed by usage' })
    expect(unusedCost(unused('c', 0, { costKnown: false, priceSource: 'unknown' }), none)).toMatchObject({ text: '—' })
  })
  it('borrow the matching claim state, or show the estimate, on older servers', () => {
    const idx = claimIndex([claim('efs', { costKnown: false, priceSource: 'usage-billed' }), claim('gp3', { costKnown: true, estMonthlyCostUSD: 8, priceSource: 'ebs-table' })])
    expect(unusedCost(unused('efs', 10), idx).text).toBe('billed by usage')
    expect(unusedCost(unused('gp3', 8), idx)).toMatchObject({ text: '$8.00', title: 'Price from the EBS price table for the volume type' })
    expect(unusedCost(unused('legacy', 10), idx)).toMatchObject({ text: '$10.00', kind: 'known' })
  })
  it('total only the known costs and count the rest', () => {
    const items = [
      unused('a', 8, { costKnown: true, priceSource: 'ebs-table' }),
      unused('b', 0, { costKnown: false, priceSource: 'usage-billed' }),
      unused('c', 2, { costKnown: true, priceSource: 'default' }),
      unused('d', 0, { costKnown: false, priceSource: 'unknown' }),
    ]
    expect(unusedTotal(items, claimIndex([]))).toEqual({ total: 10, unpriced: 2 })
  })
})
