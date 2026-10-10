type RegressionSummary = {
  passed?: unknown
  failed?: unknown
  skipped?: unknown
  errored?: unknown
  inconclusive?: unknown
}

/** Format the persisted /api/regression/runs summary without inferring missing counts. */
export function formatRegressionHistorySummary(summary: unknown): string {
  const value = summary && typeof summary === 'object' ? summary as RegressionSummary : null
  const count = (key: keyof RegressionSummary) => {
    const n = value?.[key]
    return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 ? String(n) : '—'
  }

  return `${count('passed')} passed · ${count('failed')} failed · ${count('skipped')} skipped · ${count('errored')} errored · ${count('inconclusive')} inconclusive`
}
