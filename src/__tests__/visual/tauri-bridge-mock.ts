/**
 * The Tauri bridge, faked for the visual harness: `invoke` answers
 * `get_usage_stats` with the reading the `?s=` scenario names and everything
 * else with null. Imported FIRST by limit-harness.tsx, so it is in place
 * before any module that reads `window.__TAURI_INTERNALS__` at load time
 * (TitleBar's getCurrentWindow()).
 */

/** Minutes ago, as an ISO instant (the freshness line reads "Updated 2 min ago"). */
const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString();

const reading = (usedGb: number, limitGb: number | null, plan = 'RECON') => ({
  plan,
  bandwidthLimitGb: limitGb,
  bandwidthUsedGb: usedGb,
  bandwidthPeriodEnd: '2026-10-31T23:59:59.999Z',
  bandwidthLastSyncAt: ago(2),
  bandwidthIsFresh: true,
});

/** `?s=` → what get_usage_stats returns; 'loading' never answers, 'error' fails. */
export const SCENARIOS: Record<string, unknown> = {
  empty: reading(0, 50),
  half: reading(25, 50),
  warn: reading(40.2, 50),
  full: reading(50, 50),
  over: reading(63.4, 50),
  small: reading(0.52, 50),
  unlimited: reading(184.6, null, 'SOVEREIGN'),
  nosync: { ...reading(0, 50), bandwidthLastSyncAt: null, bandwidthIsFresh: false },
};

export const scenario = new URLSearchParams(window.location.search).get('s') ?? 'half';

(window as unknown as { __TAURI_INTERNALS__: unknown }).__TAURI_INTERNALS__ = {
  invoke: (cmd: string) => {
    if (cmd !== 'get_usage_stats') return Promise.resolve(null);
    if (scenario === 'loading') return new Promise(() => {});
    if (scenario === 'error') return Promise.reject({ code: 'network', message: 'offline', retryable: true });
    return Promise.resolve(SCENARIOS[scenario] ?? SCENARIOS.half);
  },
  transformCallback: () => 0,
  unregisterCallback: () => {},
  metadata: { currentWindow: { label: 'main' }, currentWebview: { windowLabel: 'main', label: 'main' } },
};
