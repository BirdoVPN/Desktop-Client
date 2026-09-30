/**
 * Derived connection state, kept OUT of app-store.ts so the many component
 * tests that replace the store module with a plain object still get the real
 * derivation (a mocked module has no selectors).
 */
import type { AppStateSnapshot, ConnectionState } from '@/store/app-store';

/**
 * What the pill, the CTA and the announcer show: the Rust state, with the
 * user's in-flight command laid over it until that command settles.
 */
export function selectDisplayState(
  s: Pick<AppStateSnapshot, 'connectionState' | 'pendingAction'>,
): ConnectionState {
  switch (s.pendingAction) {
    case 'disconnecting':
      return s.connectionState === 'disconnected' ? 'disconnected' : 'disconnecting';
    case 'connecting':
      return s.connectionState === 'connected' ? 'connected' : 'connecting';
    case 'switching':
      return 'switching';
    default:
      return s.connectionState;
  }
}

/** A tunnel exists, is being built, or traffic is being held for one. */
export function selectTunnelActive(
  s: Pick<AppStateSnapshot, 'connectionState' | 'pendingAction' | 'killSwitchBlocking'>,
): boolean {
  return s.connectionState !== 'disconnected' || s.pendingAction !== null || s.killSwitchBlocking;
}
