/**
 * Account API contract item 40: `features.<PLAN>.customDns` from the server's
 * client-config. Custom DNS is on every plan (owner decision D6) and the
 * server sends `true` for each, so on today's and tomorrow's servers this
 * does nothing.
 *
 * If the server ever says `false` for the user's plan, the Settings row reads
 * OFF and cannot be switched on. That alone would be a row that lies: Rust's
 * saved settings would still carry the addresses, and the tunnel would keep
 * using them. So the user's switch is turned off through the normal save path
 * as well (the addresses are kept, as with any switch-off, P1-parity-042) and
 * a live tunnel is rebuilt without them.
 */
import { useEffect, useRef } from 'react';
import { customDnsAvailable } from '@/lib/plan';
import { useAppStore } from '@/store/app-store';
import { persistSettings } from '@/session/settings-persist';

export function useCustomDnsGate(): void {
  const offered = useAppStore((s) => customDnsAvailable(s.account.plan, s.customDnsByPlan));
  // `persistSettings` writes the whole object: never before Rust's copy has
  // loaded, or the user's settings would be replaced with defaults.
  const hydrated = useAppStore((s) => s.settingsHydrated);
  const on = useAppStore((s) => s.settings.customDnsEnabled);
  // One attempt per refusal: a failed save puts the switch back ON, and
  // retrying on that change would loop for as long as saves fail.
  const tried = useRef(false);
  useEffect(() => {
    if (offered) {
      tried.current = false;
      return;
    }
    if (!hydrated || !on || tried.current) return;
    tried.current = true;
    const hasAddresses = (useAppStore.getState().settings.customDns ?? []).length > 0;
    void persistSettings({ customDnsEnabled: false }, { reapply: hasAddresses, quiet: true });
  }, [offered, hydrated, on]);
}
