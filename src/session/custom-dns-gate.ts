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
 *
 * WIN3-009 item 4: if that rebuild fails, Rust puts the previous settings
 * back — Custom DNS on again — and the UI re-reads them. That is not a
 * refused save, so the gate switches it off again; this time it saves the
 * file only. The live session took the revert, and rebuilding it again for
 * the same change would loop for as long as the rebuild keeps failing: the
 * next connect applies it.
 */
import { useEffect, useRef, useState } from 'react';
import { customDnsAvailable } from '@/lib/plan';
import { useAppStore } from '@/store/app-store';
import { persistSettings } from '@/session/settings-persist';

export function useCustomDnsGate(): void {
  const offered = useAppStore((s) => customDnsAvailable(s.account.plan, s.customDnsByPlan));
  // `persistSettings` writes the whole object: never before Rust's copy has
  // loaded, or the user's settings would be replaced with defaults.
  const hydrated = useAppStore((s) => s.settingsHydrated);
  const on = useAppStore((s) => s.settings.customDnsEnabled);
  // Where the gate's last switch-off stands. One attempt per refusal: a
  // failed save puts the switch back ON, and retrying on that change would
  // loop for as long as saves fail. One that was SAVED and is ON again was
  // put back by a revert, and is switched off again (file only).
  const attempt = useRef<'none' | 'saving' | 'saved' | 'refused'>('none');
  // Looks again once a save settles: a revert can land while it runs.
  const [settled, setSettled] = useState(0);
  useEffect(() => {
    if (offered) {
      attempt.current = 'none';
      return;
    }
    if (!hydrated || !on) return;
    if (attempt.current === 'saving' || attempt.current === 'refused') return;
    const again = attempt.current === 'saved';
    attempt.current = 'saving';
    const hasAddresses = (useAppStore.getState().settings.customDns ?? []).length > 0;
    void persistSettings({ customDnsEnabled: false }, { reapply: hasAddresses && !again, quiet: true }).then(
      (saved) => {
        attempt.current = saved ? 'saved' : 'refused';
        setSettled((n) => n + 1);
      },
    );
  }, [offered, hydrated, on, settled]);
}
