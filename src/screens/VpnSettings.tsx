/**
 * VpnSettings — pushed sub-screen, pixel-faithful to mobile's
 * `VpnSettingsScreen.kt`.
 *
 * Sections (mobile order): SECURITY (Kill Switch, Stealth Mode, Quantum
 * Protection), NETWORK (Local Network Sharing), DNS (Custom DNS expandable),
 * WIREGUARD (Port radio group + MTU), an info note, then FEATURES
 * (Port Forwarding nav row).
 *
 * Every toggle reads/writes the Zustand store settings and persists via the
 * SAME full-object `invoke('save_settings', { settings: settingsToRust(...) })`
 * path used by Settings.tsx / MultiHopCard.tsx. Changes apply on next connect.
 *
 * Kill Switch is special: the Rust `disable_killswitch` command is REJECTED
 * while the VPN is connected/connecting, so we surface that inline and read the
 * live armed state from `get_killswitch_status` on mount.
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useShallow } from 'zustand/react/shallow';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  EyeOff,
  Lock,
  Network,
  Globe,
  Router,
  SlidersHorizontal,
  Info,
  ArrowLeftRight,
  ChevronRight,
  AlertTriangle,
} from 'lucide-react';
import {
  BirdoTopBar,
  BirdoCard,
  BirdoSectionHeader,
  BirdoToggleRow,
  BirdoNavRow,
  BirdoTextField,
} from '@/components/birdo';
import { useAppStore } from '@/store/app-store';
import { settingsToRust, isValidPort } from '@/utils/helpers';
import { white, status, brand, hairline, motion as motionTokens } from '@/lib/birdo-theme';

interface KillSwitchStatus {
  enabled: boolean;
  active: boolean;
  blocking_connections: number;
}

export function VpnSettings() {
  const { settings, updateSettings, connectionState, popRoute, pushRoute } = useAppStore(
    useShallow((s) => ({
      settings: s.settings,
      updateSettings: s.updateSettings,
      connectionState: s.connectionState,
      popRoute: s.popRoute,
      pushRoute: s.pushRoute,
    })),
  );

  // The Rust `disable_killswitch` command is rejected unless the tunnel is fully
  // down. Mirror that here (anything other than disconnected/error counts as up).
  const vpnActive = connectionState !== 'disconnected' && connectionState !== 'error';

  const [killSwitchError, setKillSwitchError] = useState<string | null>(null);
  const [dnsExpanded, setDnsExpanded] = useState(false);
  const [customPortInput, setCustomPortInput] = useState(
    !['auto', '51820', '53'].includes(settings.wireGuardPort) ? settings.wireGuardPort : '',
  );
  const [customMtuInput, setCustomMtuInput] = useState(
    settings.wireGuardMtu > 0 ? String(settings.wireGuardMtu) : '',
  );
  const saveDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
    };
  }, []);

  // Reconcile the armed kill-switch flag with the backend's source of truth.
  useEffect(() => {
    invoke<KillSwitchStatus>('get_killswitch_status')
      .then((s) => {
        if (s.enabled !== settings.killSwitchEnabled) {
          updateSettings({ killSwitchEnabled: s.enabled });
        }
      })
      .catch(() => {
        /* Rust logs; keep persisted preference */
      });
    // Run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep DNS-derived custom port/MTU inputs in sync if settings change elsewhere.
  useEffect(() => {
    if (!['auto', '51820', '53'].includes(settings.wireGuardPort)) {
      setCustomPortInput(settings.wireGuardPort);
    }
    if (settings.wireGuardMtu > 0) {
      setCustomMtuInput(String(settings.wireGuardMtu));
    }
  }, [settings.wireGuardPort, settings.wireGuardMtu]);

  // Persist the FULL settings object via the shared settingsToRust path.
  const saveSettingsToBackend = useCallback(async (next: typeof settings) => {
    try {
      await invoke('save_settings', { settings: settingsToRust(next) });
    } catch {
      /* Rust backend logs the error */
    }
  }, []);

  // Patch the store + persist the full object.
  const persist = useCallback(
    (patch: Partial<typeof settings>) => {
      const next = { ...useAppStore.getState().settings, ...patch };
      updateSettings(patch);
      saveSettingsToBackend(next);
    },
    [updateSettings, saveSettingsToBackend],
  );

  // ── Kill Switch (special: armed via enable/disable_killswitch) ────────────
  const handleKillSwitch = useCallback(
    async (value: boolean) => {
      setKillSwitchError(null);
      try {
        if (value) {
          await invoke('enable_killswitch');
        } else {
          await invoke('disable_killswitch');
        }
      } catch (err) {
        const msg = String(err);
        const lower = msg.toLowerCase();
        if (lower.includes('administrator') || lower.includes('admin') || lower.includes('root') || lower.includes('privilege')) {
          setKillSwitchError('Kill switch requires running Birdo as administrator.');
        } else if (
          !value &&
          (lower.includes('connected') || lower.includes('connecting') || lower.includes('disconnect'))
        ) {
          setKillSwitchError('Disconnect before turning off the kill switch.');
        } else {
          setKillSwitchError(msg);
        }
        return;
      }
      persist({ killSwitchEnabled: value });
    },
    [persist],
  );

  // ── DNS helpers (custom DNS expandable: primary / secondary) ──────────────
  const dnsList = settings.customDns ?? [];
  const customDnsEnabled = dnsList.length > 0;
  const dnsPrimary = dnsList[0] ?? '';
  const dnsSecondary = dnsList[1] ?? '';

  const setDns = useCallback(
    (primary: string, secondary: string) => {
      const next = [primary.trim(), secondary.trim()].filter((v) => v.length > 0);
      persist({ customDns: next.length > 0 ? next : null });
    },
    [persist],
  );

  // ── WireGuard port selection ──────────────────────────────────────────────
  const portOptions = ['auto', '51820', '53', 'custom'] as const;
  const selectedPort = ['auto', '51820', '53'].includes(settings.wireGuardPort)
    ? settings.wireGuardPort
    : 'custom';

  const onSelectPort = (option: (typeof portOptions)[number]) => {
    if (option === 'custom') {
      persist({ wireGuardPort: isValidPort(customPortInput) ? customPortInput : 'auto' });
    } else {
      persist({ wireGuardPort: option });
    }
  };

  const portLabel = (option: (typeof portOptions)[number]) => {
    switch (option) {
      case 'auto':
        return 'Automatic';
      case 'custom':
        return 'Custom';
      default:
        return option;
    }
  };

  // ── MTU ───────────────────────────────────────────────────────────────────
  const mtuAuto = settings.wireGuardMtu === 0;

  return (
    <div className="flex h-full flex-col bg-birdo-s0">
      <BirdoTopBar title="VPN Settings" onBack={popRoute} />

      <div className="flex-1 overflow-y-auto px-4 pb-8 pt-2">
        {/* ── SECURITY ──────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Security" />

        <BirdoCard padding="0" className="overflow-visible">
          <BirdoToggleRow
            title="Kill Switch"
            subtitle="Block all internet traffic if the VPN connection drops, preventing data leaks."
            leadingIcon={Shield}
            leadingTint={status.green}
            checked={settings.killSwitchEnabled}
            onCheckedChange={handleKillSwitch}
          />
        </BirdoCard>

        <AnimatePresence>
          {killSwitchError && (
            <motion.div
              className="mt-2 flex items-start gap-2 rounded-birdo-sm px-3 py-2 text-xs"
              style={{
                backgroundColor: status.yellowBg,
                border: `1px solid ${hairline.soft}`,
                color: status.yellowLight,
              }}
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden />
              <span>{killSwitchError}</span>
            </motion.div>
          )}
        </AnimatePresence>

        {vpnActive && (
          <p className="mt-1.5 px-1 text-[11px]" style={{ color: white.w40 }}>
            The kill switch can&apos;t be turned off while the VPN is connected. Disconnect first.
          </p>
        )}

        <div className="h-2" />
        <BirdoCard padding="0">
          <BirdoToggleRow
            title="Stealth Mode"
            subtitle="Route through Xray Reality to bypass deep packet inspection. Makes VPN traffic look like normal HTTPS."
            leadingIcon={EyeOff}
            leadingTint={status.blue}
            checked={settings.stealthMode}
            onCheckedChange={(v) => persist({ stealthMode: v })}
          />
        </BirdoCard>

        <div className="h-2" />
        <BirdoCard padding="0">
          <BirdoToggleRow
            title="Quantum Protection"
            subtitle="Add post-quantum pre-shared key exchange via BirdoPQ v1 (ML-KEM-1024, NIST FIPS 203). Protects against future quantum attacks."
            leadingIcon={Lock}
            leadingTint={brand.purple}
            checked={settings.quantumProtection}
            onCheckedChange={(v) => persist({ quantumProtection: v })}
          />
        </BirdoCard>

        {/* ── NETWORK ───────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Network" className="mt-4" />

        <BirdoCard padding="0">
          <BirdoToggleRow
            title="Local Network Sharing"
            subtitle="Allow access to devices on your local network (printers, NAS) while connected."
            leadingIcon={Network}
            leadingTint={status.blue}
            checked={settings.localNetworkSharing}
            onCheckedChange={(v) => persist({ localNetworkSharing: v })}
          />
        </BirdoCard>

        {/* ── DNS ───────────────────────────────────────────────────── */}
        <BirdoSectionHeader title="DNS" className="mt-4" />

        <BirdoCard padding="0">
          <button
            type="button"
            onClick={() => setDnsExpanded((v) => !v)}
            className="flex w-full items-center gap-3.5 rounded-birdo-md px-3.5 py-3 text-left transition-colors hover:bg-white/5"
          >
            <div
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full"
              style={{ backgroundColor: white.w05 }}
            >
              <Globe size={18} color={brand.purple} aria-hidden />
            </div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-[15px] font-medium text-white">Custom DNS Servers</div>
              <div className="mt-0.5 truncate text-xs" style={{ color: white.w60 }}>
                {customDnsEnabled
                  ? `${dnsList.length} server${dnsList.length > 1 ? 's' : ''} configured`
                  : 'Using VPN default DNS'}
              </div>
            </div>
            <ChevronRight
              size={20}
              color={white.w40}
              aria-hidden
              className="shrink-0 transition-transform"
              style={{ transform: dnsExpanded ? 'rotate(90deg)' : 'none' }}
            />
          </button>

          <AnimatePresence initial={false}>
            {dnsExpanded && (
              <motion.div
                className="overflow-hidden"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: motionTokens.fast, ease: motionTokens.ease }}
              >
                <div className="space-y-3 px-3.5 pb-3.5 pt-1">
                  <BirdoTextField
                    label="Primary DNS"
                    placeholder="e.g. 1.1.1.1"
                    value={dnsPrimary}
                    onChange={(v) => setDns(v, dnsSecondary)}
                  />
                  <BirdoTextField
                    label="Secondary DNS (optional)"
                    placeholder="e.g. 1.0.0.1"
                    value={dnsSecondary}
                    onChange={(v) => setDns(dnsPrimary, v)}
                  />
                  <p className="text-xs" style={{ color: white.w40 }}>
                    Leave empty to use the VPN server&apos;s DNS. Popular options: 1.1.1.1
                    (Cloudflare), 8.8.8.8 (Google), 9.9.9.9 (Quad9).
                  </p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </BirdoCard>

        {/* ── WIREGUARD ─────────────────────────────────────────────── */}
        <BirdoSectionHeader title="WireGuard" className="mt-4" />

        {/* Port radio group */}
        <BirdoCard>
          <div className="flex items-center gap-3.5">
            <Router size={20} color={status.green} aria-hidden />
            <span className="text-[15px] font-medium text-white">WireGuard Port</span>
          </div>
          <div className="mt-3 space-y-1">
            {portOptions.map((option) => {
              const checked = selectedPort === option;
              return (
                <button
                  key={option}
                  type="button"
                  role="radio"
                  aria-checked={checked}
                  onClick={() => onSelectPort(option)}
                  className={`flex w-full items-center gap-3 rounded-birdo-sm px-3 py-2 text-left transition-colors ${
                    checked ? 'bg-white/10' : 'hover:bg-white/5'
                  }`}
                >
                  <span
                    className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full border-2"
                    style={{ borderColor: checked ? white.w100 : white.w40 }}
                  >
                    {checked && (
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: white.w100 }} />
                    )}
                  </span>
                  <span className="text-sm" style={{ color: white.w80 }}>
                    {portLabel(option)}
                  </span>
                </button>
              );
            })}

            {selectedPort === 'custom' && (
              <div className="pt-1">
                <BirdoTextField
                  placeholder="1-65535"
                  value={customPortInput}
                  onChange={(raw) => {
                    const filtered = raw.replace(/\D/g, '').slice(0, 5);
                    setCustomPortInput(filtered);
                    if (isValidPort(filtered)) {
                      updateSettings({ wireGuardPort: filtered });
                      if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
                      saveDebounceRef.current = setTimeout(() => {
                        saveSettingsToBackend({
                          ...useAppStore.getState().settings,
                          wireGuardPort: filtered,
                        });
                      }, 500);
                    }
                  }}
                />
              </div>
            )}
          </div>
          <p className="mt-2 text-xs" style={{ color: white.w40 }}>
            Use port 53 to bypass restrictive firewalls. Default is 51820.
          </p>
        </BirdoCard>

        {/* MTU */}
        <div className="h-2" />
        <BirdoCard>
          <div className="flex items-center gap-3.5">
            <SlidersHorizontal size={20} color={status.yellow} aria-hidden />
            <div>
              <div className="text-[15px] font-medium text-white">MTU</div>
              <div className="text-xs" style={{ color: white.w40 }}>
                Maximum transmission unit
              </div>
            </div>
          </div>
          <div className="mt-3 space-y-1">
            <button
              type="button"
              role="checkbox"
              aria-checked={mtuAuto}
              onClick={() => {
                if (mtuAuto) {
                  setCustomMtuInput('1420');
                  persist({ wireGuardMtu: 1420 });
                } else {
                  setCustomMtuInput('');
                  persist({ wireGuardMtu: 0 });
                }
              }}
              className="flex w-full items-center gap-3 rounded-birdo-sm px-3 py-2 text-left"
            >
              <span
                className="flex h-4 w-4 shrink-0 items-center justify-center rounded border-2"
                style={{
                  borderColor: mtuAuto ? white.w100 : white.w40,
                  backgroundColor: mtuAuto ? white.w100 : 'transparent',
                }}
              >
                {mtuAuto && (
                  <svg viewBox="0 0 12 12" className="h-3 w-3" style={{ color: '#000000' }}>
                    <path
                      d="M10 3L4.5 8.5L2 6"
                      stroke="currentColor"
                      strokeWidth="2"
                      fill="none"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                )}
              </span>
              <span className="text-sm" style={{ color: white.w80 }}>
                Automatic (use server default)
              </span>
            </button>

            {!mtuAuto && (
              <div className="pt-1">
                <BirdoTextField
                  placeholder="1280-1500"
                  value={customMtuInput}
                  onChange={(raw) => {
                    const filtered = raw.replace(/\D/g, '').slice(0, 4);
                    setCustomMtuInput(filtered);
                    const n = Number(filtered);
                    if (n >= 1280 && n <= 1500) {
                      updateSettings({ wireGuardMtu: n });
                      if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
                      saveDebounceRef.current = setTimeout(() => {
                        saveSettingsToBackend({
                          ...useAppStore.getState().settings,
                          wireGuardMtu: n,
                        });
                      }, 500);
                    }
                  }}
                />
                <p className="mt-1.5 text-xs" style={{ color: white.w40 }}>
                  Valid range: 1280 - 1500. Recommended: 1420.
                </p>
              </div>
            )}
          </div>
        </BirdoCard>

        {/* ── Info note ─────────────────────────────────────────────── */}
        <div
          className="mt-3 flex items-center gap-2.5 rounded-birdo-sm px-3 py-2.5"
          style={{ backgroundColor: white.w10 }}
        >
          <Info size={16} color={white.w40} aria-hidden className="shrink-0" />
          <p className="text-xs" style={{ color: white.w60 }}>
            Changes take effect on the next connection.
          </p>
        </div>

        {/* ── FEATURES ──────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Features" className="mt-4" />

        <BirdoCard padding="0">
          <BirdoNavRow
            title="Port Forwarding"
            subtitle="Forward external ports to your device for gaming, torrents, or servers."
            leadingIcon={ArrowLeftRight}
            leadingTint={status.blue}
            onClick={() => pushRoute('portForward')}
          />
        </BirdoCard>
      </div>
    </div>
  );
}
