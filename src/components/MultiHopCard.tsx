/**
 * MultiHopCard — Connect-page card for Multi-Hop (Double VPN) routing.
 *
 *  • SOVEREIGN-only feature. Lower tiers see a locked card; clicking it
 *    opens an upgrade modal explaining the requirement.
 *  • SOVEREIGN users see current Entry → Exit selection. Tap the card to open
 *    a bottom-sheet picker for entry & exit nodes.
 *  • The actual connection is initiated by the main Connect button on the
 *    Dashboard. This card only configures which two hops to use.
 *
 *  Replaces the previous Multi-Hop section that lived in Settings.
 */
import { useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open as openExternal } from '@tauri-apps/plugin-shell';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Layers,
  ChevronRight,
  X,
  ArrowRight,
  Lock,
  Sparkles,
  Power,
  Check,
  AlertCircle,
} from 'lucide-react';
import { useAppStore, type Server } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { settingsToRust, countryCodeToFlag } from '@/utils/helpers';
import { surface, hairline, white, status, brand } from '@/lib/birdo-theme';

interface MultiHopCardProps {
  /** True while the main connect flow is running. Disables interaction. */
  busy: boolean;
}

const planLevel = (plan: string | null | undefined): number => {
  switch (plan?.toUpperCase()) {
    case 'SOVEREIGN':
      return 2;
    case 'OPERATIVE':
      return 1;
    default:
      return 0;
  }
};

export function MultiHopCard({ busy }: MultiHopCardProps) {
  const { settings, updateSettings, servers, account } = useAppStore(
    useShallow((s) => ({
      settings: s.settings,
      updateSettings: s.updateSettings,
      servers: s.servers,
      account: s.account,
    })),
  );

  const [showPicker, setShowPicker] = useState(false);
  const [showUpgrade, setShowUpgrade] = useState(false);

  const userPlan = planLevel(account?.plan);
  const isSovereign = userPlan >= 2;

  const entryServer = servers.find((s) => s.id === settings.multiHopEntryNodeId) || null;
  const exitServer = servers.find((s) => s.id === settings.multiHopExitNodeId) || null;
  const enabled = settings.multiHopEnabled;

  // Persist a settings patch to both Zustand and the Rust backend.
  const persist = useCallback(
    async (patch: Partial<typeof settings>) => {
      const next = { ...settings, ...patch };
      updateSettings(patch);
      try {
        await invoke('save_settings', { settings: settingsToRust(next) });
      } catch {
        /* Rust will log */
      }
    },
    [settings, updateSettings],
  );

  const handleCardClick = useCallback(() => {
    if (busy) return;
    if (!isSovereign) {
      setShowUpgrade(true);
      return;
    }
    setShowPicker(true);
  }, [busy, isSovereign]);

  const handleToggle = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      if (busy) return;
      if (!isSovereign) {
        setShowUpgrade(true);
        return;
      }
      persist({ multiHopEnabled: !enabled });
    },
    [busy, isSovereign, enabled, persist],
  );

  // ── Card render ────────────────────────────────────────────────────
  return (
    <>
      <button
        type="button"
        onClick={handleCardClick}
        disabled={busy}
        className="w-full rounded-2xl px-3.5 py-3 text-left transition disabled:opacity-50"
        style={{
          backgroundColor: surface.s2,
          border: `1px solid ${enabled && isSovereign ? brand.purple : hairline.soft}`,
        }}
      >
        <div className="flex items-center gap-3">
          <div
            className="flex h-10 w-10 items-center justify-center rounded-full"
            style={{
              backgroundColor: enabled && isSovereign ? 'rgba(168,85,247,0.15)' : 'rgba(255,255,255,0.05)',
            }}
          >
            {isSovereign ? (
              <Layers size={18} color={enabled ? brand.purple : white.w60} />
            ) : (
              <Lock size={16} color={white.w40} />
            )}
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <p className="text-sm font-medium" style={{ color: white.w100 }}>
                Multi-Hop
              </p>
              {!isSovereign && (
                <span
                  className="rounded-full px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                  style={{ backgroundColor: 'rgba(168,85,247,0.18)', color: brand.purple }}
                >
                  Sovereign
                </span>
              )}
            </div>

            {!isSovereign ? (
              <p className="truncate text-xs" style={{ color: white.w60 }}>
                Upgrade to chain two servers for extra privacy
              </p>
            ) : enabled && entryServer && exitServer ? (
              <div className="mt-0.5 flex items-center gap-1.5 text-xs" style={{ color: white.w60 }}>
                <span>{countryCodeToFlag(entryServer.countryCode)}</span>
                <span className="truncate">{entryServer.city || entryServer.name}</span>
                <ArrowRight size={11} style={{ color: white.w40 }} />
                <span>{countryCodeToFlag(exitServer.countryCode)}</span>
                <span className="truncate">{exitServer.city || exitServer.name}</span>
              </div>
            ) : enabled ? (
              <p className="text-xs" style={{ color: status.yellowLight }}>
                Tap to choose entry &amp; exit servers
              </p>
            ) : (
              <p className="text-xs" style={{ color: white.w60 }}>
                Off — tap to configure
              </p>
            )}
          </div>

          {/* Toggle switch (only meaningful when Sovereign) */}
          <button
            type="button"
            role="switch"
            aria-checked={enabled && isSovereign}
            aria-label="Enable Multi-Hop"
            onClick={handleToggle}
            disabled={busy}
            className="relative h-6 w-11 shrink-0 rounded-full transition disabled:opacity-40"
            style={{
              backgroundColor: enabled && isSovereign ? brand.purple : 'rgba(255,255,255,0.18)',
            }}
          >
            <div
              className="absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all"
              style={{ left: enabled && isSovereign ? '22px' : '2px' }}
            />
          </button>

          <ChevronRight size={16} style={{ color: white.w40 }} />
        </div>
      </button>

      {/* ── Picker bottom sheet (Sovereign only) ──────────────────── */}
      <AnimatePresence>
        {showPicker && (
          <MultiHopPicker
            servers={servers}
            entryId={settings.multiHopEntryNodeId}
            exitId={settings.multiHopExitNodeId}
            onApply={(entryId, exitId) => {
              persist({
                multiHopEntryNodeId: entryId,
                multiHopExitNodeId: exitId,
                multiHopEnabled: !!(entryId && exitId),
              });
              setShowPicker(false);
            }}
            onDisable={() => {
              persist({ multiHopEnabled: false });
              setShowPicker(false);
            }}
            onClose={() => setShowPicker(false)}
          />
        )}
      </AnimatePresence>

      {/* ── Tier-locked upgrade modal ─────────────────────────────── */}
      <AnimatePresence>
        {showUpgrade && <UpgradeModal onClose={() => setShowUpgrade(false)} />}
      </AnimatePresence>
    </>
  );
}

// ────────────────────────────────────────────────────────────────────
// Picker
// ────────────────────────────────────────────────────────────────────

interface PickerProps {
  servers: Server[];
  entryId: string | null;
  exitId: string | null;
  onApply: (entryId: string | null, exitId: string | null) => void;
  onDisable: () => void;
  onClose: () => void;
}

function MultiHopPicker({ servers, entryId, exitId, onApply, onDisable, onClose }: PickerProps) {
  const [step, setStep] = useState<'entry' | 'exit'>(entryId ? 'exit' : 'entry');
  const [draftEntry, setDraftEntry] = useState<string | null>(entryId);
  const [draftExit, setDraftExit] = useState<string | null>(exitId);

  const onlineServers = servers.filter((s) => s.isOnline);
  const exitChoices = onlineServers.filter((s) => s.id !== draftEntry);
  const canApply = !!(draftEntry && draftExit && draftEntry !== draftExit);

  return (
    <motion.div
      className="absolute inset-0 z-50 flex items-end justify-center bg-black/70 backdrop-blur-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.div
        className="w-full max-w-md rounded-t-3xl px-5 pt-4 pb-6"
        style={{ backgroundColor: surface.s2, border: `1px solid ${hairline.soft}` }}
        initial={{ y: '100%' }}
        animate={{ y: 0 }}
        exit={{ y: '100%' }}
        transition={{ type: 'spring', damping: 28, stiffness: 280 }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drag handle */}
        <div className="mx-auto mb-3 h-1 w-10 rounded-full" style={{ backgroundColor: white.w20 }} />

        {/* Header + step indicator */}
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers size={16} color={brand.purple} />
            <h3 className="text-base font-semibold" style={{ color: white.w100 }}>
              Multi-Hop Route
            </h3>
          </div>
          <button onClick={onClose} aria-label="Close" className="rounded-full p-1 hover:bg-white/10">
            <X size={16} color={white.w60} />
          </button>
        </div>

        {/* Visual route */}
        <div
          className="mb-3 flex items-center justify-between rounded-xl px-3 py-2 text-xs"
          style={{ backgroundColor: white.w05, color: white.w60 }}
        >
          <RouteHop
            label="Entry"
            server={onlineServers.find((s) => s.id === draftEntry) || null}
            active={step === 'entry'}
            onClick={() => setStep('entry')}
          />
          <ArrowRight size={14} style={{ color: white.w40 }} />
          <RouteHop
            label="Exit"
            server={onlineServers.find((s) => s.id === draftExit) || null}
            active={step === 'exit'}
            onClick={() => draftEntry && setStep('exit')}
            disabled={!draftEntry}
          />
        </div>

        {/* Server list for current step */}
        <div className="mb-3 max-h-72 overflow-y-auto rounded-xl" style={{ backgroundColor: white.w05 }}>
          {(step === 'entry' ? onlineServers : exitChoices).length === 0 ? (
            <p className="p-4 text-center text-sm" style={{ color: white.w60 }}>
              No servers available.
            </p>
          ) : (
            (step === 'entry' ? onlineServers : exitChoices).map((s) => {
              const selected = step === 'entry' ? s.id === draftEntry : s.id === draftExit;
              return (
                <button
                  key={s.id}
                  onClick={() => {
                    if (step === 'entry') {
                      setDraftEntry(s.id);
                      // If exit equals new entry, clear exit and advance
                      if (draftExit === s.id) setDraftExit(null);
                      setStep('exit');
                    } else {
                      setDraftExit(s.id);
                    }
                  }}
                  className="flex w-full items-center gap-3 px-3 py-2.5 text-left transition hover:bg-white/5"
                  style={{ borderBottom: `1px solid ${hairline.soft}` }}
                >
                  <span className="text-base">{countryCodeToFlag(s.countryCode)}</span>
                  <div className="flex-1 min-w-0">
                    <p className="truncate text-sm font-medium" style={{ color: white.w100 }}>
                      {s.city ? `${s.city}, ${s.country}` : s.name}
                    </p>
                    <p className="text-xs" style={{ color: white.w60 }}>
                      {s.load}% load{typeof s.ping === 'number' ? ` • ${s.ping} ms` : ''}
                    </p>
                  </div>
                  {selected && <Check size={16} color={brand.purple} />}
                </button>
              );
            })
          )}
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          <button
            onClick={onDisable}
            className="rounded-xl px-3 py-2.5 text-sm font-medium transition hover:bg-white/10"
            style={{
              backgroundColor: white.w05,
              color: white.w60,
              border: `1px solid ${hairline.soft}`,
            }}
          >
            <Power size={14} className="inline mr-1" />
            Disable
          </button>
          <button
            disabled={!canApply}
            onClick={() => onApply(draftEntry, draftExit)}
            className="flex-1 rounded-xl py-2.5 text-sm font-medium transition disabled:opacity-40"
            style={{
              backgroundColor: canApply ? brand.purple : white.w10,
              color: white.w100,
            }}
          >
            {canApply ? 'Apply Route' : 'Select Both Servers'}
          </button>
        </div>

        <p className="mt-3 flex items-start gap-2 text-[11px]" style={{ color: white.w40 }}>
          <AlertCircle size={11} className="mt-0.5 shrink-0" />
          <span>
            Your traffic flows: You&nbsp;→&nbsp;{onlineServers.find((s) => s.id === draftEntry)?.country || 'Entry'}&nbsp;→&nbsp;
            {onlineServers.find((s) => s.id === draftExit)?.country || 'Exit'}&nbsp;→&nbsp;Internet. Press the main Connect button to apply.
          </span>
        </p>
      </motion.div>
    </motion.div>
  );
}

function RouteHop({
  label,
  server,
  active,
  onClick,
  disabled,
}: {
  label: string;
  server: Server | null;
  active: boolean;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="flex flex-1 items-center gap-2 rounded-lg px-2 py-1 transition disabled:opacity-40"
      style={{
        backgroundColor: active ? 'rgba(168,85,247,0.18)' : 'transparent',
        border: active ? `1px solid ${brand.purple}` : '1px solid transparent',
      }}
    >
      <span className="text-base">{server ? countryCodeToFlag(server.countryCode) : '—'}</span>
      <div className="min-w-0 text-left">
        <p className="text-[10px] uppercase tracking-wide" style={{ color: white.w40 }}>
          {label}
        </p>
        <p className="truncate text-xs font-medium" style={{ color: white.w100 }}>
          {server ? server.city || server.name : 'Select…'}
        </p>
      </div>
    </button>
  );
}

// ────────────────────────────────────────────────────────────────────
// Tier-locked upgrade modal
// ────────────────────────────────────────────────────────────────────

function UpgradeModal({ onClose }: { onClose: () => void }) {
  return (
    <motion.div
      className="absolute inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.div
        className="mx-6 w-full max-w-sm rounded-2xl p-6 text-center"
        style={{ backgroundColor: surface.s2, border: `1px solid ${hairline.soft}` }}
        initial={{ scale: 0.92, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.92, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="mx-auto mb-3 flex h-14 w-14 items-center justify-center rounded-full"
          style={{ backgroundColor: 'rgba(168,85,247,0.15)' }}
        >
          <Sparkles size={28} color={brand.purple} />
        </div>
        <h3 className="mb-2 text-lg font-semibold" style={{ color: white.w100 }}>
          Multi-Hop is a Sovereign feature
        </h3>
        <p className="mb-5 text-sm" style={{ color: white.w60 }}>
          Chain two servers for stronger anonymity. The entry server only sees your IP, the exit
          server only sees the destination.
        </p>
        <div className="mb-5 space-y-2 text-left text-xs" style={{ color: white.w60 }}>
          <FeatureLine text="Two-hop encrypted routing" />
          <FeatureLine text="Quantum-resistant key exchange" />
          <FeatureLine text="No-logs policy with mesh isolation" />
          <FeatureLine text="Port forwarding included" />
        </div>
        <div className="flex gap-3">
          <button
            type="button"
            onClick={onClose}
            className="flex-1 rounded-xl py-2.5 text-sm font-medium transition hover:bg-white/10"
            style={{
              backgroundColor: white.w05,
              color: white.w100,
              border: `1px solid ${hairline.soft}`,
            }}
          >
            Not now
          </button>
          <button
            type="button"
            onClick={() => {
              // Open the billing/upgrade page in the user's default browser
              openExternal('https://birdo.app/account#upgrade').catch(() => {});
              onClose();
            }}
            className="flex-1 rounded-xl py-2.5 text-sm font-semibold transition hover:opacity-90"
            style={{ backgroundColor: brand.purple, color: white.w100 }}
          >
            Upgrade
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

function FeatureLine({ text }: { text: string }) {
  return (
    <div className="flex items-center gap-2">
      <Check size={12} color={brand.purple} />
      <span>{text}</span>
    </div>
  );
}
