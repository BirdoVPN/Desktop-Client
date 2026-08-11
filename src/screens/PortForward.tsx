/**
 * PortForward — mobile-parity Port Forwarding screen.
 *
 * Pixel-faithful port of mobile's `PortForwardScreen.kt`:
 *   • BirdoTopBar "Port Forwarding" + back (popRoute).
 *   • "NEW RULE" BirdoSubCard — port field (1024-65535) + TCP/UDP segmented
 *     toggle + Add button → invoke('create_port_forward', { port, protocol }).
 *   • "ACTIVE RULES" — loading / empty (BirdoEmptyState) / list of rules,
 *     each row external → internal with a Delete →
 *     invoke('delete_port_forward', { id }).
 *
 * Rules are loaded on mount via invoke('get_port_forwards') and stored in the
 * zustand `portForwards` slice (camelCase Server/PortForward shape).
 */
import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useShallow } from 'zustand/react/shallow';
import { motion, AnimatePresence } from 'framer-motion';
import { Plus, Trash2, ArrowRightLeft, Network } from 'lucide-react';
import {
  BirdoTopBar,
  BirdoSubCard,
  BirdoSectionHeader,
  BirdoTextField,
  BirdoButton,
  BirdoBadge,
  BirdoEmptyState,
} from '@/components/birdo';
import { useAppStore, type PortForward as PortForwardRule } from '@/store/app-store';
import { white, status, hairline, surface, gradient, motion as motionTokens } from '@/lib/birdo-theme';

type Protocol = 'tcp' | 'udp';

/**
 * Wire shape of `create_port_forward` — mirrors the Rust
 * `CreatePortForwardResponse` (`#[serde(rename_all = "camelCase")]`, types.rs):
 * `{ success, message?, portForward? }`. The rule fields live INSIDE
 * `portForward`, and a backend refusal arrives as `success: false` with a
 * `message` — this interface used to declare the rule fields at the top level,
 * so every add rendered `{id: undefined, ...}` into the store (crashing the
 * screen on `protocol.toUpperCase()`) and refusals were indistinguishable from
 * success.
 */
interface CreatePortForwardResult {
  success: boolean;
  message?: string | null;
  portForward?: {
    id: string;
    externalPort: number;
    internalPort: number;
    protocol: string;
    enabled: boolean;
  } | null;
}

export function PortForward() {
  const { popRoute, portForwards, setPortForwards } = useAppStore(
    useShallow((s) => ({
      popRoute: s.popRoute,
      portForwards: s.portForwards,
      setPortForwards: s.setPortForwards,
    }))
  );

  const [portText, setPortText] = useState('');
  const [protocol, setProtocol] = useState<Protocol>('tcp');
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [deletingIds, setDeletingIds] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  // Deleting a rule tears down a live DNAT mapping — confirm before it happens
  // (mobile parity; a mis-click otherwise silently removes a rule).
  const [pendingDelete, setPendingDelete] = useState<PortForwardRule | null>(null);

  const portValue = Number.parseInt(portText, 10);
  // Must match the Rust command's range (vpn_port_forward rejects <1024 —
  // privileged ports); accepting 1-1023 here just deferred the error to a
  // confusing backend message after submit.
  const isPortValid =
    portText.length > 0 &&
    !Number.isNaN(portValue) &&
    portValue >= 1024 &&
    portValue <= 65535;
  const showPortError = portText.length > 0 && !isPortValid;

  // ── Load active rules on mount ──────────────────────────────────────────
  const loadRules = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rules = await invoke<PortForwardRule[]>('get_port_forwards');
      setPortForwards(rules);
    } catch (e) {
      setError(typeof e === 'string' ? e : 'Failed to load port forwarding rules.');
    } finally {
      setLoading(false);
    }
  }, [setPortForwards]);

  useEffect(() => {
    void loadRules();
  }, [loadRules]);

  // ── Create ──────────────────────────────────────────────────────────────
  const handleAdd = useCallback(async () => {
    if (!isPortValid || adding) return;
    setAdding(true);
    setError(null);
    try {
      const res = await invoke<CreatePortForwardResult>('create_port_forward', {
        port: portValue,
        protocol,
      });
      // Branch on `success` and read the rule from `portForward` — a refusal
      // (plan limit, port taken) must surface its message, never render as a
      // half-empty "successful" row.
      if (!res.success || !res.portForward) {
        setError(res.message || 'Failed to create port forwarding rule.');
        return;
      }
      const created = res.portForward;
      setPortForwards([
        ...portForwards,
        {
          id: created.id,
          externalPort: created.externalPort,
          internalPort: created.internalPort,
          protocol: created.protocol,
          enabled: created.enabled ?? true,
        },
      ]);
      setPortText('');
    } catch (e) {
      setError(typeof e === 'string' ? e : 'Failed to create port forwarding rule.');
    } finally {
      setAdding(false);
    }
  }, [isPortValid, adding, portValue, protocol, portForwards, setPortForwards]);

  // ── Delete ──────────────────────────────────────────────────────────────
  const handleDelete = useCallback(
    async (id: string) => {
      // Guard against rapid-fire / concurrent deletes of the same rule.
      if (deletingIds.has(id)) return;
      setError(null);
      setDeletingIds((prev) => new Set(prev).add(id));
      try {
        await invoke('delete_port_forward', { id });
        setPortForwards(portForwards.filter((pf) => pf.id !== id));
      } catch (e) {
        setError(typeof e === 'string' ? e : 'Failed to delete port forwarding rule.');
      } finally {
        setDeletingIds((prev) => {
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
      }
    },
    [deletingIds, portForwards, setPortForwards]
  );

  return (
    <div className="flex h-full flex-col">
      <BirdoTopBar title="Port Forwarding" onBack={popRoute} />

      <div className="flex-1 overflow-y-auto px-4 py-2">
        {/* ── Error display ────────────────────────────────────────────── */}
        {error && (
          <div
            className="mt-1.5 p-3 text-[13px]"
            style={{
              borderRadius: 12,
              backgroundColor: status.redBg,
              color: status.red,
            }}
            role="alert"
          >
            {error}
          </div>
        )}

        {/* ── New rule ─────────────────────────────────────────────────── */}
        <BirdoSectionHeader title="New Rule" className="mt-3" />
        <BirdoSubCard padding="1rem">
          <BirdoTextField
            value={portText}
            onChange={(v) => setPortText(v.replace(/\D/g, '').slice(0, 5))}
            label="Internal Port"
            placeholder="e.g. 8080"
            error={showPortError}
            ariaLabel="Internal port"
          />
          {showPortError && (
            <p className="mt-1.5 pl-1 text-xs" style={{ color: status.red }}>
              Port must be 1024-65535
            </p>
          )}

          {/* Protocol segmented toggle (TCP / UDP) */}
          <div className="mt-3 flex items-center gap-3">
            <span className="text-sm" style={{ color: white.w60 }}>
              Protocol
            </span>
            <div
              className="inline-flex p-0.5"
              role="group"
              aria-label="Protocol"
              style={{
                borderRadius: 10,
                backgroundColor: white.w05,
                border: `1px solid ${white.w20}`,
              }}
            >
              {(['tcp', 'udp'] as const).map((proto) => {
                const selected = protocol === proto;
                return (
                  <button
                    key={proto}
                    type="button"
                    onClick={() => setProtocol(proto)}
                    aria-pressed={selected}
                    className="px-4 py-1 text-xs font-semibold uppercase tracking-wide transition-colors"
                    style={{
                      borderRadius: 8,
                      backgroundColor: selected ? white.w10 : 'transparent',
                      color: selected ? '#FFFFFF' : white.w40,
                    }}
                  >
                    {proto}
                  </button>
                );
              })}
            </div>
          </div>

          <BirdoButton
            text="Add Rule"
            onClick={handleAdd}
            icon={Plus}
            fullWidth
            isLoading={adding}
            disabled={!isPortValid || adding}
            className="mt-4"
          />
        </BirdoSubCard>

        {/* ── Active rules ─────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Active Rules" className="mt-4" />

        {loading ? (
          <div className="flex w-full items-center justify-center py-6">
            <span
              className="h-6 w-6 animate-spin rounded-full border-2"
              style={{ borderColor: white.w60, borderTopColor: 'transparent' }}
              aria-label="Loading"
            />
          </div>
        ) : portForwards.length === 0 ? (
          <BirdoSubCard padding="0">
            <BirdoEmptyState
              icon={Network}
              title="No rules yet"
              description="Add one above to get started."
            />
          </BirdoSubCard>
        ) : (
          <div className="flex flex-col gap-1">
            {portForwards.map((pf) => (
              <PortForwardRow
                key={pf.id}
                rule={pf}
                onRequestDelete={setPendingDelete}
                deleting={deletingIds.has(pf.id)}
              />
            ))}
          </div>
        )}

        <div className="h-8" />
      </div>

      <AnimatePresence>
        {pendingDelete && (
          <DeleteRuleDialog
            rule={pendingDelete}
            onCancel={() => setPendingDelete(null)}
            onConfirm={() => {
              const id = pendingDelete.id;
              setPendingDelete(null);
              void handleDelete(id);
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

// ── Delete confirmation dialog ──────────────────────────────────────────────
function DeleteRuleDialog({
  rule,
  onCancel,
  onConfirm,
}: {
  rule: PortForwardRule;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onCancel]);

  return (
    <motion.div
      className="absolute inset-0 z-50 flex items-center justify-center p-5"
      style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: motionTokens.fast, ease: motionTokens.ease }}
      onClick={onCancel}
    >
      <motion.div
        role="dialog"
        aria-modal="true"
        aria-label="Delete port forwarding rule"
        className="w-full max-w-[340px] overflow-hidden rounded-birdo-lg"
        style={{
          background: `linear-gradient(${surface.s3}, ${surface.s3}) padding-box, ${gradient.glassStroke} border-box`,
          border: '1px solid transparent',
        }}
        initial={{ scale: 0.94, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.94, opacity: 0 }}
        transition={{ duration: motionTokens.standard, ease: motionTokens.ease }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex flex-col gap-4 p-5">
          <div className="flex items-center gap-2">
            <Trash2 size={20} color={status.red} aria-hidden />
            <h2 className="text-[16px] font-bold" style={{ color: '#FFFFFF' }}>
              Delete rule?
            </h2>
          </div>
          <p className="text-[13px]" style={{ color: white.w60 }}>
            Remove the {(rule.protocol || '').toUpperCase()} forward{' '}
            <span className="font-medium" style={{ color: white.w80 }}>
              {rule.externalPort} → {rule.internalPort}
            </span>
            ? This tears down the live mapping immediately.
          </p>
          <div className="flex gap-2.5">
            <BirdoButton text="Cancel" variant="secondary" fullWidth onClick={onCancel} />
            <BirdoButton text="Delete" variant="danger" fullWidth onClick={onConfirm} />
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}

// ── Single active-rule row (external → internal + protocol badge + delete) ──
interface PortForwardRowProps {
  rule: PortForwardRule;
  onRequestDelete: (rule: PortForwardRule) => void;
  deleting: boolean;
}

function PortForwardRow({ rule, onRequestDelete, deleting }: PortForwardRowProps) {
  return (
    <div
      className="flex items-center gap-3.5 px-4 py-3.5"
      style={{
        borderRadius: 14,
        backgroundColor: white.w03,
        border: `1px solid ${hairline.soft}`,
      }}
    >
      <ArrowRightLeft size={22} color={status.green} aria-hidden className="shrink-0" />

      <div className="min-w-0 flex-1">
        <div className="flex items-center text-[15px] font-medium">
          <span style={{ color: white.w80 }}>{rule.externalPort}</span>
          <span className="px-1.5" style={{ color: white.w40 }}>
            →
          </span>
          <span style={{ color: white.w80 }}>{rule.internalPort}</span>
        </div>
        <div className="mt-1">
          {/* Defensive: a malformed rule must degrade to a blank badge, not
              throw into the screen's error boundary. */}
          <BirdoBadge text={(rule.protocol || '').toUpperCase()} tone="neutral" />
        </div>
      </div>

      <button
        type="button"
        onClick={() => onRequestDelete(rule)}
        disabled={deleting}
        aria-label={`Delete rule ${rule.externalPort}`}
        aria-busy={deleting}
        className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full transition-colors hover:bg-white/5 disabled:opacity-50"
      >
        {deleting ? (
          <span
            className="h-4 w-4 animate-spin rounded-full border-2"
            style={{ borderColor: status.red, borderTopColor: 'transparent' }}
            aria-hidden
          />
        ) : (
          <Trash2 size={18} color={status.red} aria-hidden />
        )}
      </button>
    </div>
  );
}
