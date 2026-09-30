/**
 * PortForward — mobile-parity Port Forwarding screen.
 *
 * A failed LOAD is its own state with a Retry, never "No port forwarding
 * rules yet" (W2-030): the empty state used to render under the error banner,
 * telling users they had no rules when the list had merely failed to load.
 * Errors from add / delete are mapped by code, not shown raw (W2-012).
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
import { useShallow } from 'zustand/react/shallow';
import { Plus, Trash2, ArrowRightLeft, Network, AlertCircle } from 'lucide-react';
import {
  BirdoTopBar,
  BirdoSubCard,
  BirdoSectionHeader,
  BirdoTextField,
  BirdoButton,
  BirdoBadge,
  BirdoEmptyState,
  BirdoDialog,
} from '@/components/birdo';
import { useAppStore, type PortForward as PortForwardRule } from '@/store/app-store';
import { white, status, hairline, brand } from '@/lib/birdo-theme';
import { errorCopy } from '@/lib/errors';
import { toIpcError } from '@/lib/ipc';
import { command } from '@/session/command';

/** Copy for an add / delete failure; unclassified refusals get `fallback`. */
function portForwardError(e: unknown, fallback: string): string {
  const err = toIpcError(e);
  return err.code === 'unknown' ? fallback : errorCopy(err).message;
}

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
  const [loadError, setLoadError] = useState(false);
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
    setLoadError(false);
    try {
      const rules = await command<PortForwardRule[]>('get_port_forwards');
      setPortForwards(Array.isArray(rules) ? rules : []);
    } catch {
      setLoadError(true);
    } finally {
      setLoading(false);
    }
  }, [setPortForwards]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- load-on-mount; loadRules sets the loading flag synchronously (a no-op on first render, where it is already true)
    void loadRules();
  }, [loadRules]);

  // ── Create ──────────────────────────────────────────────────────────────
  const handleAdd = useCallback(async () => {
    if (!isPortValid || adding) return;
    setAdding(true);
    setError(null);
    try {
      const res = await command<CreatePortForwardResult>('create_port_forward', {
        port: portValue,
        protocol,
      });
      // Branch on `success` and read the rule from `portForward` — a refusal
      // (plan limit, port taken) must surface its message, never render as a
      // half-empty "successful" row.
      if (!res.success || !res.portForward) {
        setError(
          "Couldn't add that rule. Check your plan includes Port Forwarding and the port is free, then try again.",
        );
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
      setError(portForwardError(e, "Couldn't add that rule. Please try again."));
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
        await command('delete_port_forward', { id });
        setPortForwards(portForwards.filter((pf) => pf.id !== id));
      } catch (e) {
        setError(portForwardError(e, "Couldn't delete that rule. Please try again."));
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
        <BirdoSectionHeader title="New rule" className="mt-3" />
        <BirdoSubCard padding="1rem">
          <BirdoTextField
            value={portText}
            onChange={(v) => setPortText(v.replace(/\D/g, '').slice(0, 5))}
            label="Internal port"
            placeholder="e.g. 8080"
            inputMode="numeric"
            errorText={showPortError ? 'Port must be 1024–65535' : null}
          />

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
                    className="birdo-toggle px-4 py-1 text-xs font-semibold uppercase tracking-wide transition-colors"
                    style={{
                      borderRadius: 8,
                      backgroundColor: selected ? white.w10 : 'transparent',
                      color: selected ? '#FFFFFF' : white.w60,
                    }}
                  >
                    {proto}
                  </button>
                );
              })}
            </div>
          </div>

          <BirdoButton
            text="Add rule"
            onClick={handleAdd}
            icon={Plus}
            fullWidth
            isLoading={adding}
            disabled={!isPortValid || adding}
            className="mt-4"
          />
        </BirdoSubCard>

        {/* ── Active rules ─────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Active rules" className="mt-4" />

        {loadError ? (
          <BirdoSubCard padding="0">
            <BirdoEmptyState
              icon={AlertCircle}
              title="Couldn't load your rules"
              description="Your rules are unchanged. Check your connection and try again."
              action={
                <BirdoButton text="Retry" variant="secondary" size="medium" onClick={() => void loadRules()} />
              }
            />
          </BirdoSubCard>
        ) : loading ? (
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
              title="No port forwarding rules yet"
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

      <BirdoDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        title="Delete rule?"
        icon={Trash2}
        iconColor={status.red}
      >
        {pendingDelete && (
          <p className="text-[13px]" style={{ color: white.w60 }}>
            Remove the {(pendingDelete.protocol || '').toUpperCase()} forward{' '}
            <span className="font-medium" style={{ color: white.w80 }}>
              {pendingDelete.externalPort} → {pendingDelete.internalPort}
            </span>
            ? This tears down the live mapping immediately.
          </p>
        )}
        <div className="flex gap-2.5">
          <BirdoButton text="Cancel" variant="secondary" fullWidth onClick={() => setPendingDelete(null)} />
          <BirdoButton
            text="Delete"
            variant="danger"
            fullWidth
            onClick={() => {
              if (!pendingDelete) return;
              const id = pendingDelete.id;
              setPendingDelete(null);
              void handleDelete(id);
            }}
          />
        </div>
      </BirdoDialog>
    </div>
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
      <ArrowRightLeft size={22} color={brand.accent} aria-hidden className="shrink-0" />

      <div className="min-w-0 flex-1">
        <div className="flex items-center text-[15px] font-medium">
          <span style={{ color: white.w80 }}>{rule.externalPort}</span>
          <span className="px-1.5" style={{ color: white.w60 }} aria-label="to">
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
