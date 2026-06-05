/**
 * PortForward — mobile-parity Port Forwarding screen.
 *
 * Pixel-faithful port of mobile's `PortForwardScreen.kt`:
 *   • BirdoTopBar "Port Forwarding" + back (popRoute).
 *   • Info row explaining the feature.
 *   • "NEW RULE" BirdoSubCard — port field (1-65535) + TCP/UDP segmented
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
import { Info, Plus, Trash2, ArrowRightLeft, Network } from 'lucide-react';
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
import { white, status, hairline } from '@/lib/birdo-theme';

type Protocol = 'tcp' | 'udp';

/** create_port_forward returns the created rule (camelCase, mirrors Rust). */
interface CreatePortForwardResult {
  id: string;
  externalPort: number;
  internalPort: number;
  protocol: string;
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
  const [error, setError] = useState<string | null>(null);

  const portValue = Number.parseInt(portText, 10);
  const isPortValid =
    portText.length > 0 &&
    !Number.isNaN(portValue) &&
    portValue >= 1 &&
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
      const created = await invoke<CreatePortForwardResult>('create_port_forward', {
        port: portValue,
        protocol,
      });
      setPortForwards([
        ...portForwards,
        {
          id: created.id,
          externalPort: created.externalPort,
          internalPort: created.internalPort,
          protocol: created.protocol,
          enabled: true,
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
      setError(null);
      try {
        await invoke('delete_port_forward', { id });
        setPortForwards(portForwards.filter((pf) => pf.id !== id));
      } catch (e) {
        setError(typeof e === 'string' ? e : 'Failed to delete port forwarding rule.');
      }
    },
    [portForwards, setPortForwards]
  );

  return (
    <div className="flex h-full flex-col">
      <BirdoTopBar title="Port Forwarding" onBack={popRoute} />

      <div className="flex-1 overflow-y-auto px-4 py-2">
        {/* ── Info row ─────────────────────────────────────────────────── */}
        <div
          className="flex items-start gap-2.5 p-3"
          style={{ borderRadius: 12, backgroundColor: white.w10 }}
        >
          <Info size={18} color={white.w40} aria-hidden className="mt-0.5 shrink-0" />
          <p className="text-[13px]" style={{ color: white.w60 }}>
            Forward external ports on your VPN server to a local port on your
            device. Useful for hosting services behind the VPN.
          </p>
        </div>

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
              Port must be 1-65535
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
              <PortForwardRow key={pf.id} rule={pf} onDelete={handleDelete} />
            ))}
          </div>
        )}

        <div className="h-8" />
      </div>
    </div>
  );
}

// ── Single active-rule row (external → internal + protocol badge + delete) ──
interface PortForwardRowProps {
  rule: PortForwardRule;
  onDelete: (id: string) => void;
}

function PortForwardRow({ rule, onDelete }: PortForwardRowProps) {
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
          <BirdoBadge text={rule.protocol.toUpperCase()} tone="neutral" />
        </div>
      </div>

      <button
        type="button"
        onClick={() => onDelete(rule.id)}
        aria-label={`Delete rule ${rule.externalPort}`}
        className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full transition-colors hover:bg-white/5"
      >
        <Trash2 size={18} color={status.red} aria-hidden />
      </button>
    </div>
  );
}
