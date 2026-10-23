/**
 * Settings rows: the desktop twins of the private row composables in mobile's
 * `SettingsScreen.kt` (SettingIconChip, SettingsToggle, SettingsLink) and
 * `VpnSettingsScreen.kt` (VpnToggle), plus `BirdoSectionHeader` from
 * `BirdoCard.kt`.
 *
 * Owner, 2026-10-21: Settings looks like mobile, and a row is its title and
 * its control. No row carries a description. The only text a row adds under
 * its title is `status`: why the control cannot be used right now (a fleet
 * gate, a plan, a plan still loading). It is not a description of the
 * setting, and a disabled switch with no reason reads as broken.
 *
 * Accessibility follows `BirdoListItem` (PR #162 review): the row IS the
 * switch (one tab stop), `aria-label` pins its name to the title, a status
 * is its description, and a blocked row stays focusable with `aria-disabled`.
 */
import { useId, type ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { Check, ChevronRight, ExternalLink, Lock } from 'lucide-react';
import { BirdoCard } from '@/components/birdo';
import { BirdoSwitchKnob } from '@/components/birdo/ListItem';
import { brand, hairline, surface, white } from '@/lib/birdo-theme';

/** Mobile `BirdoSectionHeader`: accent tick + tracked uppercase micro-label. */
export function SettingsSectionHeader({ title }: { title: string }) {
  return (
    <div role="heading" aria-level={2} className="flex w-full items-center pb-2 pl-1 pt-5">
      <span
        aria-hidden
        className="h-3 w-[3px] shrink-0 rounded-[2px]"
        style={{ backgroundColor: brand.accent, opacity: 0.85 }}
      />
      <span
        className="ml-2 flex-1 text-[11px] font-semibold uppercase tracking-[1.5px]"
        style={{ color: white.w60 }}
      >
        {title}
      </span>
    </div>
  );
}

/** Mobile `SettingIconChip`: a 36px rounded square. Decorative (the title names the row). */
export function SettingIconChip({ icon: Icon, tint }: { icon: LucideIcon; tint: string }) {
  return (
    <span
      aria-hidden
      className="flex h-9 w-9 shrink-0 items-center justify-center"
      style={{ borderRadius: 10, backgroundColor: surface.s2, border: `1px solid ${hairline.soft}` }}
    >
      <Icon size={18} color={tint} />
    </span>
  );
}

/**
 * `chip`: the Settings tab (mobile SettingsToggle/SettingsLink: icon chip,
 * 16px card, 14px padding). `bare`: VPN Settings (mobile VpnToggle: a plain
 * 22px icon, 14px card, 16px side padding).
 */
export type SettingsRowStyle = 'chip' | 'bare';

const CARD_RADIUS: Record<SettingsRowStyle, number> = { chip: 16, bare: 14 };
const ROW_PADDING: Record<SettingsRowStyle, string> = { chip: 'px-3.5 py-3.5', bare: 'px-4 py-3.5' };

/**
 * The row fills its card, and the card clips (`overflow-hidden`), so the
 * global focus ring (2px, offset 2px OUTSIDE) would be cut away entirely: it
 * is drawn inside the row instead, following the card's corners.
 */
const ROW_FOCUS: Record<SettingsRowStyle, string> = {
  chip: 'rounded-[15px] focus-visible:-outline-offset-2',
  bare: 'rounded-[13px] focus-visible:-outline-offset-2',
};

/** One row per card, as on mobile. */
export function SettingsCard({
  children,
  rowStyle = 'chip',
  padding = '0',
}: {
  children: ReactNode;
  rowStyle?: SettingsRowStyle;
  padding?: string;
}) {
  return (
    <BirdoCard cornerRadius={CARD_RADIUS[rowStyle]} padding={padding}>
      {children}
    </BirdoCard>
  );
}

function Leading({ icon: Icon, tint, rowStyle }: { icon: LucideIcon; tint: string; rowStyle: SettingsRowStyle }) {
  if (rowStyle === 'chip') return <SettingIconChip icon={Icon} tint={tint} />;
  return <Icon size={22} color={tint} aria-hidden className="shrink-0" />;
}

function Title({ text, enabled, rowStyle }: { text: string; enabled: boolean; rowStyle: SettingsRowStyle }) {
  return (
    <div
      className={`text-[14px] leading-snug ${rowStyle === 'chip' ? 'font-semibold' : 'font-medium'}`}
      // Disabled: w55, the faintest tier that still passes AA for text.
      style={{ color: enabled ? white.w100 : white.w55 }}
    >
      {text}
    </div>
  );
}

/**
 * Why the control cannot be used right now. Shown in full (the window is a
 * fixed 380px wide, so a truncated reason could never be read).
 */
function Status({ id, text }: { id: string; text: string }) {
  return (
    <div id={id} className="mt-0.5 whitespace-normal break-words text-xs leading-snug" style={{ color: white.w60 }}>
      {text}
    </div>
  );
}

/**
 * A locked row's trailing lock and the plan that has it. The lock is
 * decorative, so a screen reader also hears "Requires" before the plan:
 * "Port Forwarding Requires Sovereign", not a bare plan name.
 */
function LockedTrailing({ label }: { label?: string }) {
  return (
    <span className="ml-2 flex shrink-0 items-center gap-1 text-xs" style={{ color: white.w60 }}>
      <Lock size={16} aria-hidden />
      {label ? (
        <>
          {/* The space outside: a name computation may trim it inside. */}
          <span className="sr-only">Requires</span> {label}
        </>
      ) : (
        'View plans'
      )}
    </span>
  );
}

export interface SettingsToggleProps {
  icon: LucideIcon;
  iconColor: string;
  title: string;
  checked: boolean;
  onCheckedChange: (next: boolean) => void;
  enabled?: boolean;
  /** Why the switch cannot be used right now. Never a description of the setting. */
  status?: string;
  /**
   * The plan does not include this setting: a lock (and the plan that has
   * it) instead of a switch, and the whole row routes to the upgrade.
   */
  locked?: { onClick: () => void; label?: string };
  rowStyle?: SettingsRowStyle;
}

export function SettingsToggle({
  icon,
  iconColor,
  title,
  checked,
  onCheckedChange,
  enabled = true,
  status,
  locked,
  rowStyle = 'chip',
}: SettingsToggleProps) {
  const statusId = useId();
  const padding = ROW_PADDING[rowStyle];
  const gap = rowStyle === 'chip' ? 'gap-3' : 'gap-3.5';

  if (locked) {
    return (
      <SettingsCard rowStyle={rowStyle}>
        <button
          type="button"
          onClick={locked.onClick}
          className={`flex w-full items-center ${gap} ${padding} ${ROW_FOCUS[rowStyle]} text-left transition-colors hover:bg-white/5`}
        >
          <Leading icon={icon} tint={white.w55} rowStyle={rowStyle} />
          <div className="min-w-0 flex-1">
            <Title text={title} enabled rowStyle={rowStyle} />
          </div>
          <LockedTrailing label={locked.label} />
        </button>
      </SettingsCard>
    );
  }

  const Row = enabled ? 'button' : 'div';
  return (
    <SettingsCard rowStyle={rowStyle}>
      <Row
        type={enabled ? 'button' : undefined}
        role="switch"
        aria-checked={checked}
        aria-label={title}
        aria-describedby={status ? statusId : undefined}
        aria-disabled={enabled ? undefined : true}
        // A blocked row stays reachable so its state and reason can be read.
        tabIndex={enabled ? undefined : 0}
        onClick={enabled ? () => onCheckedChange(!checked) : undefined}
        className={`flex w-full items-center ${gap} ${padding} ${ROW_FOCUS[rowStyle]} text-left ${
          enabled ? 'transition-colors hover:bg-white/5' : ''
        }`}
      >
        <Leading icon={icon} tint={enabled ? iconColor : white.w55} rowStyle={rowStyle} />
        <div className="min-w-0 flex-1">
          <Title text={title} enabled={enabled} rowStyle={rowStyle} />
          {status && <Status id={statusId} text={status} />}
        </div>
        <span className="ml-2 shrink-0">
          <BirdoSwitchKnob checked={checked} disabled={!enabled} />
        </span>
      </Row>
    </SettingsCard>
  );
}

export interface SettingsLinkProps {
  icon: LucideIcon;
  iconColor: string;
  title: string;
  onClick: () => void;
  /** `external` opens a web page (mobile's OpenInNew trailing icon). */
  trailing?: 'chevron' | 'external';
  /**
   * The plan does not include it (mobile SettingsLink's `locked`): a dimmed
   * chip, and a lock with the plan that has it instead of the chevron. The
   * row still takes the click, and the caller decides where it goes.
   */
  locked?: { label: string };
}

/** Mobile `SettingsLink`: chip, title, chevron. */
export function SettingsLink({ icon, iconColor, title, onClick, trailing = 'chevron', locked }: SettingsLinkProps) {
  const Trailing = trailing === 'external' ? ExternalLink : ChevronRight;
  return (
    <SettingsCard>
      <button
        type="button"
        onClick={onClick}
        className={`flex w-full items-center gap-3 px-3.5 py-3.5 ${ROW_FOCUS.chip} text-left transition-colors hover:bg-white/5`}
      >
        <SettingIconChip icon={icon} tint={locked ? white.w55 : iconColor} />
        <div className="min-w-0 flex-1">
          <Title text={title} enabled rowStyle="chip" />
        </div>
        {locked ? (
          <LockedTrailing label={locked.label} />
        ) : (
          <Trailing size={18} color={white.w55} aria-hidden className="ml-2 shrink-0" />
        )}
      </button>
    </SettingsCard>
  );
}

/** A row that shows a value and offers no choice (VPN Settings › WireGuard Port). */
export function SettingsValueRow({
  icon,
  iconColor,
  title,
  value,
  rowStyle = 'bare',
}: {
  icon: LucideIcon;
  iconColor: string;
  title: string;
  value: string;
  rowStyle?: SettingsRowStyle;
}) {
  return (
    <SettingsCard rowStyle={rowStyle}>
      <div className={`flex w-full items-center ${rowStyle === 'chip' ? 'gap-3' : 'gap-3.5'} ${ROW_PADDING[rowStyle]}`}>
        <Leading icon={icon} tint={iconColor} rowStyle={rowStyle} />
        <div className="min-w-0 flex-1">
          <Title text={title} enabled rowStyle={rowStyle} />
        </div>
        <span className="ml-2 shrink-0 text-[13px]" style={{ color: white.w60 }}>
          {value}
        </span>
      </div>
    </SettingsCard>
  );
}

/**
 * Mobile's MTU "Automatic (server default)" row: a checkbox, the row is the
 * control. `birdo-check` keeps the state visible in forced colours.
 */
export function SettingsCheckRow({
  title,
  checked,
  onCheckedChange,
}: {
  title: string;
  checked: boolean;
  onCheckedChange: (next: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      onClick={() => onCheckedChange(!checked)}
      className="flex w-full items-center gap-3 rounded-[10px] px-1 py-1.5 text-left transition-colors hover:bg-white/5"
    >
      <span
        aria-hidden
        data-checked={checked || undefined}
        className="birdo-check flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-[3px]"
        style={{
          backgroundColor: checked ? brand.accent : 'transparent',
          border: `2px solid ${checked ? brand.accent : white.w55}`,
        }}
      >
        {checked && <Check size={14} strokeWidth={3} color="#FFFFFF" />}
      </span>
      <span className="text-[14px]" style={{ color: white.w80 }}>
        {title}
      </span>
    </button>
  );
}

/** Mobile's info note (VPN Settings): a raised strip with an info icon. */
export function SettingsNote({
  icon: Icon,
  children,
  live = false,
}: {
  icon: LucideIcon;
  children: ReactNode;
  live?: boolean;
}) {
  return (
    <div
      className="flex items-center gap-2.5 p-3"
      style={{ borderRadius: 12, backgroundColor: surface.s2 }}
      aria-live={live ? 'polite' : undefined}
    >
      <Icon size={18} color={white.w55} aria-hidden className="shrink-0" />
      <p className="text-xs" style={{ color: white.w60 }}>
        {children}
      </p>
    </div>
  );
}
