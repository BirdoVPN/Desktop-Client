/**
 * BirdoListItem — settings list row with leading icon, title, optional subtitle,
 * and trailing content (toggle, value text, chevron).
 *
 * Mirrors mobile's `BirdoListItem.kt` (BirdoListItem, BirdoToggleRow, BirdoNavRow).
 */
import { useId, type ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { ChevronRight } from 'lucide-react';
import { white, brand, hairline } from '@/lib/birdo-theme';

export interface BirdoListItemProps {
  title: string;
  subtitle?: string;
  leadingIcon?: LucideIcon;
  leadingTint?: string;
  trailing?: ReactNode;
  onClick?: () => void;
  enabled?: boolean;
  className?: string;
  /**
   * When the row itself is the control (BirdoToggleRow), it carries the
   * switch semantics so there is exactly ONE interactive element: a row
   * `<button>` wrapping a switch `<button>` is invalid HTML, gives keyboard
   * users two tab stops for one setting, and needed a stopPropagation hack to
   * avoid toggling twice.
   */
  role?: 'switch';
  ariaChecked?: boolean;
  /**
   * Let the subtitle WRAP instead of truncating to one ellipsised line.
   *
   * The default is `truncate`, which is right for a subtitle that is a value
   * or a hint ("Automatic", "2 apps"), and wrong for one that is the only
   * explanation of why a row is disabled: the window is a fixed, non-resizable
   * 380x640 (`src-tauri/tauri.conf.json`), which leaves the subtitle column
   * roughly 208px, so at `text-xs` (12px) about 34 characters survive and the
   * rest is an ellipsis the user can never reveal — there is no resize, no
   * tooltip and no horizontal scroll. A blocked row whose reason is cut off is
   * the same missing-information failure as a row that lies about its state.
   */
  subtitleWrap?: boolean;
}

export function BirdoListItem({
  title,
  subtitle,
  leadingIcon: Icon,
  leadingTint = white.w80,
  trailing,
  onClick,
  enabled = true,
  className = '',
  role,
  ariaChecked,
  subtitleWrap = false,
}: BirdoListItemProps) {
  const Wrapper = onClick && enabled ? 'button' : 'div';
  // A disabled control still has to be a control (PR #162 review, nits).
  // A blocked toggle row degrades to a <div role="switch">, and a plain div
  // carries no disabled semantics and is not focusable, so the row announced
  // as an ordinary switch reading "off" -- a screen-reader user was told the
  // setting was simply off, not that it was unavailable, which is the same
  // reassurance-from-missing-data failure as a row that lies visually.
  //
  // `aria-disabled` (not the `disabled` attribute, which a div cannot carry)
  // states it, and `tabIndex={0}` keeps the row in the tab order so the reason
  // can actually be reached: per the ARIA practices an aria-disabled control
  // stays focusable precisely so its state and description can be read. It has
  // no click handler, so reaching it does nothing.
  //
  // WHAT THE NAME/DESCRIPTION HALF IS FOR -- round-5 correction, because the
  // reason given for it in round 4 was measurably false. That revision said
  // the explanation sat "in a sibling node with nothing linking it" and that a
  // screen reader announced only "BirdoShield, switch, off". Neither was true:
  // the subtitle is a DESCENDANT of the element carrying role="switch", so it
  // was already part of the row's ACCESSIBLE NAME. Measured against the real
  // row with `aria-describedby` removed, the name computed to "BirdoShield Not
  // available on your account's server fleet yet. Your preference is kept and
  // applies as soon as it is." -- the reason WAS being announced, welded onto
  // the name, and adding `aria-describedby` ALONE made that same sentence the
  // description too, so every subtitled row (enabled ones included) said it
  // twice.
  //
  // The fix is the pair, not either half. `aria-label={title}` pins the NAME
  // to the setting ("BirdoShield"), and `aria-describedby` makes the subtitle
  // the DESCRIPTION -- so the row announces "BirdoShield, switch, off, dimmed"
  // and then, separately, why. Drop the label and the description duplicates
  // the name; drop the description and the reason is only ever heard welded to
  // the name, in the same breath as the state. The label is safe for WCAG
  // 2.5.3 (label in name) because `title` IS the row's visible label.
  //
  // `src/__tests__/BirdoShieldToggle.test.tsx` computes both strings and fails
  // if either collapses back into the other.
  const subtitleId = useId();
  const isSemanticControl = role !== undefined;
  // `Boolean(subtitle)` is spelling, not a bug fix, and the difference is
  // worth stating because review reported the opposite. The nit was that
  // `subtitle && isSemanticControl ? subtitleId : undefined` "yields '' for an
  // empty-string subtitle, so React would emit aria-describedby=\"\"". It does
  // not: `&&` binds tighter than `?:`, so '' is the falsy CONDITION and the
  // ternary already returns undefined. MEASURED both ways -- the attribute is
  // absent for `subtitle=""` under either form, which the test below pins so
  // the claim stops being re-litigated. This form just spares the next reader
  // deriving the precedence.
  const describedBy = isSemanticControl && Boolean(subtitle) ? subtitleId : undefined;
  return (
    <Wrapper
      type={Wrapper === 'button' ? 'button' : undefined}
      role={role}
      aria-checked={role === 'switch' ? ariaChecked : undefined}
      aria-disabled={isSemanticControl && !enabled ? true : undefined}
      aria-label={isSemanticControl ? title : undefined}
      aria-describedby={describedBy}
      tabIndex={Wrapper === 'div' && isSemanticControl ? 0 : undefined}
      onClick={onClick && enabled ? onClick : undefined}
      className={`flex w-full items-center gap-3.5 overflow-hidden rounded-birdo-md px-3.5 py-3 text-left ${
        onClick && enabled ? 'transition-colors hover:bg-white/5' : ''
      } ${className}`}
      disabled={Wrapper === 'button' ? !enabled : undefined}
    >
      {Icon && (
        <div
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full"
          style={{ backgroundColor: white.w05 }}
        >
          <Icon size={18} color={leadingTint} aria-hidden />
        </div>
      )}
      <div className="min-w-0 flex-1">
        <div
          className="truncate text-[15px] font-medium"
          style={{ color: enabled ? '#FFFFFF' : white.w40 }}
        >
          {title}
        </div>
        {subtitle && (
          <div
            id={describedBy}
            className={`mt-0.5 text-xs ${
              subtitleWrap ? 'whitespace-normal break-words leading-snug' : 'truncate'
            }`}
            style={{ color: white.w60 }}
          >
            {subtitle}
          </div>
        )}
      </div>
      {trailing && <div className="shrink-0">{trailing}</div>}
    </Wrapper>
  );
}

// ── Toggle row ────────────────────────────────────────────────────────────

export interface BirdoToggleRowProps {
  title: string;
  checked: boolean;
  onCheckedChange: (next: boolean) => void;
  subtitle?: string;
  leadingIcon?: LucideIcon;
  leadingTint?: string;
  enabled?: boolean;
  /** See `BirdoListItemProps.subtitleWrap`. */
  subtitleWrap?: boolean;
}

export function BirdoToggleRow({
  title,
  checked,
  onCheckedChange,
  subtitle,
  leadingIcon,
  leadingTint,
  enabled = true,
  subtitleWrap = false,
}: BirdoToggleRowProps) {
  return (
    <BirdoListItem
      title={title}
      subtitle={subtitle}
      leadingIcon={leadingIcon}
      leadingTint={leadingTint}
      enabled={enabled}
      subtitleWrap={subtitleWrap}
      role="switch"
      ariaChecked={checked}
      onClick={enabled ? () => onCheckedChange(!checked) : undefined}
      trailing={<BirdoSwitchKnob checked={checked} disabled={!enabled} />}
    />
  );
}

// ── Nav row (with chevron) ────────────────────────────────────────────────

export interface BirdoNavRowProps {
  title: string;
  onClick: () => void;
  subtitle?: string;
  leadingIcon?: LucideIcon;
  leadingTint?: string;
  valueText?: string;
  enabled?: boolean;
  /** See `BirdoListItemProps.subtitleWrap`. */
  subtitleWrap?: boolean;
}

export function BirdoNavRow({
  title,
  onClick,
  subtitle,
  leadingIcon,
  leadingTint,
  valueText,
  enabled = true,
  subtitleWrap = false,
}: BirdoNavRowProps) {
  return (
    <BirdoListItem
      title={title}
      subtitle={subtitle}
      leadingIcon={leadingIcon}
      leadingTint={leadingTint}
      enabled={enabled}
      subtitleWrap={subtitleWrap}
      onClick={onClick}
      trailing={
        <div className="flex items-center gap-1.5">
          {valueText && (
            <span className="text-[13px]" style={{ color: white.w60 }}>
              {valueText}
            </span>
          )}
          <ChevronRight size={20} color={white.w40} aria-hidden />
        </div>
      }
    />
  );
}

// ── Switch (emerald track) ────────────────────────────────────────────────

export interface BirdoSwitchProps {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  ariaLabel?: string;
}

/**
 * The switch's appearance alone -- no semantics, no handlers. Used inside
 * BirdoToggleRow, where the ROW is the switch; the knob just shows its state.
 */
export function BirdoSwitchKnob({ checked, disabled = false }: { checked: boolean; disabled?: boolean }) {
  return (
    <span
      aria-hidden
      className={`relative inline-flex h-[28px] w-[48px] shrink-0 items-center rounded-full transition-colors ${
        disabled ? 'opacity-40' : ''
      }`}
      style={{
        backgroundColor: checked ? brand.accent : white.w10,
        border: `1px solid ${checked ? 'transparent' : hairline.soft}`,
      }}
    >
      <span
        className="inline-block h-[22px] w-[22px] transform rounded-full bg-white shadow-sm transition-transform"
        style={{
          transform: checked ? 'translateX(22px)' : 'translateX(2px)',
          backgroundColor: checked ? '#FFFFFF' : white.w60,
        }}
      />
    </span>
  );
}

/** A standalone switch control (its own button). Not for use inside a clickable row. */
export function BirdoSwitch({ checked, onChange, disabled = false, ariaLabel }: BirdoSwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => {
        if (!disabled) onChange(!checked);
      }}
      className="cursor-pointer disabled:cursor-not-allowed"
    >
      <BirdoSwitchKnob checked={checked} disabled={disabled} />
    </button>
  );
}
