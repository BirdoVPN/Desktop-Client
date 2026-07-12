/**
 * BirdoTextField — labeled glass text field used across login, settings, and
 * DNS screens. Mirrors mobile's `BirdoTextField.kt`.
 *
 * Border: soft hairline → emerald on focus → red on error.
 */
import { useState } from 'react';
import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { Eye, EyeOff } from 'lucide-react';
import { status, white } from '@/lib/birdo-theme';

export interface BirdoTextFieldProps {
  value: string;
  onChange: (next: string) => void;
  label?: string;
  placeholder?: string;
  type?: 'text' | 'password' | 'email';
  error?: boolean;
  disabled?: boolean;
  leadingIcon?: LucideIcon;
  trailing?: ReactNode;
  className?: string;
  ariaLabel?: string;
  autoComplete?: string;
}

export function BirdoTextField({
  value,
  onChange,
  label,
  placeholder = '',
  type = 'text',
  error = false,
  disabled = false,
  leadingIcon: LeadingIcon,
  trailing,
  className = '',
  ariaLabel,
  autoComplete,
}: BirdoTextFieldProps) {
  const [focused, setFocused] = useState(false);
  const [revealed, setRevealed] = useState(false);

  const isPassword = type === 'password';
  const inputType = isPassword ? (revealed ? 'text' : 'password') : type;

  // Focus = a soft, layered brand-emerald glow (a brighter emerald edge + a tight
  // ring + an outer bloom). Error = red. Otherwise a calm hairline. The glow
  // makes the active field unmistakable without a hard outline.
  const borderColor = error
    ? status.red
    : focused
    ? 'rgba(16,185,129,0.55)'
    : disabled
    ? 'rgba(255,255,255,0.05)'
    : 'rgba(255,255,255,0.10)';

  const boxShadow = error
    ? '0 0 0 3px rgba(248,113,113,0.16), inset 0 1px 0 rgba(255,255,255,0.04)'
    : focused
    ? '0 0 0 3px rgba(16,185,129,0.16), 0 0 22px -2px rgba(16,185,129,0.45), inset 0 1px 0 rgba(255,255,255,0.06)'
    : 'inset 0 1px 0 rgba(255,255,255,0.04)';

  return (
    <div className={className}>
      {label && (
        <label
          className="mb-1.5 block pl-1 text-xs font-medium tracking-tight"
          style={{ color: white.w60 }}
        >
          {label}
        </label>
      )}
      <div
        className="flex items-center gap-2.5 px-3.5 transition-all duration-150"
        style={{
          minHeight: 48,
          borderRadius: 14,
          // A solid, slightly-recessed dark well. The old ~3.5% white fill let the
          // animated background grid bleed straight through, so the field read as
          // barely-there; a near-opaque dark surface makes it a clear input.
          backgroundColor: focused ? 'rgba(24,24,34,0.92)' : 'rgba(16,16,23,0.85)',
          border: `1px solid ${borderColor}`,
          boxShadow,
          opacity: disabled ? 0.6 : 1,
        }}
      >
        {LeadingIcon && (
          <LeadingIcon size={18} color={white.w40} aria-hidden className="shrink-0" />
        )}
        <input
          type={inputType}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          placeholder={placeholder}
          disabled={disabled}
          aria-label={ariaLabel ?? label}
          aria-invalid={error ? 'true' : undefined}
          autoComplete={autoComplete}
          className="birdo-field-input min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-[color:var(--placeholder)] disabled:cursor-not-allowed"
          style={{
            color: focused ? white.w100 : white.w80,
            // expose placeholder color to the pseudo-element (raised to ~0.45 so
            // the hint text is legible on the solid field, not a ghost)
            ['--placeholder' as string]: 'rgba(255,255,255,0.45)',
          }}
        />
        {isPassword && (
          <button
            type="button"
            onClick={() => setRevealed((r) => !r)}
            disabled={disabled}
            aria-label={revealed ? 'Hide password' : 'Show password'}
            className="shrink-0 rounded-md p-0.5 transition-colors hover:bg-white/5 disabled:cursor-not-allowed"
          >
            {revealed ? (
              <EyeOff size={18} color={white.w40} aria-hidden />
            ) : (
              <Eye size={18} color={white.w40} aria-hidden />
            )}
          </button>
        )}
        {!isPassword && trailing && <div className="shrink-0">{trailing}</div>}
      </div>
    </div>
  );
}
