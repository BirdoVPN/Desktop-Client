/**
 * BirdoTextField — labeled glass text field used across login, settings, and
 * DNS screens. Mirrors mobile's `BirdoTextField.kt`.
 *
 * Border: soft hairline → purpleSoft@60% on focus → red on error.
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

  // Neutral focus: a brighter white border on focus (no purple, no glow ring),
  // red on error. The subtle fill change + inner highlight give it depth without
  // the coloured glow.
  const borderColor = error
    ? status.red
    : focused
    ? 'rgba(255,255,255,0.30)'
    : disabled
    ? 'rgba(255,255,255,0.05)'
    : 'rgba(255,255,255,0.10)';

  // No coloured focus glow — only a faint red ring on error; otherwise just a
  // gentle inner top highlight at all times.
  const boxShadow = error
    ? '0 0 0 3px rgba(248,113,113,0.14)'
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
          backgroundColor: focused ? 'rgba(255,255,255,0.06)' : 'rgba(255,255,255,0.035)',
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
          className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-[color:var(--placeholder)] disabled:cursor-not-allowed"
          style={{
            color: focused ? white.w100 : white.w80,
            // expose placeholder color to the pseudo-element
            ['--placeholder' as string]: white.w20,
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
