/**
 * BirdoRadioGroup — a real radio group (W2-035): `role="radiogroup"` around
 * `role="radio"` buttons, one tab stop (the checked option), arrow keys move
 * and select. The WireGuard port options were radios with no group, and the
 * window-position buttons announced nothing about which was selected ("Top L").
 */
import { useRef, type KeyboardEvent } from 'react';
import type { LucideIcon } from 'lucide-react';
import { brand, white } from '@/lib/birdo-theme';

export interface RadioOption<T extends string> {
  value: T;
  label: string;
  icon?: LucideIcon;
}

export interface BirdoRadioGroupProps<T extends string> {
  label: string;
  options: RadioOption<T>[];
  value: T;
  onChange: (value: T) => void;
  /** `list`: stacked rows with a radio dot. `segmented`: a grid of pill buttons. */
  variant?: 'list' | 'segmented';
  columns?: number;
}

export function BirdoRadioGroup<T extends string>({
  label,
  options,
  value,
  onChange,
  variant = 'list',
  columns = 2,
}: BirdoRadioGroupProps<T>) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const current = Math.max(0, options.findIndex((o) => o.value === value));

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const forward = e.key === 'ArrowDown' || e.key === 'ArrowRight';
    const back = e.key === 'ArrowUp' || e.key === 'ArrowLeft';
    if (!forward && !back) return;
    e.preventDefault();
    const next = (index + (forward ? 1 : -1) + options.length) % options.length;
    onChange(options[next].value);
    refs.current[next]?.focus();
  };

  return (
    <div
      role="radiogroup"
      aria-label={label}
      className={variant === 'segmented' ? 'grid gap-1 rounded-birdo-sm p-1' : 'space-y-1'}
      style={
        variant === 'segmented'
          ? { gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))`, backgroundColor: white.w05 }
          : undefined
      }
    >
      {options.map((opt, i) => {
        const checked = i === current;
        const Icon = opt.icon;
        const common = {
          ref: (el: HTMLButtonElement | null) => {
            refs.current[i] = el;
          },
          type: 'button' as const,
          role: 'radio',
          'aria-checked': checked,
          tabIndex: checked ? 0 : -1,
          onClick: () => onChange(opt.value),
          onKeyDown: (e: KeyboardEvent<HTMLButtonElement>) => onKeyDown(e, i),
        };
        return variant === 'segmented' ? (
          <button
            key={opt.value}
            {...common}
            className="birdo-radio flex items-center justify-center gap-1.5 rounded-birdo-xs px-2 py-2 text-[12px] font-medium transition-colors"
            style={{
              backgroundColor: checked ? brand.accentBg : 'transparent',
              border: checked ? `1px solid ${brand.accent}` : '1px solid transparent',
              color: checked ? brand.accentSoft : white.w60,
            }}
          >
            {Icon && <Icon size={14} aria-hidden />}
            {opt.label}
          </button>
        ) : (
          <button
            key={opt.value}
            {...common}
            className={`birdo-radio flex w-full items-center gap-3 rounded-birdo-sm px-3 py-2 text-left transition-colors ${
              checked ? 'bg-white/10' : 'hover:bg-white/5'
            }`}
          >
            <span
              className="birdo-radio-dot flex h-4 w-4 shrink-0 items-center justify-center rounded-full border-2"
              style={{ borderColor: checked ? brand.accent : white.w40 }}
              aria-hidden
            >
              {checked && <span className="h-2 w-2 rounded-full" style={{ backgroundColor: brand.accent }} />}
            </span>
            <span className="text-sm" style={{ color: white.w80 }}>
              {opt.label}
            </span>
          </button>
        );
      })}
    </div>
  );
}
