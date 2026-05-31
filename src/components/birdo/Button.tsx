/**
 * BirdoButton — unified button with 5 variants matching mobile's `BirdoButton.kt`.
 *   Primary   — solid white on dark
 *   Brand     — purple gradient (hero CTA)
 *   Secondary — bordered glass
 *   Ghost     — text only
 *   Danger    — red
 */
import { motion } from 'framer-motion';
import type { LucideIcon } from 'lucide-react';
import { status, white, gradient, motion as motionTokens } from '@/lib/birdo-theme';

export type BirdoButtonVariant = 'primary' | 'brand' | 'secondary' | 'ghost' | 'danger';
export type BirdoButtonSize = 'small' | 'medium' | 'large';

export interface BirdoButtonProps {
  text: string;
  onClick: () => void;
  variant?: BirdoButtonVariant;
  size?: BirdoButtonSize;
  icon?: LucideIcon;
  isLoading?: boolean;
  disabled?: boolean;
  fullWidth?: boolean;
  className?: string;
  type?: 'button' | 'submit' | 'reset';
  ariaLabel?: string;
}

const SIZE_STYLES: Record<BirdoButtonSize, { height: string; fontSize: string; padX: string }> = {
  small:  { height: '40px', fontSize: '13px', padX: '14px' },
  medium: { height: '48px', fontSize: '14px', padX: '18px' },
  large:  { height: '56px', fontSize: '16px', padX: '18px' },
};

export function BirdoButton({
  text,
  onClick,
  variant = 'primary',
  size = 'medium',
  icon: Icon,
  isLoading = false,
  disabled = false,
  fullWidth = false,
  className = '',
  type = 'button',
  ariaLabel,
}: BirdoButtonProps) {
  const sz = SIZE_STYLES[size];
  const isInactive = disabled || isLoading;

  let bg: string;
  let fg: string;
  let border = 'none';
  let backgroundImage: string | undefined;

  switch (variant) {
    case 'brand':
      bg = 'transparent';
      fg = '#FFFFFF';
      backgroundImage = gradient.primary;
      break;
    case 'secondary':
      bg = white.w06;
      fg = white.w100;
      border = `1px solid transparent`;
      backgroundImage = `linear-gradient(${white.w06}, ${white.w06}) padding-box, ${gradient.glassStroke} border-box`;
      break;
    case 'ghost':
      bg = 'transparent';
      fg = white.w80;
      break;
    case 'danger':
      bg = 'rgba(248,113,113,0.12)';
      fg = status.red;
      break;
    case 'primary':
    default:
      bg = '#FFFFFF';
      fg = '#000000';
      break;
  }

  if (disabled) {
    bg = white.w10;
    fg = white.w40;
    backgroundImage = undefined;
  }

  return (
    <motion.button
      type={type}
      onClick={onClick}
      disabled={isInactive}
      aria-label={ariaLabel ?? text}
      whileTap={!isInactive ? { scale: 0.97 } : undefined}
      transition={{ duration: 0.12, ease: motionTokens.ease }}
      className={`relative flex items-center justify-center rounded-birdo-md font-semibold transition-opacity disabled:cursor-not-allowed ${
        fullWidth ? 'w-full' : ''
      } ${className}`}
      style={{
        height: sz.height,
        fontSize: sz.fontSize,
        paddingLeft: sz.padX,
        paddingRight: sz.padX,
        backgroundColor: bg,
        backgroundImage,
        color: fg,
        border,
        opacity: disabled ? 0.7 : 1,
      }}
    >
      {isLoading ? (
        <span
          className="mr-2.5 h-[18px] w-[18px] animate-spin rounded-full border-2 border-current border-t-transparent"
          aria-hidden
        />
      ) : Icon ? (
        <Icon size={18} className="mr-2" aria-hidden />
      ) : null}
      <span>{text}</span>
    </motion.button>
  );
}
