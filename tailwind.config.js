/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#faf5ff',
          100: '#f3e8ff',
          200: '#e9d5ff',
          300: '#d8b4fe',
          400: '#c084fc',
          500: '#a855f7',
          600: '#9333ea',
          700: '#7c3aed',
          800: '#6b21a8',
          900: '#581c87',
          950: '#3b0764',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      // ── Birdo design tokens exposed as utilities (mirror mobile) ──────────
      // Backed by CSS vars in globals.css so `.light` (dark-slate) overrides work.
      backgroundColor: {
        'birdo-black': 'var(--birdo-black)',
        'birdo-s0': 'var(--birdo-s0)',
        'birdo-s1': 'var(--birdo-s1)',
        'birdo-s2': 'var(--birdo-s2)',
        'birdo-s3': 'var(--birdo-s3)',
        'birdo-purple-bg': 'var(--birdo-purple-bg)',
        'birdo-green-bg': 'var(--birdo-green-bg)',
        'birdo-red-bg': 'var(--birdo-red-bg)',
        'birdo-primary': 'var(--birdo-primary)',
        w03: 'var(--w03)',
        w04: 'var(--w04)',
        w05: 'var(--w05)',
        w06: 'var(--w06)',
        w10: 'var(--w10)',
      },
      textColor: {
        w100: 'var(--w100)',
        w80: 'var(--w80)',
        w60: 'var(--w60)',
        w40: 'var(--w40)',
        w20: 'var(--w20)',
        'birdo-purple': 'var(--birdo-purple)',
        'birdo-purple-soft': 'var(--birdo-purple-soft)',
        'birdo-green': 'var(--birdo-green)',
        'birdo-on-primary': 'var(--birdo-on-primary)',
      },
      borderColor: {
        'birdo-hairline': 'var(--birdo-hairline)',
        'birdo-hairline-soft': 'var(--birdo-hairline-soft)',
      },
      borderRadius: {
        'birdo-xs': '6px',
        'birdo-sm': '10px',
        'birdo-md': '14px',
        'birdo-lg': '18px',
        'birdo-card': '16px',
        'birdo-sub': '12px',
        'birdo-xl': '24px',
      },
      maxWidth: {
        phone: '420px',
      },
      minWidth: {
        phone: '360px',
      },
      animation: {
        'spin-slow': 'spin 3s linear infinite',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'birdo-pulse-ring': 'birdo-pulse-ring 1100ms linear infinite',
      },
      keyframes: {
        'birdo-pulse-ring': {
          '0%': { transform: 'scale(1)', opacity: '0.6' },
          '100%': { transform: 'scale(2)', opacity: '0' },
        },
      },
    },
  },
  plugins: [],
};
