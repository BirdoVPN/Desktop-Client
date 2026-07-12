/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#ecfdf5',
          100: '#d1fae5',
          200: '#a7f3d0',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          600: '#059669',
          700: '#047857',
          800: '#065f46',
          900: '#064e3b',
          950: '#022c22',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      // ── Birdo design tokens exposed as utilities ──────────────────────────
      // Backed by CSS vars in globals.css so `.light` (dark-slate) overrides work.
      backgroundColor: {
        'birdo-black': 'var(--birdo-black)',
        'birdo-s0': 'var(--birdo-s0)',
        'birdo-s1': 'var(--birdo-s1)',
        'birdo-s2': 'var(--birdo-s2)',
        'birdo-s3': 'var(--birdo-s3)',
        'birdo-accent-bg': 'var(--birdo-accent-bg)',
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
        'birdo-accent': 'var(--birdo-accent)',
        'birdo-accent-soft': 'var(--birdo-accent-soft)',
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
        // Finite: three rings, then the dot settles. See PulsingDot in Badge.tsx —
        // an infinite ring keeps the compositor awake for the whole connected
        // session. `forwards` holds the final (invisible) ring frame.
        'birdo-pulse-ring-3x': 'birdo-pulse-ring 1100ms linear 3 forwards',
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
