// ESLint v9 flat config for BirdoVPN desktop.
// Covers the React/TypeScript frontend under src/. Rust lints are handled by
// `cargo clippy` in CI.

import js from '@eslint/js'
import globals from 'globals'
import tsParser from '@typescript-eslint/parser'
import tsPlugin from '@typescript-eslint/eslint-plugin'
import reactPlugin from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'

export default [
  // Global ignores — must be a lone object to apply repo-wide.
  {
    ignores: [
      'dist/**',
      'src-tauri/target/**',
      'src-tauri/gen/**',
      'node_modules/**',
      '*.config.js',
      '*.config.cjs',
      '*.config.mjs',
      '*.config.ts',
      'coverage/**',
      'src/__mocks__/**',
    ],
  },

  js.configs.recommended,

  // TypeScript / React sources.
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
        ecmaFeatures: { jsx: true },
      },
      globals: {
        ...globals.browser,
        ...globals.es2022,
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
      react: reactPlugin,
      'react-hooks': reactHooks,
    },
    settings: {
      react: { version: '18.3' },
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      ...reactPlugin.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,

      // TypeScript handles undefined-symbol detection better than ESLint.
      // Disabling `no-undef` avoids duplicate diagnostics for TS/JSX symbols.
      'no-undef': 'off',

      // React 17+ new JSX transform — `import React` is not required.
      'react/react-in-jsx-scope': 'off',
      'react/jsx-uses-react': 'off',
      // Prop-types disabled in favour of TypeScript.
      'react/prop-types': 'off',
      // Noisy for copy — apostrophes are rendered correctly via React's text escape.
      'react/no-unescaped-entities': 'off',

      // Project-specific tightening.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-non-null-assertion': 'warn',
      'no-console': ['warn', { allow: ['warn', 'error', 'info'] }],

      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
    },
  },

  // Test files: relax a few rules and add test globals.
  {
    files: [
      'src/**/*.test.{ts,tsx}',
      'src/**/__tests__/**/*.{ts,tsx}',
      'src/test-setup.ts',
    ],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.es2022,
        describe: 'readonly',
        it: 'readonly',
        test: 'readonly',
        expect: 'readonly',
        beforeAll: 'readonly',
        beforeEach: 'readonly',
        afterAll: 'readonly',
        afterEach: 'readonly',
        vi: 'readonly',
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      'no-console': 'off',
    },
  },
]

