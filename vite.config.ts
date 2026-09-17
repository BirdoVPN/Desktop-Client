/// <reference types="vitest" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      // import.meta.dirname, not __dirname: vite 8 warns that __dirname is
      // unsupported by the native config loader it plans to make default.
      // Node >= 20.11 (CI and release use 22).
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  // Prevent vite from obscuring rust errors
  clearScreen: false,
  // Tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // Ignore watching Tauri folder
      ignored: ['**/src-tauri/**'],
    },
  },
  // Env variables
  envPrefix: ['VITE_', 'TAURI_'],
  build: {
    // Tauri supports es2021
    target: process.env.TAURI_PLATFORM === 'windows' ? 'chrome105' : 'safari13',
    // Don't minify for debug builds.
    //
    // 'oxc', not 'esbuild': vite 8 no longer depends on esbuild at all (it is an
    // optional peer now). With minify: 'esbuild' the shipped dist still
    // registers vite:esbuild-transpile, whose renderChunk does import("esbuild")
    // and throws "Failed to load `transformWithEsbuild` ... requires esbuild to
    // be installed separately". No CI job runs `vite build` — only release.yml's
    // `npx tauri build` does — so that would have surfaced as a red RELEASE,
    // not a red PR. Oxc is vite 8's own default minifier.
    minify: !process.env.TAURI_DEBUG ? 'oxc' : false,
    // Produce sourcemaps for debug builds
    sourcemap: !!process.env.TAURI_DEBUG,
    rollupOptions: {
      output: {
        // One 562 kB chunk was over Vite's 500 kB advisory. Vendor code that
        // changes only on a dependency bump is split from app code that changes
        // every release, so an app update re-parses ~200 kB instead of the lot
        // and the vendor chunks stay cached. Raising chunkSizeWarningLimit
        // would have silenced the advisory without changing anything.
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return undefined;
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) return 'vendor-react';
          if (id.includes('framer-motion') || id.includes('motion-dom') || id.includes('motion-utils')) return 'vendor-motion';
          if (id.includes('lucide-react')) return 'vendor-icons';
          return 'vendor';
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
  },
});
