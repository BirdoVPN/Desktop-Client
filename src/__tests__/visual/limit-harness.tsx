/**
 * Visual harness for the Limit tab (owner 2026-10-21, UI parity with mobile):
 * the real TitleBar, <Limit /> and <BottomNav /> over the app's PixelCanvas in
 * a 380-wide window (open it at 380 x 640, the app's size), with the Tauri
 * bridge faked (tauri-bridge-mock.ts), so
 * the tab can be looked at and screenshotted in a plain browser:
 *
 *   npx vite --port 5199 --strictPort --host 127.0.0.1
 *   http://127.0.0.1:5199/src/__tests__/visual/limit-harness.html?s=warn
 *
 * Scenarios are tauri-bridge-mock.ts's SCENARIOS plus 'loading' and 'error'.
 * Not in the app bundle (vite build reads index.html only), not a vitest file.
 */
import { scenario } from './tauri-bridge-mock';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BottomNav } from '@/components/BottomNav';
import { PixelCanvas } from '@/components/PixelCanvas';
import { TitleBar } from '@/components/TitleBar';
import { Limit } from '@/screens/Limit';
import { useAppStore } from '@/store/app-store';
import '@/styles/globals.css';

const st = useAppStore.getState();
useAppStore.setState({
  isAuthenticated: true,
  tab: 'limit',
  account: { ...st.account, plan: scenario === 'unlimited' ? 'SOVEREIGN' : 'RECON' },
});

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <StrictMode>
      {/* 380 wide like the window; as tall as the browser, so a taller
          browser shows the whole tab without scrolling. */}
      <div className="relative flex h-screen flex-col overflow-hidden bg-birdo-black" style={{ width: 380 }}>
        <PixelCanvas />
        <TitleBar />
        <div className="relative z-10 flex min-h-0 flex-1 flex-col overflow-hidden">
          <div className="min-h-0 flex-1">
            <Limit />
          </div>
          <BottomNav />
        </div>
      </div>
    </StrictMode>,
  );
}
