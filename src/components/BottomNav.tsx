/**
 * BottomNav — the four-tab bottom navigation, the canonical set on all three
 * clients: Profile · Connect · Limit · Settings (iOS ContentView, Android
 * BirdoNavGraph). Windows had three and no usage view (P1-parity-009).
 * w06 glass bg + 1px soft top divider; active tab = emerald icon+label, inactive w60.
 */
import { User, Power, Gauge, Settings as SettingsIcon, type LucideIcon } from 'lucide-react';
import { useShallow } from 'zustand/react/shallow';
import { useAppStore, type TabId } from '@/store/app-store';
import { brand, white } from '@/lib/birdo-theme';

const TABS: { id: TabId; label: string; icon: LucideIcon }[] = [
  { id: 'profile', label: 'Profile', icon: User },
  { id: 'home', label: 'Connect', icon: Power },
  { id: 'limit', label: 'Limit', icon: Gauge },
  { id: 'settings', label: 'Settings', icon: SettingsIcon },
];

export function BottomNav() {
  const { tab, setTab } = useAppStore(
    useShallow((s) => ({ tab: s.tab, setTab: s.setTab }))
  );

  return (
    <nav
      className="shrink-0 border-t bg-w06"
      style={{ borderColor: 'var(--birdo-hairline-soft)' }}
      aria-label="Main navigation"
    >
      <div className="flex items-stretch" role="tablist" aria-label="App sections">
        {TABS.map(({ id, label, icon: Icon }, index) => {
          const active = tab === id;
          return (
            <button
              key={id}
              role="tab"
              aria-selected={active}
              tabIndex={active ? 0 : -1}
              onClick={() => setTab(id)}
              onKeyDown={(e) => {
                if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
                  e.preventDefault();
                  const dir = e.key === 'ArrowRight' ? 1 : -1;
                  const next = (index + dir + TABS.length) % TABS.length;
                  setTab(TABS[next].id);
                  // Roving focus follows the selection, as the tab pattern expects.
                  const buttons = e.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
                  buttons?.[next]?.focus();
                }
              }}
              className="birdo-tab flex flex-1 flex-col items-center justify-center gap-1 py-2.5 transition-colors"
              style={{ color: active ? brand.accent : white.w60 }}
            >
              <Icon size={22} strokeWidth={active ? 2.4 : 2} aria-hidden />
              <span className="text-[10px] font-medium tracking-wider">{label}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}
