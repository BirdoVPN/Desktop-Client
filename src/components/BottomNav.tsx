/**
 * BottomNav — 3-tab bottom navigation bar.
 * Mirrors mobile's BirdoNavGraph.kt:150-204 (Profile / Connect / Settings).
 * w06 glass bg + 1px soft top divider; active tab = purple icon+label, inactive w60.
 */
import { User, Power, Settings as SettingsIcon, type LucideIcon } from 'lucide-react';
import { useShallow } from 'zustand/react/shallow';
import { useAppStore, type TabId } from '@/store/app-store';
import { brand, white } from '@/lib/birdo-theme';

const TABS: { id: TabId; label: string; icon: LucideIcon }[] = [
  { id: 'profile', label: 'Profile', icon: User },
  { id: 'home', label: 'Connect', icon: Power },
  { id: 'settings', label: 'Settings', icon: SettingsIcon },
];

export function BottomNav() {
  const { tab, setTab } = useAppStore(
    useShallow((s) => ({ tab: s.tab, setTab: s.setTab }))
  );

  return (
    <nav
      className="flex shrink-0 items-stretch border-t bg-w06"
      style={{ borderColor: 'var(--birdo-hairline-soft)' }}
      role="tablist"
      aria-label="Main navigation"
    >
      {TABS.map(({ id, label, icon: Icon }) => {
        const active = tab === id;
        return (
          <button
            key={id}
            role="tab"
            aria-selected={active}
            onClick={() => setTab(id)}
            className="flex flex-1 flex-col items-center justify-center gap-1 py-2.5 transition-colors"
            style={{ color: active ? brand.purple : white.w60 }}
          >
            <Icon size={22} strokeWidth={active ? 2.4 : 2} />
            <span className="text-[10px] font-medium tracking-[0.05em]">{label}</span>
          </button>
        );
      })}
    </nav>
  );
}
