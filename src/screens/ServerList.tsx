/**
 * ServerListScreen — mobile-parity screen (stub; full UI built in the screens stage).
 * Placeholder so the shell + router compile and route correctly in commit 3.
 */
import { useAppStore } from '@/store/app-store';

export function ServerListScreen() {
  const popRoute = useAppStore((s) => s.popRoute);
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 bg-birdo-s0 p-8 text-center">
      <p className="text-[16px] font-semibold text-w100">ServerListScreen</p>
      <p className="text-[13px] text-w60">Coming together in the screens build stage.</p>
      <button onClick={popRoute} className="text-[13px] text-birdo-purple">Back</button>
    </div>
  );
}
