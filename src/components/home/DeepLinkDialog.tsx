/**
 * The confirmation a birdo://connect link must pass. A link is third-party
 * input — any page, chat message or document can hand the user one — so it
 * never moves the egress (or forces a reconnect that mints fresh keys) without
 * an explicit Accept naming the destination. Rendered by AppShell, so it shows
 * on whatever tab is open; staged by the session controller.
 */
import { Globe } from 'lucide-react';
import { useShallow } from 'zustand/react/shallow';
import { BirdoButton, BirdoDialog } from '@/components/birdo';
import { status, white } from '@/lib/birdo-theme';
import { acceptDeepLink } from '@/session/vpn-actions';
import { useAppStore } from '@/store/app-store';
import { selectDisplayState } from '@/store/selectors';
import { countryCodeToFlag } from '@/utils/helpers';

export function DeepLinkDialog() {
  const { target, onTunnel, setDeepLinkConfirm } = useAppStore(
    useShallow((s) => {
      const d = selectDisplayState(s);
      return {
        target: s.deepLinkConfirm,
        onTunnel: d === 'connected' || d === 'reconnecting',
        setDeepLinkConfirm: s.setDeepLinkConfirm,
      };
    }),
  );
  const where = target
    ? `${target.countryCode ? `${countryCodeToFlag(target.countryCode)} ` : ''}${
        [target.city, target.country].filter(Boolean).join(', ') || target.name
      }`
    : '';

  return (
    <BirdoDialog
      open={target !== null}
      onClose={() => setDeepLinkConfirm(null)}
      title={onTunnel ? 'Switch server via link?' : 'Connect via link?'}
      icon={Globe}
      iconColor={status.yellowLight}
    >
      <p className="text-[13px]" style={{ color: white.w60 }}>
        A link asks to route your traffic through{' '}
        <span className="font-medium" style={{ color: white.w100 }}>
          {where}
        </span>
        .{' '}
        {onTunnel
          ? 'Your current connection will be replaced. Only accept if you trust where this link came from.'
          : 'Only accept if you trust where this link came from.'}
      </p>
      <div className="flex gap-2.5">
        <BirdoButton text="Cancel" variant="secondary" fullWidth onClick={() => setDeepLinkConfirm(null)} />
        <BirdoButton
          text={onTunnel ? 'Switch' : 'Connect'}
          variant="primary"
          fullWidth
          onClick={() => {
            if (target) void acceptDeepLink(target);
          }}
        />
      </div>
    </BirdoDialog>
  );
}
