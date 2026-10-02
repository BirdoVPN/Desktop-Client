/**
 * Dashboard — the Connect tab, mirroring iOS HomeView / Android HomeScreen.
 *
 * Layout:
 *  - Full-bleed WorldGlobe background (rotates only while idle)
 *  - HomeTopBar: Multi-Hop toggle (left), identity + Sign out (right)
 *  - StatusArea: the pill and its chips (kill switch, Stealth)
 *  - Bottom panel: stats (connected) → banners → server selector (single, or
 *    the Entry/Exit pair when Multi-Hop is armed) → Connect button
 *  - Server picker is a modal bottom sheet
 *
 * A VIEW over the store, nothing more (W2-001, W2-038). The status sync, tray
 * actions, notifications, auto-connect, deep links and data loading live in
 * the session controller (`session/controller.tsx`), which App mounts once for
 * the whole session — this component unmounts on every tab switch, and while
 * it owned them, none of them ran off the Connect tab.
 */
import { useState } from 'react';
import { useShallow } from 'zustand/react/shallow';
import { Globe } from 'lucide-react';
import { AnimatePresence, motion } from 'framer-motion';
import { CompactConnectButton, ServerSelectorSheet, WorldGlobe } from './birdo';
import { HomeTopBar } from './home/HomeTopBar';
import { StatusArea } from './home/StatusArea';
import { StatsRow } from './home/StatsRow';
import { HomeBanners } from './home/HomeBanners';
import { MultiHopServerPair, ServerSelectorCard } from './home/ServerCards';
import { SignOutDialog } from './home/SignOutDialog';
import { hairline, motion as motionTokens, white } from '@/lib/birdo-theme';
import { connectCta } from '@/lib/vpn-display';
import { planRank, titleCasePlan } from '@/lib/plan';
import type { ErrorAction } from '@/lib/errors';
import { pickBestServer } from '@/lib/ipc';
import { useAppStore, type Server } from '@/store/app-store';
import { selectDisplayState, selectTunnelActive } from '@/store/selectors';
import {
  connectPreferred,
  disconnectVpn,
  findLiveServer,
  resolveConnectTarget,
  switchToServer,
} from '@/session/vpn-actions';
import { persistSettings } from '@/session/settings-persist';
import { loadServers, loadSubscription } from '@/session/session-data';
import { resolveAnonymousAccount } from '@/utils/helpers';

/** Which hop the multi-hop server sheet is currently picking. */
type MultiHopTarget = 'entry' | 'exit';

export function Dashboard() {
  const [showServerSheet, setShowServerSheet] = useState(false);
  const [multiHopPickerTarget, setMultiHopPickerTarget] = useState<MultiHopTarget | null>(null);
  const [showSignOut, setShowSignOut] = useState(false);

  const {
    display,
    tunnelActive,
    blocking,
    servers,
    serversStatus,
    serverPings,
    favoriteServers,
    currentServer,
    target,
    liveServer,
    liveMultiHop,
    userEmail,
    anonymous,
    plan,
    lastServerId,
    multiHopEnabled,
    entryId,
    exitId,
    pendingAction,
    toggleFavorite,
  } = useAppStore(
    useShallow((s) => ({
      display: selectDisplayState(s),
      tunnelActive: selectTunnelActive(s),
      blocking: s.killSwitchBlocking,
      servers: s.servers,
      serversStatus: s.serversStatus,
      serverPings: s.serverPings,
      favoriteServers: s.favoriteServers,
      currentServer: s.currentServer,
      target: resolveConnectTarget(s),
      liveServer: s.liveMultiHop
        ? s.servers.find((srv) => srv.id === s.liveMultiHop?.exitId) ?? null
        : findLiveServer(s.servers, s.liveServerId, s.liveServerName),
      liveMultiHop: s.liveMultiHop,
      userEmail: s.account.email ?? s.userEmail,
      anonymous: resolveAnonymousAccount(s.account, s.account.email ?? s.userEmail).isAnon,
      plan: s.account.plan,
      lastServerId: s.lastServerId,
      multiHopEnabled: s.settings.multiHopEnabled,
      entryId: s.settings.multiHopEntryNodeId,
      exitId: s.settings.multiHopExitNodeId,
      pendingAction: s.pendingAction,
      toggleFavorite: s.toggleFavorite,
    })),
  );

  const isConnected = display === 'connected';
  const rank = planRank(plan);
  // null = the plan is not known yet: no lock, no upsell (W2-011).
  const multiHopUnlocked = rank === null ? null : rank >= 2;

  // ── Multi-Hop route ─────────────────────────────────────────────────
  // While a session is up (or coming up) the pair shows the LIVE route and
  // cannot be edited: editing it used to relabel the cards while traffic kept
  // taking the old route (W2-010).
  const showPair = multiHopEnabled || liveMultiHop !== null;
  const byId = (id: string | null | undefined) => servers.find((s) => s.id === id) ?? null;
  const entryServer = byId(liveMultiHop?.entryId ?? entryId);
  const exitServer = byId(liveMultiHop?.exitId ?? exitId);
  const sameServer = !!(entryServer && exitServer && entryServer.id === exitServer.id);
  const multiHopReady = !!(multiHopEnabled && entryServer && exitServer && !sameServer);

  const cta = connectCta(display, { blocking, multiHopArmed: showPair, multiHopReady });
  const midTransition = display === 'connecting' || display === 'switching' || display === 'disconnecting';

  const notice: ReturnType<typeof useAppStore.getState>['showNotice'] = (n) =>
    useAppStore.getState().showNotice(n);

  const handleToggleMultiHop = () => {
    if (multiHopUnlocked === null) {
      notice({ text: 'Checking your plan…', tone: 'info' });
      void loadSubscription(true);
      return;
    }
    if (!multiHopUnlocked) {
      notice({ text: 'Multi-Hop is a Sovereign feature. Upgrade to enable.', tone: 'info' });
      useAppStore.getState().pushRoute('pricing');
      return;
    }
    if (tunnelActive) {
      notice({ text: 'Disconnect to change your route.', tone: 'info' });
      return;
    }
    // Disarming clears the route so the single selector returns clean.
    void persistSettings(
      multiHopEnabled
        ? { multiHopEnabled: false, multiHopEntryNodeId: null, multiHopExitNodeId: null }
        : { multiHopEnabled: true },
    );
  };

  const upsellLocked = (server: Server) => {
    const which = server.minPlan ? `the ${titleCasePlan(server.minPlan)} plan` : 'a higher plan';
    notice({
      text: `This server requires ${which}. Upgrade to unlock.`,
      tone: 'info',
      actionLabel: 'View plans',
      onAction: () => useAppStore.getState().pushRoute('pricing'),
    });
  };

  const handlePickServer = (server: Server) => {
    const s = useAppStore.getState();
    const d = selectDisplayState(s);
    // On a live single-hop session, picking another node is a real switch.
    if ((d === 'connected' || d === 'reconnecting') && !s.liveMultiHop && liveServer?.id !== server.id) {
      void switchToServer(server);
      return;
    }
    s.setCurrentServer(server);
  };

  const handlePickMultiHop = (server: Server) => {
    if (multiHopPickerTarget === 'entry') void persistSettings({ multiHopEntryNodeId: server.id });
    else if (multiHopPickerTarget === 'exit') void persistSettings({ multiHopExitNodeId: server.id });
    setMultiHopPickerTarget(null);
  };

  const handleBannerAction = (action: ErrorAction) => {
    const s = useAppStore.getState();
    switch (action) {
      case 'view_plans':
        s.pushRoute('pricing');
        break;
      case 'open_settings':
        s.setTab('settings');
        break;
      case 'choose_server':
        setShowServerSheet(true);
        break;
      case 'connect':
      case 'retry':
        void connectPreferred();
        break;
      default:
        break;
    }
  };

  const handleCta = () => {
    if (cta.action === 'disconnect') void disconnectVpn();
    else if (cta.action === 'connect') void connectPreferred();
  };

  // The automatic pick, not a server the user chose or last used (W2-028).
  const isFastest =
    !!target && !isConnected && target.id !== currentServer?.id && target.id !== lastServerId;
  const cardServer = isConnected && liveServer ? liveServer : target;
  const serverIp = liveServer?.ipAddress ?? liveServer?.hostname ?? null;
  const sheetOpen = showServerSheet || multiHopPickerTarget !== null;

  return (
    // Transparent root so the App-level PixelCanvas backdrop shows through.
    <div className="relative h-full overflow-hidden">
      {/* Globe background — hidden while a sheet is open to avoid flicker */}
      {!sheetOpen && (
        <WorldGlobe
          servers={servers}
          selectedServerId={(isConnected ? liveServer : target)?.id ?? null}
          isConnected={isConnected}
          // Rotate only while idle. Connected is the steady state a VPN client
          // sits in for days; an infinite transform there means the compositor
          // never idles, for a decoration nobody is watching.
          autoRotate={!isConnected}
        />
      )}

      <HomeTopBar
        userEmail={userEmail}
        anonymous={anonymous}
        multiHopArmed={multiHopEnabled}
        multiHopUnlocked={multiHopUnlocked}
        multiHopLocked={tunnelActive}
        onToggleMultiHop={handleToggleMultiHop}
        onSignOut={() => setShowSignOut(true)}
      />

      <StatusArea />

      <div className="pointer-events-none absolute inset-0 flex flex-col">
        <div className="flex-1" />
        <div
          className="pointer-events-auto rounded-t-birdo-xl px-5 pt-4 pb-4"
          style={{
            // Near-opaque fill instead of backdrop-filter blur — the blur
            // shader smears the repainting globe into vertical streaks on
            // WebView2 GPUs.
            backgroundColor: 'rgba(11,11,16,0.97)',
            borderTop: `1px solid ${hairline.soft}`,
          }}
        >
          <AnimatePresence>
            {isConnected && (
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: motionTokens.standard, delay: 0.08 }}
              >
                <StatsRow />
                {/* The node's address, labelled as such: this is where the
                    tunnel terminates (the exit, for Multi-Hop), not a
                    measured public IP (W2-031). */}
                {serverIp && (
                  <div
                    className="mt-2 flex items-center justify-center gap-1.5 text-xs"
                    style={{ color: white.w60 }}
                  >
                    <Globe size={12} aria-hidden />
                    <span>Server IP</span>
                    <span className="font-mono" style={{ color: white.w80 }}>
                      {serverIp}
                    </span>
                  </div>
                )}
                <div className="h-2.5" />
              </motion.div>
            )}
          </AnimatePresence>

          <HomeBanners onAction={handleBannerAction} />

          {showPair ? (
            <MultiHopServerPair
              entry={entryServer}
              exit={exitServer}
              sameServer={sameServer}
              disabled={midTransition}
              routeLocked={tunnelActive}
              onPickEntry={() => setMultiHopPickerTarget('entry')}
              onPickExit={() => setMultiHopPickerTarget('exit')}
            />
          ) : (
            <ServerSelectorCard
              server={cardServer}
              isFastest={isFastest}
              serversStatus={serversStatus}
              switching={pendingAction === 'switching'}
              disabled={midTransition}
              onClick={() => {
                // Always opens: on an empty or failed list the sheet explains
                // and offers Retry, instead of a card that did nothing (W2-014).
                if (serversStatus === 'error') void loadServers(true);
                setShowServerSheet(true);
              }}
            />
          )}
          <div className="h-2.5" />

          <CompactConnectButton
            state={cta.look}
            label={cta.label}
            busy={cta.busy}
            disabled={cta.action === 'none'}
            onClick={handleCta}
          />
        </div>
      </div>

      <ServerSelectorSheet
        open={showServerSheet}
        servers={servers}
        status={serversStatus}
        pings={serverPings}
        selectedServerId={(isConnected ? liveServer : currentServer)?.id ?? null}
        fastestServer={pickBestServer(servers)}
        favoriteServers={favoriteServers}
        onSelect={handlePickServer}
        onSelectLocked={upsellLocked}
        onToggleFavorite={toggleFavorite}
        onRetry={() => void loadServers(true)}
        onDismiss={() => setShowServerSheet(false)}
      />

      <ServerSelectorSheet
        open={multiHopPickerTarget !== null}
        title={multiHopPickerTarget === 'entry' ? 'Choose entry server' : 'Choose exit server'}
        servers={servers}
        status={serversStatus}
        pings={serverPings}
        selectedServerId={multiHopPickerTarget === 'entry' ? entryId : exitId}
        favoriteServers={favoriteServers}
        onSelect={handlePickMultiHop}
        onSelectLocked={upsellLocked}
        onToggleFavorite={toggleFavorite}
        onRetry={() => void loadServers(true)}
        onDismiss={() => setMultiHopPickerTarget(null)}
      />

      <SignOutDialog
        open={showSignOut}
        stillConnected={tunnelActive}
        onClose={() => setShowSignOut(false)}
      />
    </div>
  );
}
