import { invoke } from '@tauri-apps/api/core';
import { useAppStore } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { motion } from 'framer-motion';
import { Power } from 'lucide-react';

export function ConnectionButton() {
  const {
    connectionState,
    currentServer,
    servers,
    settings,
    setConnectionState,
    setCurrentServer,
    setVpnIp,
    setErrorMessage,
  } = useAppStore(
    useShallow((s) => ({
      connectionState: s.connectionState,
      currentServer: s.currentServer,
      servers: s.servers,
      settings: s.settings,
      setConnectionState: s.setConnectionState,
      setCurrentServer: s.setCurrentServer,
      setVpnIp: s.setVpnIp,
      setErrorMessage: s.setErrorMessage,
    }))
  );

  const isConnected = connectionState === 'connected';
  const isConnecting =
    connectionState === 'connecting' || connectionState === 'disconnecting'
    || connectionState === 'reconnecting' || connectionState === 'rekeying';

  const handleToggle = async () => {
    if (isConnecting) return;

    if (isConnected) {
      // Disconnect
      setConnectionState('disconnecting');
      setErrorMessage(null);
      try {
        await invoke('disconnect_vpn');
        setConnectionState('disconnected');
        setCurrentServer(null);
        setVpnIp(null);
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        setErrorMessage(msg);
        setConnectionState('error');
      }
    } else {
      // Multi-hop mode: use entry/exit node IDs from settings
      if (settings.multiHopEnabled && settings.multiHopEntryNodeId && settings.multiHopExitNodeId) {
        const entryServer = servers.find((s) => s.id === settings.multiHopEntryNodeId);
        setConnectionState('connecting');
        setCurrentServer(entryServer || null);
        setErrorMessage(null);

        try {
          await invoke<boolean>('connect_multi_hop', {
            entryNodeId: settings.multiHopEntryNodeId,
            exitNodeId: settings.multiHopExitNodeId,
          });
          setConnectionState('connected');
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error);
          setErrorMessage(msg);
          setConnectionState('error');
          setCurrentServer(null);
          setVpnIp(null);
        }
        return;
      }

      // Standard connect - use current server or best available
      const targetServer = currentServer || servers.find((s) => s.isOnline);

      if (!targetServer) return;

      setConnectionState('connecting');
      setCurrentServer(targetServer);
      setErrorMessage(null);

      try {
        await invoke<boolean>('connect_vpn', { serverId: targetServer.id });
        setConnectionState('connected');
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        setErrorMessage(msg);
        setConnectionState('error');
        setCurrentServer(null);
        setVpnIp(null);
      }
    }
  };

  return (
    <div className="relative">
      {/* Pulse effect when connected */}
      {isConnected && (
        <>
          <motion.div
            className="absolute inset-0 rounded-full bg-green-500/30"
            initial={{ scale: 1, opacity: 0.5 }}
            animate={{ scale: 1.5, opacity: 0 }}
            transition={{ duration: 1.5, repeat: Infinity }}
          />
          <motion.div
            className="absolute inset-0 rounded-full bg-green-500/20"
            initial={{ scale: 1, opacity: 0.3 }}
            animate={{ scale: 1.3, opacity: 0 }}
            transition={{ duration: 1.5, repeat: Infinity, delay: 0.3 }}
          />
        </>
      )}

      <motion.button
        onClick={handleToggle}
        disabled={isConnecting}
        aria-label={isConnecting ? 'Connecting to VPN' : isConnected ? 'Disconnect from VPN' : 'Connect to VPN'}
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        className={`relative flex h-32 w-32 items-center justify-center rounded-full transition-all focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-black ${
          isConnected
            ? 'bg-green-500 shadow-lg shadow-green-500/30'
            : isConnecting
            ? 'bg-yellow-500 shadow-lg shadow-yellow-500/30'
            : 'bg-white/10 border border-white/20 hover:bg-white hover:text-black hover:shadow-lg hover:shadow-white/20'
        } disabled:cursor-not-allowed`}
      >
        {isConnecting ? (
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-white/30 border-t-white" />
        ) : (
          <Power
            size={48}
            className={`transition ${isConnected ? 'text-white' : isConnecting ? 'text-white' : 'text-white/60 group-hover:text-black'}`}
          />
        )}
      </motion.button>
    </div>
  );
}
