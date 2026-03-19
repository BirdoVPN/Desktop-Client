import { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { getVersion } from '@tauri-apps/api/app';
import { useAppStore, type MultiHopRoute } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { UpdateChecker } from './UpdateChecker';
import { isValidDnsAddress, isValidPort } from '@/utils/helpers';
import {
  Shield,
  Wifi,
  Bell,
  ExternalLink,
  Info,
  Globe,
  Split,
  Zap,
  Monitor,
  Server,
  ChevronRight,
  X,
  Plus,
  AlertTriangle,
  Network,
  Router,
  SlidersHorizontal,
  Layers,
  ArrowRightLeft,
  Trash2,
  Loader2,
  Eye,
  Lock,
  Sun,
  Moon,
  Laptop,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export function Settings() {
  const [appVersion, setAppVersion] = useState('');
  const [dnsInput, setDnsInput] = useState('');
  const [dnsError, setDnsError] = useState<string | null>(null);
  const [splitAppInput, setSplitAppInput] = useState('');
  const [killSwitchError, setKillSwitchError] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<string | null>(null);
  const [customPortInput, setCustomPortInput] = useState('');
  const [customMtuInput, setCustomMtuInput] = useState('');
  const [portFwdPort, setPortFwdPort] = useState('');
  const [portFwdProtocol, setPortFwdProtocol] = useState<'tcp' | 'udp'>('tcp');
  const [portFwdLoading, setPortFwdLoading] = useState(false);
  const [multiHopLoading, setMultiHopLoading] = useState(false);
  const [speedTestRunning, setSpeedTestRunning] = useState(false);
  const [speedTestResult, setSpeedTestResult] = useState<{
    downloadMbps: number;
    uploadMbps: number;
    latencyMs: number;
    jitterMs: number;
  } | null>(null);
  const saveDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
    };
  }, []);

  const { settings, updateSettings, servers, multiHopRoutes, setMultiHopRoutes, portForwards, setPortForwards, theme, setTheme, account } = useAppStore(
    useShallow((s) => ({
      settings: s.settings,
      updateSettings: s.updateSettings,
      servers: s.servers,
      multiHopRoutes: s.multiHopRoutes,
      setMultiHopRoutes: s.setMultiHopRoutes,
      portForwards: s.portForwards,
      setPortForwards: s.setPortForwards,
      theme: s.theme,
      setTheme: s.setTheme,
      account: s.account,
    }))
  );

  const planLevel = (plan: string | null | undefined): number => {
    switch (plan?.toUpperCase()) {
      case 'SOVEREIGN': return 2;
      case 'OPERATIVE': return 1;
      default: return 0;
    }
  };
  const userPlan = planLevel(account?.plan);
  const hasOperative = userPlan >= 1;
  const hasSovereign = userPlan >= 2;

  useEffect(() => {
    getVersion().then(setAppVersion).catch(() => setAppVersion('unknown'));
  }, []);

  // Initialize custom port/MTU inputs from settings
  useEffect(() => {
    if (settings.wireGuardPort && !['auto', '51820', '53'].includes(settings.wireGuardPort)) {
      setCustomPortInput(settings.wireGuardPort);
    }
    if (settings.wireGuardMtu > 0) {
      setCustomMtuInput(settings.wireGuardMtu.toString());
    }
  }, [settings.wireGuardPort, settings.wireGuardMtu]);

  // Persist settings to Rust backend whenever they change
  const saveSettingsToBackend = useCallback(
    async (newSettings: typeof settings) => {
      try {
        await invoke('save_settings', {
          settings: {
            autostart: newSettings.autostart,
            start_minimized: newSettings.startMinimized,
            killswitch_enabled: newSettings.killSwitchEnabled,
            notifications_enabled: newSettings.notifications,
            auto_connect: newSettings.autoConnect,
            preferred_server_id: newSettings.preferredServerId,
            split_tunneling_enabled: newSettings.splitTunnelingEnabled,
            split_tunnel_apps: newSettings.splitTunnelApps,
            custom_dns: newSettings.customDns,
            protocol: newSettings.protocol,
            local_network_sharing: newSettings.localNetworkSharing,
            wireguard_port: newSettings.wireGuardPort,
            wireguard_mtu: newSettings.wireGuardMtu,
            stealth_mode: newSettings.stealthMode,
            quantum_protection: newSettings.quantumProtection,
          },
        });
      } catch (err) {
        console.error('Failed to save settings:', err);
      }
    },
    []
  );

  const handleToggle = async (
    key: keyof typeof settings,
    value: boolean
  ) => {
    // Special handling for kill switch
    if (key === 'killSwitchEnabled') {
      try {
        setKillSwitchError(null);
        if (value) {
          await invoke('enable_killswitch');
        } else {
          await invoke('disable_killswitch');
        }
      } catch (err) {
        const msg = String(err);
        if (msg.toLowerCase().includes('administrator')) {
          setKillSwitchError(
            'Kill switch requires administrator privileges. Right-click the app and select "Run as administrator".'
          );
        } else if (msg.toLowerCase().includes('vpn is')) {
          setKillSwitchError(
            'Cannot disable kill switch while VPN is active. Disconnect first.'
          );
        } else {
          setKillSwitchError(msg);
        }
        return;
      }
    }

    // Special handling for autostart
    if (key === 'autostart') {
      try {
        await invoke('set_autostart', { enabled: value });
      } catch (err) {
        console.error('Failed to toggle autostart:', err);
        return;
      }
    }

    const next = { ...settings, [key]: value };
    updateSettings({ [key]: value });
    saveSettingsToBackend(next);
  };

  const isValidIp = (ip: string): boolean => {
    const result = isValidDnsAddress(ip);
    if (!result.valid && result.error) {
      setDnsError(result.error);
      return false;
    }
    return result.valid;
  };

  const addDns = () => {
    const ip = dnsInput.trim();
    if (!ip) return;
    if (!isValidIp(ip)) {
      return;
    }
    const current = settings.customDns || [];
    if (current.includes(ip)) {
      setDnsError('DNS server already added');
      return;
    }
    if (current.length >= 3) {
      setDnsError('Maximum 3 DNS servers allowed');
      return;
    }
    setDnsError(null);
    const next = [...current, ip];
    const updated = { ...settings, customDns: next };
    updateSettings({ customDns: next });
    saveSettingsToBackend(updated);
    setDnsInput('');
  };

  const removeDns = (ip: string) => {
    const next = (settings.customDns || []).filter((d) => d !== ip);
    const updated = { ...settings, customDns: next.length > 0 ? next : null };
    updateSettings({ customDns: next.length > 0 ? next : null });
    saveSettingsToBackend(updated);
  };

  const addSplitApp = () => {
    const app = splitAppInput.trim();
    if (!app) return;
    if (settings.splitTunnelApps.includes(app)) return;
    const next = [...settings.splitTunnelApps, app];
    const updated = { ...settings, splitTunnelApps: next };
    updateSettings({ splitTunnelApps: next });
    saveSettingsToBackend(updated);
    setSplitAppInput('');
  };

  const removeSplitApp = (app: string) => {
    const next = settings.splitTunnelApps.filter((a) => a !== app);
    const updated = { ...settings, splitTunnelApps: next };
    updateSettings({ splitTunnelApps: next });
    saveSettingsToBackend(updated);
  };

  return (
    <div className="h-full overflow-y-auto">
      <div className="p-4 space-y-5">

        {/* ── Connection Section ── */}
        <Section title="Connection">
          <SettingToggle
            icon={Shield}
            title="Kill Switch"
            description="Block all traffic if VPN disconnects"
            enabled={settings.killSwitchEnabled}
            onChange={(v) => handleToggle('killSwitchEnabled', v)}
          />
          {killSwitchError && (
            <motion.div
              className="flex items-start gap-2 rounded-lg border border-yellow-500/20 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-300"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
            >
              <AlertTriangle size={14} className="shrink-0 mt-0.5" />
              <span>{killSwitchError}</span>
            </motion.div>
          )}
          <SettingToggle
            icon={Wifi}
            title="Auto-Connect"
            description="Connect to VPN when app starts"
            enabled={settings.autoConnect}
            onChange={(v) => handleToggle('autoConnect', v)}
          />
          <SettingToggle
            icon={Bell}
            title="Notifications"
            description="Show connection status notifications"
            enabled={settings.notifications}
            onChange={(v) => handleToggle('notifications', v)}
          />
        </Section>

        {/* ── Startup Section ── */}
        <Section title="Startup">
          <SettingToggle
            icon={Zap}
            title="Launch at Login"
            description="Start Birdo VPN when your computer starts"
            enabled={settings.autostart}
            onChange={(v) => handleToggle('autostart', v)}
          />
          <SettingToggle
            icon={Monitor}
            title="Start Minimized"
            description="Start in system tray instead of full window"
            enabled={settings.startMinimized}
            onChange={(v) => handleToggle('startMinimized', v)}
          />
        </Section>

        {/* ── Appearance Section ── */}
        <Section title="Appearance">
          <div className="glass rounded-lg p-3">
            <div className="flex items-center gap-3 mb-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/10">
                <Sun size={18} className="text-white" />
              </div>
              <div>
                <p className="text-sm font-medium text-white">Theme</p>
                <p className="text-xs text-white/50">Choose dark or light mode</p>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2">
              {[
                { value: 'dark' as const, icon: Moon, label: 'Dark' },
                { value: 'light' as const, icon: Sun, label: 'Light' },
                { value: 'system' as const, icon: Laptop, label: 'System' },
              ].map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => setTheme(opt.value)}
                  className={`flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-xs font-medium transition ${
                    theme === opt.value
                      ? 'bg-white text-black'
                      : 'bg-white/5 text-white/60 hover:bg-white/10'
                  }`}
                >
                  <opt.icon size={14} />
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        </Section>

        {/* ── DNS Section ── */}
        <Section title="DNS">
          <SettingExpandable
            icon={Globe}
            title="Custom DNS Servers"
            description={
              settings.customDns && settings.customDns.length > 0
                ? `${settings.customDns.length} server${settings.customDns.length > 1 ? 's' : ''} configured`
                : 'Using VPN default DNS'
            }
            expanded={activeSection === 'dns'}
            onToggle={() =>
              setActiveSection(activeSection === 'dns' ? null : 'dns')
            }
          >
            <div className="mt-3 space-y-2">
              {(settings.customDns || []).map((dns) => (
                <div
                  key={dns}
                  className="flex items-center justify-between rounded-lg bg-white/5 px-3 py-2"
                >
                  <span className="text-sm text-white font-mono">{dns}</span>
                  <button
                    onClick={() => removeDns(dns)}
                    className="text-white/40 hover:text-red-400 transition"
                    aria-label={`Remove ${dns}`}
                  >
                    <X size={14} />
                  </button>
                </div>
              ))}
              <div className="flex gap-2">
                <input
                  type="text"
                  value={dnsInput}
                  onChange={(e) => {
                    setDnsInput(e.target.value);
                    setDnsError(null);
                  }}
                  onKeyDown={(e) => e.key === 'Enter' && addDns()}
                  placeholder="e.g. 1.1.1.1"
                  className="flex-1 rounded-lg glass-input px-3 py-1.5 text-sm text-white placeholder-white/30 outline-none font-mono"
                />
                <button
                  onClick={addDns}
                  className="rounded-lg bg-white/10 px-3 py-1.5 text-sm text-white transition hover:bg-white/20"
                >
                  <Plus size={14} />
                </button>
              </div>
              {dnsError && (
                <p className="text-xs text-red-400">{dnsError}</p>
              )}
              <p className="text-xs text-white/30">
                Leave empty to use the VPN server's DNS. Popular options: 1.1.1.1
                (Cloudflare), 8.8.8.8 (Google), 9.9.9.9 (Quad9)
              </p>
            </div>
          </SettingExpandable>
        </Section>

        {/* ── VPN Settings Section ── */}
        <Section title="VPN Settings">
          <SettingToggle
            icon={Network}
            title="Local Network Sharing"
            description="Access local devices (printers, NAS) while connected"
            enabled={settings.localNetworkSharing}
            onChange={(v) => handleToggle('localNetworkSharing', v)}
          />

          <SettingExpandable
            icon={Router}
            title="WireGuard Port"
            description={
              settings.wireGuardPort === 'auto'
                ? 'Automatic'
                : `Port ${settings.wireGuardPort}`
            }
            expanded={activeSection === 'port'}
            onToggle={() =>
              setActiveSection(activeSection === 'port' ? null : 'port')
            }
          >
            <div className="mt-3 space-y-2">
              {(['auto', '51820', '53', 'custom'] as const).map((option) => {
                const selectedPort = ['auto', '51820', '53'].includes(settings.wireGuardPort)
                  ? settings.wireGuardPort
                  : 'custom';
                return (
                  <label
                    key={option}
                    className={`flex items-center gap-3 rounded-lg px-3 py-2 cursor-pointer transition ${
                      selectedPort === option
                        ? 'bg-white/10'
                        : 'hover:bg-white/5'
                    }`}
                  >
                    <div
                      className={`h-4 w-4 rounded-full border-2 flex items-center justify-center ${
                        selectedPort === option
                          ? 'border-white'
                          : 'border-white/30'
                      }`}
                    >
                      {selectedPort === option && (
                        <div className="h-2 w-2 rounded-full bg-white" />
                      )}
                    </div>
                    <span className="text-sm text-white">
                      {option === 'auto'
                        ? 'Automatic'
                        : option === 'custom'
                        ? 'Custom'
                        : option}
                    </span>
                    <input
                      type="radio"
                      name="wg-port"
                      className="sr-only"
                      checked={selectedPort === option}
                      onChange={() => {
                        if (option === 'custom') {
                          const port = customPortInput;
                          const next = {
                            ...settings,
                            wireGuardPort: isValidPort(port) ? port : 'auto',
                          };
                          updateSettings({ wireGuardPort: next.wireGuardPort });
                          saveSettingsToBackend(next);
                        } else {
                          const next = { ...settings, wireGuardPort: option };
                          updateSettings({ wireGuardPort: option });
                          saveSettingsToBackend(next);
                        }
                      }}
                    />
                  </label>
                );
              })}

              {!['auto', '51820', '53'].includes(settings.wireGuardPort) && (
                <div className="ml-7">
                  <input
                    type="text"
                    value={customPortInput}
                    onChange={(e) => {
                      const filtered = e.target.value.replace(/\D/g, '').slice(0, 5);
                      setCustomPortInput(filtered);
                      if (isValidPort(filtered)) {
                        updateSettings({ wireGuardPort: filtered });
                        if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
                        saveDebounceRef.current = setTimeout(() => {
                          const next = { ...useAppStore.getState().settings, wireGuardPort: filtered };
                          saveSettingsToBackend(next);
                        }, 500);
                      }
                    }}
                    placeholder="1-65535"
                    className="w-full rounded-lg glass-input px-3 py-1.5 text-sm text-white placeholder-white/30 outline-none font-mono"
                  />
                </div>
              )}

              <p className="text-xs text-white/30">
                Use port 53 to bypass restrictive firewalls. Default is 51820.
              </p>
            </div>
          </SettingExpandable>

          <SettingExpandable
            icon={SlidersHorizontal}
            title="MTU"
            description={
              settings.wireGuardMtu === 0
                ? 'Automatic (server default)'
                : `Custom: ${settings.wireGuardMtu}`
            }
            expanded={activeSection === 'mtu'}
            onToggle={() =>
              setActiveSection(activeSection === 'mtu' ? null : 'mtu')
            }
          >
            <div className="mt-3 space-y-2">
              <label className="flex items-center gap-3 rounded-lg px-3 py-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.wireGuardMtu === 0}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setCustomMtuInput('');
                      const next = { ...settings, wireGuardMtu: 0 };
                      updateSettings({ wireGuardMtu: 0 });
                      saveSettingsToBackend(next);
                    } else {
                      setCustomMtuInput('1420');
                      const next = { ...settings, wireGuardMtu: 1420 };
                      updateSettings({ wireGuardMtu: 1420 });
                      saveSettingsToBackend(next);
                    }
                  }}
                  className="sr-only"
                />
                <div
                  className={`h-4 w-4 rounded border-2 flex items-center justify-center ${
                    settings.wireGuardMtu === 0
                      ? 'border-white bg-white'
                      : 'border-white/30'
                  }`}
                >
                  {settings.wireGuardMtu === 0 && (
                    <svg viewBox="0 0 12 12" className="h-3 w-3 text-black">
                      <path
                        d="M10 3L4.5 8.5L2 6"
                        stroke="currentColor"
                        strokeWidth="2"
                        fill="none"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                  )}
                </div>
                <span className="text-sm text-white">Automatic (use server default)</span>
              </label>

              {settings.wireGuardMtu !== 0 && (
                <div className="ml-7">
                  <input
                    type="text"
                    value={customMtuInput}
                    onChange={(e) => {
                      const filtered = e.target.value.replace(/\D/g, '').slice(0, 4);
                      setCustomMtuInput(filtered);
                      const n = Number(filtered);
                      if (n >= 1280 && n <= 1500) {
                        updateSettings({ wireGuardMtu: n });
                        if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
                        saveDebounceRef.current = setTimeout(() => {
                          const next = { ...useAppStore.getState().settings, wireGuardMtu: n };
                          saveSettingsToBackend(next);
                        }, 500);
                      }
                    }}
                    placeholder="1280-1500"
                    className="w-full rounded-lg glass-input px-3 py-1.5 text-sm text-white placeholder-white/30 outline-none font-mono"
                  />
                  <p className="mt-1 text-xs text-white/30">
                    Valid range: 1280 – 1500. Recommended: 1420
                  </p>
                </div>
              )}
            </div>
          </SettingExpandable>

          {/* Info note matching Android */}
          <div className="glass rounded-lg p-3 flex items-center gap-3">
            <Info size={14} className="text-white/40 shrink-0" />
            <p className="text-xs text-white/40">
              Changes take effect on next connection.
            </p>
          </div>
        </Section>

        {/* ── Stealth & Quantum Section ── */}
        <Section title="Stealth & Quantum">
          <SettingToggle
            icon={Eye}
            title="Stealth Mode"
            description={hasOperative ? "Disguise VPN traffic as normal HTTPS (Xray Reality)" : "Requires Operative plan or higher"}
            enabled={settings.stealthMode}
            onChange={(v) => handleToggle('stealthMode', v)}
            disabled={!hasOperative}
          />
          <SettingToggle
            icon={Lock}
            title="Quantum Protection"
            description="Post-quantum key exchange (Rosenpass hybrid PSK)"
            enabled={settings.quantumProtection}
            onChange={(v) => handleToggle('quantumProtection', v)}
          />
          <div className="glass rounded-lg p-3 flex items-center gap-3">
            <Info size={14} className="text-white/40 shrink-0" />
            <p className="text-xs text-white/40">
              Stealth mode wraps WireGuard in TLS 1.3 to bypass censorship.
              Quantum protection adds future-proof key exchange. Both enabled by default.
            </p>
          </div>
        </Section>

        {/* ── Split Tunneling Section ── */}
        <Section title="Split Tunneling">
          <SettingToggle
            icon={Split}
            title="Split Tunneling"
            description={hasOperative ? "Exclude certain apps from VPN" : "Requires Operative plan or higher"}
            enabled={settings.splitTunnelingEnabled}
            onChange={(v) => handleToggle('splitTunnelingEnabled', v)}
            disabled={!hasOperative}
          />
          <AnimatePresence>
            {settings.splitTunnelingEnabled && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <div className="glass rounded-lg p-3 space-y-2">
                  {settings.splitTunnelApps.map((app) => (
                    <div
                      key={app}
                      className="flex items-center justify-between rounded-lg bg-white/5 px-3 py-2"
                    >
                      <span className="text-sm text-white truncate">
                        {app}
                      </span>
                      <button
                        onClick={() => removeSplitApp(app)}
                        className="text-white/40 hover:text-red-400 transition shrink-0"
                        aria-label={`Remove ${app}`}
                      >
                        <X size={14} />
                      </button>
                    </div>
                  ))}
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={splitAppInput}
                      onChange={(e) => setSplitAppInput(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && addSplitApp()}
                      placeholder="e.g. chrome.exe"
                      className="flex-1 rounded-lg glass-input px-3 py-1.5 text-sm text-white placeholder-white/30 outline-none"
                    />
                    <button
                      onClick={addSplitApp}
                      className="rounded-lg bg-white/10 px-3 py-1.5 text-sm text-white transition hover:bg-white/20"
                    >
                      <Plus size={14} />
                    </button>
                  </div>
                  <p className="text-xs text-white/30">
                    Enter application executable names to bypass the VPN tunnel.
                  </p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </Section>

        {/* ── Multi-Hop (Double VPN) Section ── */}
        <Section title="Multi-Hop (Double VPN)">
          <SettingToggle
            icon={Layers}
            title="Multi-Hop Routing"
            description={hasSovereign ? "Route through two servers for extra privacy" : "Requires Sovereign plan"}
            enabled={settings.multiHopEnabled}
            onChange={(v) => {
              handleToggle('multiHopEnabled', v);
              if (v && multiHopRoutes.length === 0) {
                setMultiHopLoading(true);
                invoke<MultiHopRoute[]>('get_multi_hop_routes')
                  .then(setMultiHopRoutes)
                  .catch((e) => console.error('Failed to load routes:', e))
                  .finally(() => setMultiHopLoading(false));
              }
            }}
            disabled={!hasSovereign}
          />
          <AnimatePresence>
            {settings.multiHopEnabled && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <div className="glass rounded-lg p-3 space-y-3">
                  {multiHopLoading ? (
                    <div className="flex items-center justify-center py-4 gap-2 text-white/50 text-sm">
                      <Loader2 size={16} className="animate-spin" /> Loading routes...
                    </div>
                  ) : (
                    <>
                      <div>
                        <label className="text-xs font-medium text-white/60 mb-1 block">Entry Server</label>
                        <select
                          className="w-full rounded-lg glass-input px-3 py-2 text-sm text-white outline-none"
                          value={settings.multiHopEntryNodeId || ''}
                          onChange={(e) => updateSettings({ multiHopEntryNodeId: e.target.value || null })}
                        >
                          <option value="">Select entry node...</option>
                          {servers.filter((s) => s.isOnline).map((s) => (
                            <option key={s.id} value={s.id}>
                              {s.country} - {s.name} ({s.load}% load)
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="flex justify-center">
                        <ArrowRightLeft size={16} className="text-white/30" />
                      </div>
                      <div>
                        <label className="text-xs font-medium text-white/60 mb-1 block">Exit Server</label>
                        <select
                          className="w-full rounded-lg glass-input px-3 py-2 text-sm text-white outline-none"
                          value={settings.multiHopExitNodeId || ''}
                          onChange={(e) => updateSettings({ multiHopExitNodeId: e.target.value || null })}
                        >
                          <option value="">Select exit node...</option>
                          {servers
                            .filter((s) => s.isOnline && s.id !== settings.multiHopEntryNodeId)
                            .map((s) => (
                              <option key={s.id} value={s.id}>
                                {s.country} - {s.name} ({s.load}% load)
                              </option>
                            ))}
                        </select>
                      </div>
                    </>
                  )}
                  <div className="glass rounded-lg p-3 flex items-center gap-3">
                    <Info size={14} className="text-white/40 shrink-0" />
                    <p className="text-xs text-white/40">
                      Requires Sovereign plan. Traffic is routed: You → Entry → Exit → Internet.
                      Connect with the main button after selecting servers.
                    </p>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </Section>

        {/* ── Port Forwarding Section ── */}
        <Section title="Port Forwarding">
          <div className={`glass rounded-lg p-3 space-y-3 ${!hasSovereign ? 'opacity-50 pointer-events-none' : ''}`}>
            {!hasSovereign && (
              <p className="text-xs text-amber-400">Requires Sovereign plan</p>
            )}
            <div className="flex items-center gap-3 mb-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/10">
                <Router size={18} className="text-white" />
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium text-white">Port Forwards</p>
                <p className="text-xs text-white/50">
                  Forward external ports to your device
                </p>
              </div>
            </div>

            {/* Active forwards list */}
            {portForwards.length > 0 && (
              <div className="space-y-1">
                {portForwards.map((pf) => (
                  <div
                    key={pf.id}
                    className="flex items-center justify-between rounded-lg bg-white/5 px-3 py-2"
                  >
                    <div className="flex items-center gap-2">
                      <span className={`h-2 w-2 rounded-full ${pf.enabled ? 'bg-green-400' : 'bg-white/30'}`} />
                      <span className="text-sm text-white">
                        {pf.externalPort} → {pf.internalPort}
                      </span>
                      <span className="text-xs text-white/40 uppercase">{pf.protocol}</span>
                    </div>
                    <button
                      onClick={async () => {
                        try {
                          await invoke('delete_port_forward', { id: pf.id });
                          setPortForwards(portForwards.filter((f) => f.id !== pf.id));
                        } catch (e) {
                          console.error('Failed to delete port forward:', e);
                        }
                      }}
                      className="text-white/40 hover:text-red-400 transition"
                      aria-label={`Delete port forward ${pf.externalPort}`}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Add new port forward */}
            <div className="flex gap-2 items-end">
              <div className="flex-1">
                <label className="text-xs text-white/50 mb-1 block">Port</label>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={portFwdPort}
                  onChange={(e) => setPortFwdPort(e.target.value)}
                  placeholder="8080"
                  className="w-full rounded-lg glass-input px-3 py-1.5 text-sm text-white placeholder-white/30 outline-none"
                />
              </div>
              <div>
                <label className="text-xs text-white/50 mb-1 block">Protocol</label>
                <select
                  className="rounded-lg glass-input px-3 py-1.5 text-sm text-white outline-none"
                  value={portFwdProtocol}
                  onChange={(e) => setPortFwdProtocol(e.target.value as 'tcp' | 'udp')}
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
              <button
                disabled={portFwdLoading || !portFwdPort}
                onClick={async () => {
                  const port = parseInt(portFwdPort, 10);
                  if (isNaN(port) || port < 1 || port > 65535) return;
                  setPortFwdLoading(true);
                  try {
                    const result = await invoke<{ id: string; externalPort: number; internalPort: number; protocol: string }>('create_port_forward', {
                      port,
                      protocol: portFwdProtocol,
                    });
                    setPortForwards([...portForwards, {
                      id: result.id,
                      externalPort: result.externalPort,
                      internalPort: result.internalPort,
                      protocol: result.protocol,
                      enabled: true,
                    }]);
                    setPortFwdPort('');
                  } catch (e) {
                    console.error('Failed to create port forward:', e);
                  } finally {
                    setPortFwdLoading(false);
                  }
                }}
                className="rounded-lg bg-white/10 px-3 py-1.5 text-sm text-white transition hover:bg-white/20 disabled:opacity-50"
              >
                {portFwdLoading ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              </button>
            </div>

            <p className="text-xs text-white/30">
              Requires an active VPN connection. Forward ports for gaming, torrents, or servers.
            </p>
          </div>
        </Section>

        {/* ── Protocol Section ── */}
        <Section title="Protocol">
          <div className="glass rounded-lg p-3 flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/10">
              <Server size={18} className="text-white" />
            </div>
            <div className="flex-1">
              <p className="text-sm font-medium text-white">WireGuard</p>
              <p className="text-xs text-white/50">
                Fast, modern, and secure VPN protocol
              </p>
            </div>
            <span className="rounded-full bg-green-500/10 border border-green-500/20 px-2 py-0.5 text-xs text-green-400">
              Active
            </span>
          </div>
        </Section>

        {/* ── Speed Test Section ── */}
        <Section title="Speed Test">
          <div className={`space-y-3 ${!hasOperative ? 'opacity-50 pointer-events-none' : ''}`}>
            {!hasOperative && (
              <p className="text-xs text-amber-400">Requires Operative plan or higher</p>
            )}
            <div className="glass rounded-lg p-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/10">
                    <Zap size={18} className="text-white" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-white">Test VPN Speed</p>
                    <p className="text-xs text-white/50">
                      {speedTestResult
                        ? `↓ ${speedTestResult.downloadMbps.toFixed(1)} / ↑ ${speedTestResult.uploadMbps.toFixed(1)} Mbps · ${speedTestResult.latencyMs}ms`
                        : 'Measure download, upload & latency'}
                    </p>
                  </div>
                </div>
                <button
                  disabled={speedTestRunning}
                  onClick={async () => {
                    setSpeedTestRunning(true);
                    setSpeedTestResult(null);
                    try {
                      const result = await invoke<{
                        downloadMbps: number;
                        uploadMbps: number;
                        latencyMs: number;
                        jitterMs: number;
                      }>('run_speed_test_command');
                      setSpeedTestResult(result);
                    } catch {
                      // silent — user can retry
                    } finally {
                      setSpeedTestRunning(false);
                    }
                  }}
                  className="rounded-lg bg-white/10 px-3 py-1.5 text-sm text-white transition hover:bg-white/20 disabled:opacity-50"
                >
                  {speedTestRunning ? <Loader2 size={14} className="animate-spin" /> : 'Run'}
                </button>
              </div>
            </div>
          </div>
        </Section>

        {/* ── Updates Section ── */}
        <Section title="Updates">
          <UpdateChecker />
        </Section>

        {/* ── Links Section ── */}
        <Section title="Support">
          <div className="space-y-1">
            <SettingLink
              title="Manage Subscription"
              href="https://birdo.app/dashboard"
            />
            <SettingLink
              title="Privacy Policy"
              href="https://birdo.app/privacy"
            />
            <SettingLink
              title="Terms of Service"
              href="https://birdo.app/terms"
            />
          </div>
        </Section>

        {/* ── Account Deletion (GDPR) ── */}
        <Section title="Danger Zone">
          <DeleteAccountButton />
        </Section>

        {/* ── About Section ── */}
        <div className="glass-card rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-white/10">
              <Info size={20} className="text-white" />
            </div>
            <div>
              <p className="font-medium text-white">Birdo VPN</p>
              <p className="text-xs text-white/50">
                Version {appVersion || '...'}
              </p>
            </div>
          </div>
        </div>

        {/* Bottom spacer */}
        <div className="h-2" />
      </div>
    </div>
  );
}

/* ── Sub-components ── */

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-white/40">
        {title}
      </h3>
      <div className="space-y-2">{children}</div>
    </div>
  );
}

interface SettingToggleProps {
  icon: React.ElementType;
  title: string;
  description: string;
  enabled: boolean;
  onChange: (enabled: boolean) => void;
  disabled?: boolean;
}

function SettingToggle({
  icon: Icon,
  title,
  description,
  enabled,
  onChange,
  disabled,
}: SettingToggleProps) {
  return (
    <div className={`glass flex items-center justify-between rounded-lg p-3 ${disabled ? 'opacity-50' : ''}`}>
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/10">
          <Icon size={18} className="text-white" />
        </div>
        <div>
          <p className="text-sm font-medium text-white">{title}</p>
          <p className="text-xs text-white/50">{description}</p>
        </div>
      </div>
      <button
        role="switch"
        aria-checked={enabled}
        aria-label={title}
        onClick={() => !disabled && onChange(!enabled)}
        disabled={disabled}
        className={`relative h-6 w-11 shrink-0 rounded-full transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/50 ${
          enabled && !disabled ? 'bg-white' : 'bg-white/20'
        } ${disabled ? 'cursor-not-allowed' : ''}`}
      >
        <div
          className={`absolute top-1 h-4 w-4 rounded-full transition-all ${
            enabled ? 'left-6 bg-black' : 'left-1 bg-white'
          }`}
        />
      </button>
    </div>
  );
}

interface SettingExpandableProps {
  icon: React.ElementType;
  title: string;
  description: string;
  expanded: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}

function SettingExpandable({
  icon: Icon,
  title,
  description,
  expanded,
  onToggle,
  children,
}: SettingExpandableProps) {
  return (
    <div className="glass rounded-lg p-3">
      <button
        onClick={onToggle}
        className="flex w-full items-center justify-between"
      >
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/10">
            <Icon size={18} className="text-white" />
          </div>
          <div className="text-left">
            <p className="text-sm font-medium text-white">{title}</p>
            <p className="text-xs text-white/50">{description}</p>
          </div>
        </div>
        <ChevronRight
          size={16}
          className={`text-white/40 transition-transform ${
            expanded ? 'rotate-90' : ''
          }`}
        />
      </button>
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            {children}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

interface SettingLinkProps {
  title: string;
  href: string;
}

function SettingLink({ title, href }: SettingLinkProps) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="glass flex items-center justify-between rounded-lg p-3 transition hover:bg-white/10"
    >
      <span className="text-sm font-medium text-white">{title}</span>
      <ExternalLink size={14} className="text-white/40" />
    </a>
  );
}

function DeleteAccountButton() {
  const [step, setStep] = useState<'idle' | 'confirm' | 'password'>('idle');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDelete = async () => {
    if (!password) return;
    setLoading(true);
    setError(null);
    try {
      await invoke('delete_account', { request: { password } });
      // Account deleted — force reload to return to login screen
      window.location.reload();
    } catch (e: unknown) {
      setError(typeof e === 'string' ? e : 'Deletion failed');
      setLoading(false);
    }
  };

  if (step === 'idle') {
    return (
      <button
        onClick={() => setStep('confirm')}
        className="glass flex w-full items-center gap-3 rounded-lg p-3 text-left transition hover:bg-red-500/20"
      >
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-red-500/20">
          <Trash2 size={18} className="text-red-400" />
        </div>
        <div>
          <p className="text-sm font-medium text-red-400">Delete Account</p>
          <p className="text-xs text-white/50">Permanently delete your account and all data</p>
        </div>
      </button>
    );
  }

  if (step === 'confirm') {
    return (
      <div className="glass rounded-lg p-4 space-y-3">
        <div className="flex items-center gap-2 text-red-400">
          <AlertTriangle size={18} />
          <p className="text-sm font-semibold">Are you sure?</p>
        </div>
        <p className="text-xs text-white/60">
          This will permanently delete your account, VPN configurations, and all associated data. This action cannot be undone.
        </p>
        <div className="flex gap-2">
          <button
            onClick={() => setStep('idle')}
            className="flex-1 rounded-lg bg-white/10 px-3 py-2 text-xs font-medium text-white transition hover:bg-white/20"
          >
            Cancel
          </button>
          <button
            onClick={() => setStep('password')}
            className="flex-1 rounded-lg bg-red-500/80 px-3 py-2 text-xs font-medium text-white transition hover:bg-red-500"
          >
            Continue
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="glass rounded-lg p-4 space-y-3">
      <p className="text-sm font-medium text-red-400">Enter your password to confirm</p>
      {error && (
        <p className="text-xs text-red-400">{error}</p>
      )}
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
        className="w-full rounded-lg bg-white/10 px-3 py-2 text-sm text-white placeholder-white/30 outline-none focus:ring-1 focus:ring-red-400/50"
        autoFocus
        onKeyDown={(e) => e.key === 'Enter' && handleDelete()}
      />
      <div className="flex gap-2">
        <button
          onClick={() => { setStep('idle'); setPassword(''); setError(null); }}
          className="flex-1 rounded-lg bg-white/10 px-3 py-2 text-xs font-medium text-white transition hover:bg-white/20"
        >
          Cancel
        </button>
        <button
          onClick={handleDelete}
          disabled={loading || !password}
          className="flex-1 rounded-lg bg-red-500/80 px-3 py-2 text-xs font-medium text-white transition hover:bg-red-500 disabled:opacity-50"
        >
          {loading ? <Loader2 size={14} className="mx-auto animate-spin" /> : 'Delete Forever'}
        </button>
      </div>
    </div>
  );
}
