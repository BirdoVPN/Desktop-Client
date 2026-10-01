import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useAppStore } from './app-store'
import { selectDisplayState, selectTunnelActive } from './selectors'
import { parseVpnStatus, type VpnStatus } from '@/lib/ipc'

/** A v2 status payload (snake_case), parsed exactly as the controller parses one. */
function status(fields: Record<string, unknown>): VpnStatus {
  const st = parseVpnStatus({ state: 'disconnected', kill_switch_blocking: false, error: null, ...fields })
  if (!st) throw new Error('fixture did not parse')
  return st
}

describe('useAppStore', () => {
  beforeEach(() => {
    // Reset store to initial state before each test
    useAppStore.setState({
      isAuthenticated: false,
      isLoading: false,
      userEmail: null,
      connectionState: 'disconnected',
      pendingAction: null,
      killSwitchBlocking: false,
      vpnError: null,
      commandError: null,
      giveUp: null,
      statusSeq: -1,
      dnsDegraded: [],
      currentServer: null,
      servers: [],
      favoriteServers: [],
      settings: {
        killSwitchEnabled: true,
        autoConnect: false,
        autostart: false,
        startMinimized: false,
        notifications: true,
        showIpInNotification: false,
        showLocationInNotification: false,
        preferredServerId: null,
        splitTunnelingEnabled: false,
        splitTunnelApps: [],
        customDns: null,
        customDnsEnabled: false,
        protocol: 'wireguard',
        localNetworkSharing: false,
        wireGuardPort: 'auto',
        wireGuardMtu: 0,
        multiHopEnabled: false,
        multiHopEntryNodeId: null,
        multiHopExitNodeId: null,
        stealthMode: false,
        quantumProtection: false,
        dnsFiltering: false,
        lockdownMode: true,
        crashReportsEnabled: false,
      },
      hasAcceptedConsent: false,
      isOnline: true,
    })
  })

  // ==========================================
  // Auth State
  // ==========================================

  describe('authentication', () => {
    it('should start unauthenticated', () => {
      const state = useAppStore.getState()
      expect(state.isAuthenticated).toBe(false)
      expect(state.userEmail).toBeNull()
    })

    it('should set authenticated state', () => {
      useAppStore.getState().setAuthenticated(true)
      expect(useAppStore.getState().isAuthenticated).toBe(true)
    })

    it('should set user email', () => {
      useAppStore.getState().setUserEmail('test@birdo.app')
      expect(useAppStore.getState().userEmail).toBe('test@birdo.app')
    })

    it('should clear state on logout', () => {
      // Set up authenticated state
      useAppStore.setState({
        isAuthenticated: true,
        userEmail: 'test@birdo.app',
        connectionState: 'connected',
        currentServer: makeMockServer('us-1'),
        lastServerId: 'us-1',
        servers: [makeMockServer('us-1')],
        liveStats: { bytesIn: 2048, bytesOut: 1024, uptimeSeconds: 60, latencyMs: 20 },
        killSwitchBlocking: true,
        pendingAction: 'disconnecting',
      })

      useAppStore.getState().logout()

      const state = useAppStore.getState()
      expect(state.isAuthenticated).toBe(false)
      expect(state.userEmail).toBeNull()
      expect(state.connectionState).toBe('disconnected')
      expect(state.currentServer).toBeNull()
      // The next account must not inherit this one's servers, choice or counters.
      expect(state.lastServerId).toBeNull()
      expect(state.servers).toEqual([])
      expect(state.liveStats).toBeNull()
      expect(state.killSwitchBlocking).toBe(false)
      expect(state.pendingAction).toBeNull()
    })
  })

  // ==========================================
  // Connection State Machine
  // ==========================================

  describe('connection state', () => {
    it('should start disconnected', () => {
      expect(useAppStore.getState().connectionState).toBe('disconnected')
    })

    it('should transition to connecting', () => {
      useAppStore.getState().setConnectionState('connecting')
      expect(useAppStore.getState().connectionState).toBe('connecting')
    })

    it('should transition connecting → connected', () => {
      useAppStore.getState().setConnectionState('connecting')
      useAppStore.getState().setConnectionState('connected')
      expect(useAppStore.getState().connectionState).toBe('connected')
    })

    it('should transition connected → disconnecting', () => {
      useAppStore.getState().setConnectionState('connected')
      useAppStore.getState().setConnectionState('disconnecting')
      expect(useAppStore.getState().connectionState).toBe('disconnecting')
    })

    it('should transition disconnecting → disconnected', () => {
      useAppStore.getState().setConnectionState('disconnecting')
      useAppStore.getState().setConnectionState('disconnected')
      expect(useAppStore.getState().connectionState).toBe('disconnected')
    })

    it('should handle error state', () => {
      useAppStore.getState().setConnectionState('connecting')
      useAppStore.getState().setConnectionState('error')
      expect(useAppStore.getState().connectionState).toBe('error')
    })
  })

  // ==========================================
  // Server Selection
  // ==========================================

  describe('server management', () => {
    it('should set servers list', () => {
      const servers = [makeMockServer('us-1'), makeMockServer('eu-1')]
      useAppStore.getState().setServers(servers)
      expect(useAppStore.getState().servers).toHaveLength(2)
    })

    it('should set current server', () => {
      const server = makeMockServer('us-1')
      useAppStore.getState().setCurrentServer(server)
      expect(useAppStore.getState().currentServer?.id).toBe('us-1')
    })

    it('should clear current server', () => {
      useAppStore.getState().setCurrentServer(makeMockServer('us-1'))
      useAppStore.getState().setCurrentServer(null)
      expect(useAppStore.getState().currentServer).toBeNull()
    })
  })

  // ==========================================
  // Favorites
  // ==========================================

  describe('favorites', () => {
    it('should add server to favorites', () => {
      useAppStore.getState().toggleFavorite('us-1')
      expect(useAppStore.getState().favoriteServers).toContain('us-1')
    })

    it('should remove server from favorites', () => {
      useAppStore.setState({ favoriteServers: ['us-1', 'eu-1'] })
      useAppStore.getState().toggleFavorite('us-1')
      expect(useAppStore.getState().favoriteServers).not.toContain('us-1')
      expect(useAppStore.getState().favoriteServers).toContain('eu-1')
    })

    it('should toggle favorite idempotently', () => {
      useAppStore.getState().toggleFavorite('us-1')
      useAppStore.getState().toggleFavorite('us-1')
      expect(useAppStore.getState().favoriteServers).not.toContain('us-1')
    })
  })

  // ==========================================
  // Settings
  // ==========================================

  describe('settings', () => {
    it('should have kill switch enabled by default', () => {
      expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true)
    })

    it('should toggle kill switch', () => {
      useAppStore.getState().updateSettings({ killSwitchEnabled: false })
      expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false)
    })

    it('should have auto-connect disabled by default', () => {
      expect(useAppStore.getState().settings.autoConnect).toBe(false)
    })

    it('should toggle auto-connect', () => {
      useAppStore.getState().updateSettings({ autoConnect: true })
      expect(useAppStore.getState().settings.autoConnect).toBe(true)
    })

    it('should have notifications enabled by default', () => {
      expect(useAppStore.getState().settings.notifications).toBe(true)
    })

    it('should toggle notifications', () => {
      useAppStore.getState().updateSettings({ notifications: false })
      expect(useAppStore.getState().settings.notifications).toBe(false)
    })
  })

  // ==========================================
  // Consent
  // ==========================================

  describe('consent', () => {
    it('should start without consent', () => {
      expect(useAppStore.getState().hasAcceptedConsent).toBe(false)
    })

    it('should accept consent', () => {
      useAppStore.getState().setConsent(true)
      expect(useAppStore.getState().hasAcceptedConsent).toBe(true)
    })
  })

  // ==========================================
  // Network State
  // ==========================================

  describe('network state', () => {
    it('should start online', () => {
      expect(useAppStore.getState().isOnline).toBe(true)
    })

    it('should detect offline', () => {
      useAppStore.getState().setOnline(false)
      expect(useAppStore.getState().isOnline).toBe(false)
    })

    it('should detect back online', () => {
      useAppStore.getState().setOnline(false)
      useAppStore.getState().setOnline(true)
      expect(useAppStore.getState().isOnline).toBe(true)
    })
  })

  // ==========================================
  // VPN Settings (Android parity)
  // ==========================================

  describe('VPN settings', () => {
    it('should have local network sharing disabled by default', () => {
      expect(useAppStore.getState().settings.localNetworkSharing).toBe(false)
    })

    it('should update local network sharing', () => {
      useAppStore.getState().updateSettings({ localNetworkSharing: true })
      expect(useAppStore.getState().settings.localNetworkSharing).toBe(true)
    })

    it('should have auto wireguard port by default', () => {
      expect(useAppStore.getState().settings.wireGuardPort).toBe('auto')
    })

    it('should update wireguard port', () => {
      useAppStore.getState().updateSettings({ wireGuardPort: '53' })
      expect(useAppStore.getState().settings.wireGuardPort).toBe('53')
    })

    it('should have auto MTU by default', () => {
      expect(useAppStore.getState().settings.wireGuardMtu).toBe(0)
    })

    it('should update MTU', () => {
      useAppStore.getState().updateSettings({ wireGuardMtu: 1420 })
      expect(useAppStore.getState().settings.wireGuardMtu).toBe(1420)
    })

    // BirdoShield (D18) is opt-in. The `beforeEach` above seeds the settings
    // from a fixture, so asserting on THIS store instance would only test the
    // fixture (PR #160 review, nit 2): import a fresh module instance and read
    // the store's own `defaultSettings` before anything touches it.
    it('should have BirdoShield (dnsFiltering) OFF in the store default, not just the fixture', async () => {
      // `settings` is in the persist partialize: drop what earlier tests wrote
      // to localStorage so the fresh instance cannot rehydrate from it.
      localStorage.removeItem('birdo-vpn-storage')
      vi.resetModules()
      const fresh = await import('./app-store')
      expect(fresh.useAppStore.getState().settings.dnsFiltering).toBe(false)
      // And the Rust `AppSettings::default()` twin: quantum ON, stealth OFF.
      expect(fresh.useAppStore.getState().settings.quantumProtection).toBe(true)
      expect(fresh.useAppStore.getState().settings.stealthMode).toBe(false)
    })

    // The fleet gate is separate from the per-device preference: it is not
    // persisted and must start AVAILABLE, so a cold start (or a client that
    // never reaches the web app) offers a feature that works instead of
    // hiding it.
    it('should default dnsFilteringAvailable to true and keep it out of persisted storage', async () => {
      localStorage.clear()
      vi.resetModules()
      const fresh = await import('./app-store')
      expect(fresh.useAppStore.getState().dnsFilteringAvailable).toBe(true)

      fresh.useAppStore.getState().setDnsFilteringAvailable(false)
      expect(fresh.useAppStore.getState().dnsFilteringAvailable).toBe(false)
      expect(localStorage.getItem('birdo-vpn-storage') ?? '').not.toContain(
        'dnsFilteringAvailable',
      )
    })

    it('should turn BirdoShield on via updateSettings', () => {
      useAppStore.getState().updateSettings({ dnsFiltering: true })
      expect(useAppStore.getState().settings.dnsFiltering).toBe(true)
    })
  })

  // ==========================================
  // Rust status (contract v2 §1): seq ordering and error ownership
  // ==========================================

  describe('applyVpnStatus', () => {
    it('applies a newer status and records its seq', () => {
      expect(useAppStore.getState().applyVpnStatus(status({ state: 'connected', seq: 3 }))).toBe(true)
      expect(useAppStore.getState().connectionState).toBe('connected')
      expect(useAppStore.getState().statusSeq).toBe(3)
    })

    it('drops a status older than the one applied — the stale-poll flip-back (W2-009)', () => {
      useAppStore.getState().applyVpnStatus(status({ state: 'disconnected', seq: 5 }))
      // A resync that read `connected` before the user's Disconnect, arriving late.
      expect(useAppStore.getState().applyVpnStatus(status({ state: 'connected', seq: 4 }))).toBe(false)
      expect(useAppStore.getState().connectionState).toBe('disconnected')
    })

    it('applies an EQUAL seq (a resync of the same state) without moving backwards', () => {
      useAppStore.getState().applyVpnStatus(status({ state: 'connected', seq: 7, dns_degraded: [] }))
      expect(
        useAppStore.getState().applyVpnStatus(status({ state: 'connected', seq: 7, dns_degraded: ['Wi-Fi'] })),
      ).toBe(true)
      expect(useAppStore.getState().dnsDegraded).toEqual(['Wi-Fi'])
    })

    it('an identical reading writes nothing, so subscribers do not re-render (W2-037)', () => {
      useAppStore.getState().applyVpnStatus(status({ state: 'connected', seq: 1, dns_degraded: [] }))
      const listener = vi.fn()
      const unsubscribe = useAppStore.subscribe(listener)
      useAppStore.getState().applyVpnStatus(status({ state: 'connected', seq: 1, dns_degraded: [] }))
      unsubscribe()
      expect(listener).not.toHaveBeenCalled()
    })

    it('a pre-v2 status without `seq` or `error` is applied and leaves a command error alone', () => {
      useAppStore.setState({ commandError: { code: 'device_limit', message: '', retryable: false, retry_after_secs: null } })
      const legacy = parseVpnStatus({ state: 'disconnected' })!
      expect(legacy.seq).toBeNull()
      expect(legacy.error).toBeUndefined()
      expect(useAppStore.getState().applyVpnStatus(legacy)).toBe(true)
      expect(useAppStore.getState().commandError?.code).toBe('device_limit')
    })

    it('records a reconnect give-up with its kind and attempts (P1-parity-020)', () => {
      useAppStore.getState().applyVpnStatus(status({ state: 'reconnecting', seq: 1, reconnect_attempt: 9, reconnect_max: 10 }))
      useAppStore.getState().applyVpnStatus(
        status({
          state: 'error',
          seq: 2,
          gave_up: { attempts: 10 },
          error: { code: 'server_unreachable', message: 'x', retryable: true, retry_after_secs: null },
        }),
      )
      expect(useAppStore.getState().giveUp).toEqual({ kind: 'never_established', attempts: 10 })
      useAppStore.getState().applyVpnStatus(status({ state: 'connecting', seq: 3 }))
      expect(useAppStore.getState().giveUp).toBeNull()
    })

    it('sees a give-up whose reconnecting status was coalesced away (REVIEW-WIN-009)', () => {
      // A breaker trip: TearDown (connected → reconnecting) and GiveUp
      // (→ error) back to back. The emitter sends the latest snapshot only, so
      // the UI can go straight from connected to error.
      useAppStore.getState().applyVpnStatus(status({ state: 'connected', seq: 1 }))
      useAppStore.getState().applyVpnStatus(
        status({
          state: 'error',
          seq: 3,
          gaveUp: { attempts: 0 },
          error: { code: 'server_unreachable', message: 'x', retryable: true, retry_after_secs: null },
        }),
      )
      expect(useAppStore.getState().giveUp).toEqual({ kind: 'never_established', attempts: 0 })
    })

    it('an error that ends no recovery is not a give-up, whatever came before it', () => {
      useAppStore.getState().applyVpnStatus(status({ state: 'reconnecting', seq: 1 }))
      useAppStore.getState().applyVpnStatus(
        status({
          state: 'error',
          seq: 2,
          gaveUp: null,
          error: { code: 'revoked', message: 'x', retryable: false, retry_after_secs: null },
        }),
      )
      expect(useAppStore.getState().giveUp).toBeNull()
    })
  })

  describe('display state (the pending command over the Rust state)', () => {
    it('shows the pending command until Rust gets there', () => {
      expect(selectDisplayState({ connectionState: 'disconnected', pendingAction: 'connecting' })).toBe('connecting')
      expect(selectDisplayState({ connectionState: 'connected', pendingAction: 'connecting' })).toBe('connected')
      expect(selectDisplayState({ connectionState: 'connected', pendingAction: 'disconnecting' })).toBe('disconnecting')
      expect(selectDisplayState({ connectionState: 'disconnected', pendingAction: 'disconnecting' })).toBe('disconnected')
      expect(selectDisplayState({ connectionState: 'connected', pendingAction: 'switching' })).toBe('switching')
      expect(selectDisplayState({ connectionState: 'reconnecting', pendingAction: null })).toBe('reconnecting')
    })

    it('counts a held kill-switch block as an active tunnel, even when disconnected', () => {
      expect(selectTunnelActive({ connectionState: 'disconnected', pendingAction: null, killSwitchBlocking: false })).toBe(false)
      expect(selectTunnelActive({ connectionState: 'disconnected', pendingAction: null, killSwitchBlocking: true })).toBe(true)
      expect(selectTunnelActive({ connectionState: 'error', pendingAction: null, killSwitchBlocking: false })).toBe(true)
    })
  })

  describe('persisted settings migration', () => {
    it('merges an older saved settings object over the defaults and carries a Custom DNS list over as ON', async () => {
      localStorage.setItem(
        'birdo-vpn-storage',
        JSON.stringify({ state: { settings: { customDns: ['1.1.1.1'], killSwitchEnabled: false } }, version: 0 }),
      )
      await useAppStore.persist.rehydrate()
      const s = useAppStore.getState().settings
      expect(s.customDnsEnabled).toBe(true)
      expect(s.killSwitchEnabled).toBe(false)
      // A field the old object never had comes from the defaults, not undefined.
      expect(s.lockdownMode).toBe(true)
      localStorage.removeItem('birdo-vpn-storage')
    })
  })
})

// ==========================================
// Helpers
// ==========================================

function makeMockServer(id: string, overrides: Partial<import('./app-store').Server> = {}): import('./app-store').Server {
  return {
    id,
    name: `Server ${id}`,
    country: 'United States',
    countryCode: 'US',
    city: 'Los Angeles',
    load: 25,
    isPremium: false,
    minPlan: 'RECON',
    isHighSpeed: false,
    isPortForwarding: false,
    isOnline: true,
    isAccessible: true,
    ...overrides,
  }
}
