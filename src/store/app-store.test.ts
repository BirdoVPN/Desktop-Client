import { describe, it, expect, beforeEach } from 'vitest'
import { useAppStore } from './app-store'

describe('useAppStore', () => {
  beforeEach(() => {
    // Reset store to initial state before each test
    useAppStore.setState({
      isAuthenticated: false,
      isLoading: false,
      userEmail: null,
      connectionState: 'disconnected',
      currentServer: null,
      stats: {
        bytesSent: 0,
        bytesReceived: 0,
        connectedAt: null,
        serverName: null,
      },
      servers: [],
      favoriteServers: [],
      settings: {
        killSwitchEnabled: true,
        autoConnect: false,
        autostart: false,
        startMinimized: false,
        notifications: true,
        preferredServerId: null,
        splitTunnelingEnabled: false,
        splitTunnelApps: [],
        customDns: null,
        protocol: 'wireguard',
        localNetworkSharing: false,
        wireGuardPort: 'auto',
        wireGuardMtu: 0,
        multiHopEnabled: false,
        multiHopEntryNodeId: null,
        multiHopExitNodeId: null,
        stealthMode: false,
        quantumProtection: false,
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
        stats: {
          bytesSent: 1024,
          bytesReceived: 2048,
          connectedAt: '2026-01-01T00:00:00Z',
          serverName: 'US Server',
        },
      })

      useAppStore.getState().logout()

      const state = useAppStore.getState()
      expect(state.isAuthenticated).toBe(false)
      expect(state.userEmail).toBeNull()
      expect(state.connectionState).toBe('disconnected')
      expect(state.currentServer).toBeNull()
      expect(state.stats.bytesSent).toBe(0)
      expect(state.stats.bytesReceived).toBe(0)
      expect(state.stats.connectedAt).toBeNull()
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
      useAppStore.getState().setKillSwitch(false)
      expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false)
    })

    it('should have auto-connect disabled by default', () => {
      expect(useAppStore.getState().settings.autoConnect).toBe(false)
    })

    it('should toggle auto-connect', () => {
      useAppStore.getState().setAutoConnect(true)
      expect(useAppStore.getState().settings.autoConnect).toBe(true)
    })

    it('should have notifications enabled by default', () => {
      expect(useAppStore.getState().settings.notifications).toBe(true)
    })

    it('should toggle notifications', () => {
      useAppStore.getState().setNotifications(false)
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
  })

  // ==========================================
  // Stats
  // ==========================================

  describe('connection stats', () => {
    it('should start with zeroed stats', () => {
      const stats = useAppStore.getState().stats
      expect(stats.bytesSent).toBe(0)
      expect(stats.bytesReceived).toBe(0)
      expect(stats.connectedAt).toBeNull()
      expect(stats.serverName).toBeNull()
    })

    it('should update stats', () => {
      useAppStore.getState().setStats({
        bytesSent: 1024,
        bytesReceived: 2048,
        connectedAt: '2026-01-01T00:00:00Z',
        serverName: 'US West',
      })

      const stats = useAppStore.getState().stats
      expect(stats.bytesSent).toBe(1024)
      expect(stats.bytesReceived).toBe(2048)
      expect(stats.connectedAt).toBe('2026-01-01T00:00:00Z')
      expect(stats.serverName).toBe('US West')
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
    isStreaming: false,
    isP2p: false,
    isOnline: true,
    ...overrides,
  }
}
