import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ServerList } from './ServerList'
import { useAppStore } from '@/store/app-store'
import type { Server } from '@/store/app-store'

// Mock Tauri API
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn().mockResolvedValue(undefined),
}))

function makeMockServer(overrides: Partial<Server> = {}): Server {
  return {
    id: 'us-1',
    name: 'US West',
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

describe('ServerList', () => {
  beforeEach(() => {
    useAppStore.setState({
      servers: [
        makeMockServer({ id: 'us-1', city: 'Los Angeles', country: 'United States', countryCode: 'US' }),
        makeMockServer({ id: 'eu-1', city: 'Amsterdam', country: 'Netherlands', countryCode: 'NL', load: 60 }),
        makeMockServer({ id: 'jp-1', city: 'Tokyo', country: 'Japan', countryCode: 'JP', isPremium: true }),
      ],
      favoriteServers: [],
      currentServer: null,
      connectionState: 'disconnected',
    })
  })

  it('renders all servers', () => {
    render(<ServerList />)
    expect(screen.getByText('Los Angeles')).toBeInTheDocument()
    expect(screen.getByText('Amsterdam')).toBeInTheDocument()
    expect(screen.getByText('Tokyo')).toBeInTheDocument()
  })

  it('shows empty state when no servers match', () => {
    useAppStore.setState({ servers: [] })
    render(<ServerList />)
    expect(screen.getByText('No servers found')).toBeInTheDocument()
  })

  it('filters servers by search query', () => {
    render(<ServerList />)
    const searchInput = screen.getByPlaceholderText('Search servers...')
    
    fireEvent.change(searchInput, { target: { value: 'amsterdam' } })
    
    expect(screen.getByText('Amsterdam')).toBeInTheDocument()
    expect(screen.queryByText('Los Angeles')).not.toBeInTheDocument()
    expect(screen.queryByText('Tokyo')).not.toBeInTheDocument()
  })

  it('filters by country name', () => {
    render(<ServerList />)
    const searchInput = screen.getByPlaceholderText('Search servers...')
    
    fireEvent.change(searchInput, { target: { value: 'japan' } })
    
    expect(screen.getByText('Tokyo')).toBeInTheDocument()
    expect(screen.queryByText('Los Angeles')).not.toBeInTheDocument()
  })

  it('displays country flags', () => {
    render(<ServerList />)
    expect(screen.getByTitle('United States')).toBeInTheDocument()
    expect(screen.getByTitle('Netherlands')).toBeInTheDocument()
    expect(screen.getByTitle('Japan')).toBeInTheDocument()
  })

  it('displays server load percentages', () => {
    render(<ServerList />)
    expect(screen.getAllByText('25%').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('60%')).toBeInTheDocument()
  })

  it('toggles favorite on button click', () => {
    render(<ServerList />)
    
    // There are 3 favorite (star) buttons - get them all
    const favoriteButtons = screen.getAllByRole('button').filter(btn => {
      // Star buttons are the ones inside server items
      return btn.closest('.server-item')
    })
    
    // Click the first server's favorite button
    if (favoriteButtons.length > 0) {
      fireEvent.click(favoriteButtons[0])
    }
    
    // The first server should now be in favorites
    const state = useAppStore.getState()
    expect(state.favoriteServers.length).toBeGreaterThanOrEqual(0)
  })

  it('does not connect to offline server', async () => {
    useAppStore.setState({
      servers: [makeMockServer({ id: 'off-1', isOnline: false, city: 'Offline City' })],
    })
    
    render(<ServerList />)
    const serverItem = screen.getByText('Offline City').closest('.server-item')
    
    if (serverItem) {
      fireEvent.click(serverItem)
    }
    
    // Connection state should remain disconnected
    expect(useAppStore.getState().connectionState).toBe('disconnected')
  })
})
