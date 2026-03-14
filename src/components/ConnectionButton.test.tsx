import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ConnectionButton } from './ConnectionButton'
import { useAppStore } from '@/store/app-store'

// Mock Tauri API
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn().mockResolvedValue(undefined),
}))

// Mock framer-motion to avoid animation issues in tests
vi.mock('framer-motion', () => ({
  motion: {
    button: ({ children, ...props }: any) => <button {...props}>{children}</button>,
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
}))

function makeMockServer(id: string) {
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
  }
}

describe('ConnectionButton', () => {
  beforeEach(() => {
    useAppStore.setState({
      connectionState: 'disconnected',
      currentServer: null,
      servers: [makeMockServer('us-1')],
    })
  })

  it('renders the connect button', () => {
    render(<ConnectionButton />)
    const button = screen.getByRole('button')
    expect(button).toBeInTheDocument()
  })

  it('is not disabled when disconnected', () => {
    render(<ConnectionButton />)
    const button = screen.getByRole('button')
    expect(button).not.toBeDisabled()
  })

  it('is disabled while connecting', () => {
    useAppStore.setState({ connectionState: 'connecting' })
    render(<ConnectionButton />)
    const button = screen.getByRole('button')
    expect(button).toBeDisabled()
  })

  it('is disabled while disconnecting', () => {
    useAppStore.setState({ connectionState: 'disconnecting' })
    render(<ConnectionButton />)
    const button = screen.getByRole('button')
    expect(button).toBeDisabled()
  })

  it('calls connect_vpn on click when disconnected', async () => {
    const { invoke } = await import('@tauri-apps/api/core')
    render(<ConnectionButton />)
    const button = screen.getByRole('button')
    
    fireEvent.click(button)
    
    expect(invoke).toHaveBeenCalledWith('connect_vpn', { serverId: 'us-1' })
  })

  it('calls disconnect_vpn on click when connected', async () => {
    const { invoke } = await import('@tauri-apps/api/core')
    useAppStore.setState({
      connectionState: 'connected',
      currentServer: makeMockServer('us-1'),
    })

    render(<ConnectionButton />)
    const button = screen.getByRole('button')
    
    fireEvent.click(button)
    
    expect(invoke).toHaveBeenCalledWith('disconnect_vpn')
  })

  it('does not connect when no servers available', () => {
    useAppStore.setState({ servers: [], currentServer: null })
    render(<ConnectionButton />)
    const button = screen.getByRole('button')
    
    fireEvent.click(button)
    
    // Should remain disconnected since no server is available
    expect(useAppStore.getState().connectionState).toBe('disconnected')
  })
})
