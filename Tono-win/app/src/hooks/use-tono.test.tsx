// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { SWRConfig } from 'swr'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { removeCacheData } from '@/services/query-client'
import type { TonoStatus } from '@/services/tono'

/**
 * Contract test: the backend serializes its DTOs with
 * `#[serde(rename_all = "camelCase")]` (see src-tauri/src/tono/commands.rs).
 * These payloads are shaped exactly like the wire — a regression back to
 * snake_case field names in `services/tono.ts` shows up here as `undefined`.
 */
const signedOutPayload: TonoStatus = {
  accountState: 'signedOut',
  uiState: 'notConnected',
  stage: null,
  stageLabel: null,
  selectedServer: null,
  protectionBlocked: false,
  killSwitch: null,
  catalogRevision: null,
  catalogRequiresChoice: false,
}

const readyPayload: TonoStatus = {
  accountState: 'ready',
  uiState: 'connected',
  stage: null,
  stageLabel: null,
  selectedServer: 'US West 1',
  protectionBlocked: false,
  killSwitch: {
    wanted: true,
    live: true,
    mode: 'locked',
    endpoints: [{ ip: '203.0.113.10', port: 443, protocol: 'tcp' }],
    // KillSwitchStatus carries no serde rename in the service crate: this one
    // nested field stays snake_case on the wire.
    last_error: null,
  },
  catalogRevision: 7,
  catalogRequiresChoice: false,
}

const { tonoStatusMock, subscribeTonoStatusMock } = vi.hoisted(() => ({
  tonoStatusMock: vi.fn(),
  subscribeTonoStatusMock: vi.fn((_handler: unknown) => () => {}),
}))

vi.mock('@/services/tono', () => ({
  tonoStatus: tonoStatusMock,
  subscribeTonoStatus: subscribeTonoStatusMock,
  TONO_STATUS_EVENT: 'tono://status',
}))

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async () => () => {}),
  TauriEvent: { WINDOW_CLOSE_REQUESTED: 'tauri://close-requested' },
}))

vi.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({
    isVisible: async () => true,
    onFocusChanged: async () => () => {},
    listen: async () => () => {},
  }),
}))

import { tonoStatusQueryKey, useTonoStatus } from './use-tono'

const freshSWR = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map() }}>{children}</SWRConfig>
)

beforeEach(() => {
  tonoStatusMock.mockReset()
  subscribeTonoStatusMock.mockClear()
})

afterEach(async () => {
  cleanup()
  await removeCacheData(tonoStatusQueryKey)
})

describe('useTonoStatus', () => {
  it('exposes the camelCase wire payload as-is', async () => {
    tonoStatusMock.mockResolvedValue(readyPayload)

    const { result } = renderHook(() => useTonoStatus(), { wrapper: freshSWR })

    await waitFor(() => expect(result.current.status).toBeDefined())

    const status = result.current.status!
    expect(status.accountState).toBe('ready')
    expect(status.uiState).toBe('connected')
    expect(status.selectedServer).toBe('US West 1')
    expect(status.catalogRevision).toBe(7)
    expect(status.catalogRequiresChoice).toBe(false)
    expect(status.killSwitch?.mode).toBe('locked')
    expect(status.killSwitch?.last_error).toBeNull()
  })

  it('applies pushed tono://status payloads to the snapshot', async () => {
    let push: ((status: TonoStatus) => void) | undefined
    subscribeTonoStatusMock.mockImplementation((handler) => {
      push = handler as (status: TonoStatus) => void
      return () => {}
    })
    tonoStatusMock.mockResolvedValue(signedOutPayload)

    // No scoped provider here: the hook writes events through the global SWR
    // mutate, so this test has to share the default cache.
    const { result } = renderHook(() => useTonoStatus())

    await waitFor(() =>
      expect(result.current.status?.accountState).toBe('signedOut'),
    )
    expect(push).toBeDefined()

    act(() => push?.(readyPayload))

    await waitFor(() =>
      expect(result.current.status?.accountState).toBe('ready'),
    )
    expect(result.current.status?.selectedServer).toBe('US West 1')
  })
})
