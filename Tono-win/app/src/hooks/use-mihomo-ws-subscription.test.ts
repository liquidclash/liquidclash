import type { MihomoWebSocket } from 'tauri-plugin-mihomo-api'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { createSharedSubscriptionEntry } from './use-mihomo-ws-subscription'

const socket = (close = vi.fn(async () => {})) =>
  ({
    addListener: vi.fn(),
    close,
  }) as unknown as MihomoWebSocket

afterEach(() => {
  vi.useRealTimers()
})

describe('shared Mihomo WebSocket recovery', () => {
  it('closes, clears and reconnects when onConnected throws', async () => {
    vi.useFakeTimers()
    const first = socket()
    const second = socket()
    const connect = vi
      .fn<() => Promise<MihomoWebSocket>>()
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second)
    const onConnected = vi
      .fn()
      .mockRejectedValueOnce(new Error('snapshot failed'))
      .mockResolvedValueOnce(undefined)
    const entry = createSharedSubscriptionEntry(connect)
    entry.owners.add({
      handleMessage: vi.fn(),
      onConnected,
      isMounted: () => true,
    })

    await entry.connectWs()

    expect(first.addListener).toHaveBeenCalledOnce()
    expect(first.close).toHaveBeenCalledOnce()
    expect(entry.ws).toBeNull()
    expect(entry.reconnectTimer).not.toBeNull()

    await vi.runOnlyPendingTimersAsync()

    expect(connect).toHaveBeenCalledTimes(2)
    expect(second.addListener).toHaveBeenCalledOnce()
    expect(entry.ws).toBe(second)
  })

  it('still reconnects when the stale socket close handshake fails', async () => {
    vi.useFakeTimers()
    const first = socket(
      vi.fn(async () => Promise.reject(new Error('close failed'))),
    )
    const second = socket()
    const connect = vi
      .fn<() => Promise<MihomoWebSocket>>()
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second)
    const entry = createSharedSubscriptionEntry(connect)
    entry.owners.add({
      handleMessage: vi.fn(),
      isMounted: () => true,
    })
    await entry.connectWs()

    await expect(entry.scheduleReconnect()).resolves.toBeUndefined()
    await vi.runOnlyPendingTimersAsync()

    expect(connect).toHaveBeenCalledTimes(2)
    expect(entry.ws).toBe(second)
  })
})
