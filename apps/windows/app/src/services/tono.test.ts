import { beforeEach, describe, expect, it, vi } from 'vitest'

const { invokeMock, listenMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  listenMock: vi.fn(),
}))

vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }))
vi.mock('@tauri-apps/api/event', () => ({ listen: listenMock }))

import {
  connectRejectionNeedsServerChoice,
  subscribeTonoStatus,
  tonoAuditEnabled,
  tonoAuditLogPath,
  tonoCancelServerTests,
  tonoCatalogStatus,
  tonoRefreshCatalog,
  tonoSetAuditEnabled,
  tonoTestAvailableServers,
  type TonoStatus,
} from './tono'

beforeEach(() => {
  invokeMock.mockReset()
  listenMock.mockReset()
})

describe('tono audit wrappers', () => {
  it('tonoAuditEnabled calls the audit flag command with no args', async () => {
    invokeMock.mockResolvedValue(true)

    await expect(tonoAuditEnabled()).resolves.toBe(true)
    expect(invokeMock).toHaveBeenCalledWith('tono_audit_enabled', undefined)
  })

  it('tonoSetAuditEnabled passes the flag through as args', async () => {
    invokeMock.mockResolvedValue(undefined)

    await tonoSetAuditEnabled(false)
    expect(invokeMock).toHaveBeenCalledWith('tono_set_audit_enabled', {
      enabled: false,
    })
  })

  it('tonoAuditLogPath returns the log info object', async () => {
    const info = { path: '/data/traffic-audit.jsonl', droppedCount: 3 }
    invokeMock.mockResolvedValue(info)

    await expect(tonoAuditLogPath()).resolves.toEqual(info)
    expect(invokeMock).toHaveBeenCalledWith('tono_audit_log_path', undefined)
  })

  it('normalizes backend string errors into Error instances', async () => {
    invokeMock.mockRejectedValue('kill switch still armed')

    await expect(tonoSetAuditEnabled(true)).rejects.toBeInstanceOf(Error)
    await expect(tonoSetAuditEnabled(true)).rejects.toThrow(
      'kill switch still armed',
    )
  })
})

describe('tono server management wrappers', () => {
  it('uses dedicated backend commands without frontend catalog data', async () => {
    invokeMock.mockResolvedValue({ revision: 8, nodeCount: 3 })

    await tonoCatalogStatus()
    await tonoRefreshCatalog()
    await tonoTestAvailableServers()
    await tonoCancelServerTests()

    expect(invokeMock.mock.calls).toEqual([
      ['tono_catalog_status', undefined],
      ['tono_refresh_catalog', undefined],
      ['tono_test_available_servers', undefined],
      ['tono_cancel_server_tests', undefined],
    ])
  })
})

describe('subscribeTonoStatus', () => {
  const payload = { accountState: 'ready' } as TonoStatus

  it('shares one backend listener across subscribers and reference-counts the teardown', async () => {
    const unlisten = vi.fn()
    let emit: ((event: { payload: TonoStatus }) => void) | undefined
    listenMock.mockImplementation((_name: string, callback: unknown) => {
      emit = callback as (event: { payload: TonoStatus }) => void
      return Promise.resolve(unlisten)
    })

    const first = vi.fn()
    const second = vi.fn()
    const secondLive = vi.fn()
    const unsubFirst = subscribeTonoStatus(first)
    const unsubSecond = subscribeTonoStatus(second, secondLive)

    // Registration starts once, synchronously, no matter how many subscribers.
    expect(listenMock).toHaveBeenCalledTimes(1)
    expect(listenMock).toHaveBeenCalledWith('tono://status', expect.anything())
    // `secondLive` runs once the shared listener is live.
    await vi.waitFor(() => expect(secondLive).toHaveBeenCalledTimes(1))

    emit?.({ payload })
    expect(first).toHaveBeenCalledWith(payload)
    expect(second).toHaveBeenCalledWith(payload)

    // One subscriber leaving keeps the listener alive for the rest.
    unsubFirst()
    expect(unlisten).not.toHaveBeenCalled()
    emit?.({ payload })
    expect(first).toHaveBeenCalledTimes(1)
    expect(second).toHaveBeenCalledTimes(2)

    // The last teardown unlistens.
    unsubSecond()
    expect(unlisten).toHaveBeenCalledTimes(1)
  })
})

describe('connectRejectionNeedsServerChoice', () => {
  it('matches every backend guard string that the server picker answers', () => {
    // Verbatim guard_snapshot rejections from app/src-tauri/src/tono/connection.rs.
    for (const message of [
      'select a server first',
      'the selected server is not in the catalog',
      'the exit catalog is not available yet',
      'the selected node left the catalog; pick a server again',
    ]) {
      expect(connectRejectionNeedsServerChoice(new Error(message))).toBe(true)
    }
  })

  it('leaves other rejections to the inline error path', () => {
    for (const message of [
      'TONO_SERVICE_BUSY: repair pending',
      'a connection transition is already in flight',
      'not signed in',
      '',
    ]) {
      expect(connectRejectionNeedsServerChoice(new Error(message))).toBe(false)
    }
    expect(connectRejectionNeedsServerChoice(undefined)).toBe(false)
  })
})
