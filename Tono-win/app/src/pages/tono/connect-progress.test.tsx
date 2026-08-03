// @vitest-environment jsdom
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import i18n from 'i18next'
import type { ReactNode } from 'react'
import { initReactI18next } from 'react-i18next'
import { SWRConfig } from 'swr'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { tonoConnectProgressQueryKey } from '@/hooks/use-tono'
import enShared from '@/locales/en/shared.json'
import enTono from '@/locales/en/tono.json'
import { removeCacheData } from '@/services/query-client'
import type { TonoConnectProgress, TonoConnectStep } from '@/services/tono'

const {
  tonoConnectProgressMock,
  tonoRetryNowMock,
  tonoDisconnectMock,
  tonoAuditLogPathMock,
  subscribeTonoStatusMock,
  noticeSuccess,
  noticeError,
} = vi.hoisted(() => ({
  tonoConnectProgressMock: vi.fn(),
  tonoRetryNowMock: vi.fn(),
  tonoDisconnectMock: vi.fn(),
  tonoAuditLogPathMock: vi.fn(),
  subscribeTonoStatusMock: vi.fn((_handler: unknown) => () => {}),
  noticeSuccess: vi.fn(),
  noticeError: vi.fn(),
}))

vi.mock('@/services/tono', async (importOriginal) => ({
  // Pure helpers (formatTonoActionError and friends) stay real so the card
  // renders exactly as in production; only the IPC surface is stubbed.
  ...(await importOriginal<typeof import('@/services/tono')>()),
  tonoConnectProgress: tonoConnectProgressMock,
  tonoRetryNow: tonoRetryNowMock,
  tonoDisconnect: tonoDisconnectMock,
  tonoAuditLogPath: tonoAuditLogPathMock,
  subscribeTonoStatus: subscribeTonoStatusMock,
  TONO_STATUS_EVENT: 'tono://status',
}))

vi.mock('@/services/states', () => ({ useThemeMode: () => 'dark' }))

vi.mock('@/services/notice-service', () => ({
  showNotice: { success: noticeSuccess, error: noticeError, info: vi.fn() },
}))

import { ConnectProgressCard } from './connect-progress'

// Real English resources: countdown/按钮断言需要插值后的可读文本。
void i18n.use(initReactI18next).init({
  resources: { en: { translation: { tono: enTono, shared: enShared } } },
  lng: 'en',
})

const step = (
  key: string,
  state: TonoConnectStep['state'],
  elapsedMs: number | null = null,
): TonoConnectStep => ({ key, label: key, state, elapsedMs })

const makeProgress = (
  overrides: Partial<TonoConnectProgress> = {},
): TonoConnectProgress => ({
  steps: [
    step('preparing', 'completed', 1200),
    step('startingTunnel', 'current', 3400),
    step('lockingTraffic', 'pending'),
  ],
  totalElapsedMs: 4600,
  failedStage: null,
  error: null,
  retryAttempt: 0,
  nextRetryAtMs: null,
  ...overrides,
})

const freshSWR = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map() }}>{children}</SWRConfig>
)

const renderCard = (
  props: Partial<Parameters<typeof ConnectProgressCard>[0]> = {},
) => {
  const onRefreshStatus = vi.fn().mockResolvedValue(undefined)
  render(
    <ConnectProgressCard
      uiState="connecting"
      selectedServer="US West 1"
      killSwitch={{
        wanted: true,
        live: true,
        mode: 'locked',
        endpoints: [],
        last_error: null,
      }}
      onRefreshStatus={onRefreshStatus}
      {...props}
    />,
    { wrapper: freshSWR },
  )
  return { onRefreshStatus }
}

beforeEach(() => {
  tonoConnectProgressMock.mockReset()
  tonoRetryNowMock.mockReset().mockResolvedValue(undefined)
  tonoDisconnectMock.mockReset().mockResolvedValue(undefined)
  tonoAuditLogPathMock
    .mockReset()
    .mockResolvedValue({ path: '/data/traffic-audit.jsonl', droppedCount: 0 })
  subscribeTonoStatusMock.mockReset()
  subscribeTonoStatusMock.mockImplementation(() => () => {})
  noticeSuccess.mockReset()
  noticeError.mockReset()
})

afterEach(async () => {
  cleanup()
  await removeCacheData(tonoConnectProgressQueryKey)
})

describe('ConnectProgressCard', () => {
  it('renders completed/current/pending step states with elapsed on the current step', async () => {
    tonoConnectProgressMock.mockResolvedValue(makeProgress())

    renderCard()

    await waitFor(() =>
      expect(screen.getByTestId('tono-step-preparing')).toBeDefined(),
    )
    expect(screen.getByTestId('tono-step-preparing').dataset.state).toBe(
      'completed',
    )
    expect(screen.getByTestId('tono-step-startingTunnel').dataset.state).toBe(
      'current',
    )
    expect(screen.getByTestId('tono-step-lockingTraffic').dataset.state).toBe(
      'pending',
    )
    // Localized step labels and the current step's elapsed time.
    expect(screen.getByText('Preparing protection…')).toBeDefined()
    expect(screen.getByText('3.4s')).toBeDefined()
    expect(screen.getByText('TOTAL 4.6s')).toBeDefined()
  })

  it('shows the failure block for an uncleared failure even when idle', async () => {
    tonoConnectProgressMock.mockResolvedValue(
      makeProgress({
        steps: [
          step('preparing', 'completed', 1200),
          step('securingDNS', 'failed', 8000),
        ],
        failedStage: 'securingDNS',
        error: 'dns probe failed: exit refused',
      }),
    )

    // Not connecting and not protectedOffline: the failure record alone
    // keeps the card visible.
    renderCard({ uiState: 'connected' })

    const errorBlock = await screen.findByTestId('tono-progress-error')
    expect(errorBlock.textContent).toContain('dns probe failed: exit refused')
    expect(
      screen.getByText('Failed at Securing and verifying DNS…'),
    ).toBeDefined()
    expect(screen.getByTestId('tono-step-securingDNS').dataset.state).toBe(
      'failed',
    )
  })

  it('counts the retry down to zero and then shows Retrying…', async () => {
    tonoConnectProgressMock.mockResolvedValue(
      makeProgress({
        retryAttempt: 1,
        nextRetryAtMs: Date.now() + 3000,
      }),
    )

    renderCard({ uiState: 'protectedOffline' })

    const countdown = await screen.findByTestId('tono-retry-countdown')
    expect(countdown.textContent).toBe('Retry 2 in 3s')

    await waitFor(
      () => expect(countdown.textContent).toBe('Retry 2 in 2s'),
      { timeout: 2500 },
    )
    await waitFor(() => expect(countdown.textContent).toBe('Retrying…'), {
      timeout: 4000,
    })
  }, 10000)

  it('calls tono_retry_now when Retry Now is clicked', async () => {
    tonoConnectProgressMock.mockResolvedValue(
      makeProgress({ retryAttempt: 1, nextRetryAtMs: Date.now() + 30000 }),
    )

    const { onRefreshStatus } = renderCard({ uiState: 'protectedOffline' })

    const retryButton = await screen.findByRole('button', {
      name: 'Retry Now',
    })
    fireEvent.click(retryButton)

    await waitFor(() => expect(tonoRetryNowMock).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(onRefreshStatus).toHaveBeenCalled())
  })

  it('restores normal internet through the confirm dialog', async () => {
    tonoConnectProgressMock.mockResolvedValue(
      makeProgress({ retryAttempt: 0, nextRetryAtMs: null }),
    )

    const { onRefreshStatus } = renderCard({ uiState: 'protectedOffline' })

    fireEvent.click(
      await screen.findByRole('button', { name: 'Restore Normal Internet' }),
    )
    const dialog = await screen.findByRole('dialog', {
      name: 'Restore normal internet',
    })
    fireEvent.click(
      within(dialog).getByRole('button', { name: 'Restore Normal Internet' }),
    )

    await waitFor(() => expect(tonoDisconnectMock).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(onRefreshStatus).toHaveBeenCalled())
  })

  it('keeps the restore dialog open with the error when disconnect fails', async () => {
    tonoDisconnectMock.mockRejectedValue(new Error('kill switch still armed'))
    tonoConnectProgressMock.mockResolvedValue(makeProgress())

    renderCard({ uiState: 'protectedOffline' })

    fireEvent.click(
      await screen.findByRole('button', { name: 'Restore Normal Internet' }),
    )
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(
      within(dialog).getByRole('button', { name: 'Restore Normal Internet' }),
    )

    await screen.findByText('kill switch still armed')
    expect(screen.getByRole('dialog')).toBeDefined()
  })

  it('assembles and copies diagnostics details', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })
    tonoConnectProgressMock.mockResolvedValue(
      makeProgress({
        failedStage: 'startingTunnel',
        error: 'dns probe failed',
        retryAttempt: 2,
      }),
    )

    renderCard({
      uiState: 'notConnected',
      killSwitch: {
        wanted: false,
        live: false,
        mode: 'blocked',
        endpoints: [],
        last_error: null,
      },
    })

    fireEvent.click(
      await screen.findByRole('button', { name: 'Copy details' }),
    )

    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1))
    const copied = writeText.mock.calls[0][0] as string
    expect(copied).toContain('Tono v')
    expect(copied).toContain('Server: US West 1')
    expect(copied).toContain(
      'Kill switch: inactive (reported mode=blocked, wanted=false, live=false)',
    )
    expect(copied).toContain('Failed stage: startingTunnel')
    expect(copied).toContain('Error: dns probe failed')
    expect(copied).toContain('Retry attempt: 2')
    expect(copied).toContain('startingTunnel: current (3.4s)')
    expect(copied).toContain('Audit log: /data/traffic-audit.jsonl')
    await waitFor(() =>
      expect(noticeSuccess).toHaveBeenCalledWith('tono.progress.copied'),
    )
  })
})
