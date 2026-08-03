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
import type {
  TonoConnectProgress,
  TonoConnectStep,
  TonoDiagnosticsReport,
} from '@/services/tono'

const {
  tonoConnectProgressMock,
  tonoRetryNowMock,
  tonoDisconnectMock,
  tonoDiagnosticsReportMock,
  tonoUploadDiagnosticsMock,
  subscribeTonoStatusMock,
  noticeSuccess,
  noticeError,
} = vi.hoisted(() => ({
  tonoConnectProgressMock: vi.fn(),
  tonoRetryNowMock: vi.fn(),
  tonoDisconnectMock: vi.fn(),
  tonoDiagnosticsReportMock: vi.fn(),
  tonoUploadDiagnosticsMock: vi.fn(),
  subscribeTonoStatusMock: vi.fn((_handler: unknown) => () => {}),
  noticeSuccess: vi.fn(),
  noticeError: vi.fn(),
}))

vi.mock('@/services/tono', async (importOriginal) => ({
  // Pure helpers (formatTonoActionError, formatTonoDiagnostics and friends)
  // stay real so the card renders exactly as in production, and so the copied
  // text is the real rendering of the real payload; only IPC is stubbed.
  ...(await importOriginal<typeof import('@/services/tono')>()),
  tonoConnectProgress: tonoConnectProgressMock,
  tonoRetryNow: tonoRetryNowMock,
  tonoDisconnect: tonoDisconnectMock,
  tonoDiagnosticsReport: tonoDiagnosticsReportMock,
  tonoUploadDiagnostics: tonoUploadDiagnosticsMock,
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

/**
 * The whitelisted report the Rust side assembles. The card never builds this
 * itself — it renders and uploads exactly what the backend hands it.
 */
const makeReport = (
  overrides: Partial<TonoDiagnosticsReport> = {},
): TonoDiagnosticsReport => ({
  schemaVersion: 1,
  reportedAtMs: 1712345678901,
  appVersion: '0.0.3',
  osVersion: 'Windows 11 Pro 23H2',
  osArch: 'x86_64',
  serviceProtocol: '2.9',
  serviceBuild: '2.6.2',
  uiState: 'notConnected',
  accountState: 'ready',
  selectedServer: 'US West 1',
  catalogRevision: 12,
  killSwitchMode: 'blocked',
  killSwitchWanted: false,
  killSwitchLive: false,
  killSwitchLastError: null,
  dnsEnabled: false,
  dnsLastError: null,
  failedStage: 'startingTunnel',
  error: 'dns probe failed',
  retryAttempt: 2,
  totalElapsedMs: 4600,
  steps: [
    { key: 'preparing', state: 'completed', elapsedMs: 1200 },
    { key: 'startingTunnel', state: 'current', elapsedMs: 3400 },
  ],
  virtualAdapters: ['hyperV', 'wsl'],
  auditLogPath: '%USERPROFILE%/tono/logs/traffic-audit.jsonl',
  serviceLogPath: 'C:\\ProgramData\\Tono\\logs\\tono-service.log',
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
      onRefreshStatus={onRefreshStatus}
      {...props}
    />,
    { wrapper: freshSWR },
  )
  return { onRefreshStatus }
}

const stubClipboard = () => {
  const writeText = vi.fn().mockResolvedValue(undefined)
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText },
    configurable: true,
  })
  return writeText
}

beforeEach(() => {
  tonoConnectProgressMock.mockReset()
  tonoRetryNowMock.mockReset().mockResolvedValue(undefined)
  tonoDisconnectMock.mockReset().mockResolvedValue(undefined)
  tonoDiagnosticsReportMock.mockReset().mockResolvedValue(makeReport())
  tonoUploadDiagnosticsMock
    .mockReset()
    .mockResolvedValue({ referenceCode: 'TON-4F2K-9QX1', receivedAt: 1712345678 })
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

  it('copies the backend-assembled report rather than re-deriving it', async () => {
    const writeText = stubClipboard()
    tonoConnectProgressMock.mockResolvedValue(
      makeProgress({
        failedStage: 'startingTunnel',
        error: 'dns probe failed',
        retryAttempt: 2,
      }),
    )

    renderCard({ uiState: 'notConnected' })

    fireEvent.click(await screen.findByRole('button', { name: 'Copy details' }))

    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1))
    const copied = writeText.mock.calls[0][0] as string
    expect(copied).toContain('Tono v0.0.3 diagnostics')
    expect(copied).toContain('Server: US West 1')
    expect(copied).toContain(
      'Kill switch: inactive (reported mode=blocked, wanted=false, live=false)',
    )
    expect(copied).toContain('Failed stage: startingTunnel')
    expect(copied).toContain('Error: dns probe failed')
    expect(copied).toContain('Retry attempt: 2')
    expect(copied).toContain('startingTunnel: current (3.4s)')
    expect(copied).toContain(
      'Audit log: %USERPROFILE%/tono/logs/traffic-audit.jsonl',
    )
    // The new fields, and the Service log path (which the app cannot read).
    expect(copied).toContain('OS: Windows 11 Pro 23H2 (x86_64)')
    expect(copied).toContain('Service protocol: 2.9 (build 2.6.2)')
    expect(copied).toContain('Virtual adapters: hyperV, wsl')
    expect(copied).toContain(
      'Service log (admin only): C:\\ProgramData\\Tono\\logs\\tono-service.log',
    )
    await waitFor(() =>
      expect(noticeSuccess).toHaveBeenCalledWith('tono.progress.copied'),
    )
  })

  it('reports a failure to assemble the report instead of copying nothing', async () => {
    const writeText = stubClipboard()
    tonoDiagnosticsReportMock.mockRejectedValue(new Error('state locked'))
    tonoConnectProgressMock.mockResolvedValue(makeProgress())

    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: 'Copy details' }))

    await waitFor(() =>
      expect(noticeError).toHaveBeenCalledWith('tono.progress.copyFailed'),
    )
    expect(writeText).not.toHaveBeenCalled()
  })

  describe('diagnostics upload', () => {
    it('discloses what is sent and only uploads after the user confirms', async () => {
      tonoConnectProgressMock.mockResolvedValue(makeProgress())
      renderCard()

      fireEvent.click(await screen.findByTestId('tono-upload-diagnostics'))

      const dialog = await screen.findByRole('dialog', {
        name: 'Upload diagnostics to Tono support',
      })
      // The disclosure names the account link and the exclusions.
      expect(dialog.textContent).toContain('tied to your account')
      expect(dialog.textContent).toContain(
        'never sends your configuration, keys, tokens, server addresses',
      )
      // Nothing has left the machine yet.
      expect(tonoUploadDiagnosticsMock).not.toHaveBeenCalled()

      fireEvent.click(within(dialog).getByRole('button', { name: 'Send report' }))
      await waitFor(() =>
        expect(tonoUploadDiagnosticsMock).toHaveBeenCalledTimes(1),
      )
    })

    it('cancelling sends nothing', async () => {
      tonoConnectProgressMock.mockResolvedValue(makeProgress())
      renderCard()

      fireEvent.click(await screen.findByTestId('tono-upload-diagnostics'))
      const dialog = await screen.findByRole('dialog', {
        name: 'Upload diagnostics to Tono support',
      })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))

      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
      expect(tonoUploadDiagnosticsMock).not.toHaveBeenCalled()
      expect(screen.getByTestId('tono-upload-diagnostics')).toBeDefined()
    })

    it('shows the reference code prominently and offers to copy it', async () => {
      const writeText = stubClipboard()
      tonoConnectProgressMock.mockResolvedValue(makeProgress())
      renderCard()

      fireEvent.click(await screen.findByTestId('tono-upload-diagnostics'))
      fireEvent.click(await screen.findByRole('button', { name: 'Send report' }))

      const receipt = await screen.findByTestId('tono-upload-reference')
      expect(receipt.textContent).toContain('TON-4F2K-9QX1')
      expect(receipt.textContent).toContain(
        'Give this reference code to Tono support',
      )

      fireEvent.click(within(receipt).getByRole('button', { name: 'Copy code' }))
      await waitFor(() =>
        expect(writeText).toHaveBeenCalledWith('TON-4F2K-9QX1'),
      )
      await screen.findByRole('button', { name: 'Copied' })
    })

    it('replaces the button with the code so a success cannot be repeated', async () => {
      tonoConnectProgressMock.mockResolvedValue(makeProgress())
      renderCard()

      fireEvent.click(await screen.findByTestId('tono-upload-diagnostics'))
      fireEvent.click(await screen.findByRole('button', { name: 'Send report' }))

      await screen.findByTestId('tono-upload-reference')
      expect(screen.queryByTestId('tono-upload-diagnostics')).toBeNull()
      expect(tonoUploadDiagnosticsMock).toHaveBeenCalledTimes(1)
    })

    it('disables the action while a request is in flight', async () => {
      let release: (value: { referenceCode: string; receivedAt: null }) => void =
        () => {}
      tonoUploadDiagnosticsMock.mockImplementation(
        () =>
          new Promise((resolve) => {
            release = resolve
          }),
      )
      tonoConnectProgressMock.mockResolvedValue(makeProgress())
      renderCard()

      fireEvent.click(await screen.findByTestId('tono-upload-diagnostics'))
      const send = await screen.findByRole('button', { name: 'Send report' })
      fireEvent.click(send)

      // Hammering the confirm button must not produce a second request.
      const dialog = await screen.findByRole('dialog', {
        name: 'Upload diagnostics to Tono support',
      })
      const uploading = within(dialog).getByRole('button', {
        name: 'Uploading…',
      })
      fireEvent.click(uploading)
      fireEvent.click(uploading)
      expect(tonoUploadDiagnosticsMock).toHaveBeenCalledTimes(1)
      // …and the card's own action is disabled underneath it.
      expect(
        screen.getByTestId('tono-upload-diagnostics'),
      ).toHaveProperty('disabled', true)

      release({ referenceCode: 'TON-AAAA-1111', receivedAt: null })
      await screen.findByTestId('tono-upload-reference')
      expect(tonoUploadDiagnosticsMock).toHaveBeenCalledTimes(1)
    })

    it.each([
      [
        'TONO_DIAG_SIGNED_OUT: your session has expired',
        'You are signed out, so the report could not be linked to an account. Sign in and try again, or use Copy details and send the text to support.',
      ],
      [
        'TONO_DIAG_RATE_LIMITED: too many requests',
        'Too many reports were uploaded recently. Wait a few minutes and try again, or use Copy details and send the text to support.',
      ],
      [
        'TONO_DIAG_UNREACHABLE: could not reach Tono: connection refused',
        'Could not reach Tono. Check that you are online — if the kill switch is blocking everything, Restore Normal Internet first, then retry.',
      ],
    ])('explains %s actionably and keeps the action available', async (
      raw,
      expected,
    ) => {
      tonoUploadDiagnosticsMock.mockRejectedValue(new Error(raw))
      tonoConnectProgressMock.mockResolvedValue(makeProgress())
      renderCard()

      fireEvent.click(await screen.findByTestId('tono-upload-diagnostics'))
      fireEvent.click(await screen.findByRole('button', { name: 'Send report' }))

      await screen.findByText(expected)
      // A failure is retryable: the dialog stays open, no code is shown.
      expect(screen.queryByTestId('tono-upload-reference')).toBeNull()
      expect(
        screen.getByRole('button', { name: 'Send report' }),
      ).toBeDefined()
    })
  })
})
