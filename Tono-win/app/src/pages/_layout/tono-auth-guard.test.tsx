// @vitest-environment jsdom
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react'
import i18n from 'i18next'
import type { ReactNode } from 'react'
import { initReactI18next } from 'react-i18next'
import { MemoryRouter, Route, Routes } from 'react-router'
import { SWRConfig } from 'swr'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { tonoStatusQueryKey } from '@/hooks/use-tono'
import LoginPage from '@/pages/tono/login'
import { removeCacheData } from '@/services/query-client'
import type { TonoStatus } from '@/services/tono'

/**
 * Contract test for the layout auth guard: the payloads below are shaped like
 * the backend wire format (`#[serde(rename_all = "camelCase")]`, see
 * src-tauri/src/tono/commands.rs). With snake_case field names the guard reads
 * `accountState` as `undefined` and none of these redirects fire.
 */
const statusPayload = (
  accountState: TonoStatus['accountState'],
): TonoStatus => ({
  accountState,
  uiState: 'notConnected',
  stage: null,
  stageLabel: null,
  selectedServer: null,
  protectionBlocked: false,
  killSwitch: null,
  catalogRevision: null,
  catalogRequiresChoice: false,
})

const {
  tonoStatusMock,
  subscribeTonoStatusMock,
  tonoSignInStartMock,
  tonoSignInVerifyMock,
  tonoRetryRestoreMock,
} = vi.hoisted(() => ({
  tonoStatusMock: vi.fn(),
  subscribeTonoStatusMock: vi.fn((_handler: unknown) => () => {}),
  tonoSignInStartMock: vi.fn(),
  tonoSignInVerifyMock: vi.fn(),
  tonoRetryRestoreMock: vi.fn(),
}))

vi.mock('@/services/tono', () => ({
  tonoStatus: tonoStatusMock,
  subscribeTonoStatus: subscribeTonoStatusMock,
  tonoSignInStart: tonoSignInStartMock,
  tonoSignInVerify: tonoSignInVerifyMock,
  tonoRetryRestore: tonoRetryRestoreMock,
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

import { TonoAuthGuard } from './tono-auth-guard'

// No resources loaded: t() returns the key, which is what the login-flow test
// asserts on.
void i18n.use(initReactI18next).init({ resources: {}, lng: 'en' })

const freshSWR = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map() }}>{children}</SWRConfig>
)

const renderAt = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="/"
          element={<TonoAuthGuard>dashboard page</TonoAuthGuard>}
        />
        <Route
          path="/login"
          element={<TonoAuthGuard>login page</TonoAuthGuard>}
        />
      </Routes>
    </MemoryRouter>,
    { wrapper: freshSWR },
  )

beforeEach(() => {
  tonoStatusMock.mockReset()
  subscribeTonoStatusMock.mockReset()
  subscribeTonoStatusMock.mockImplementation(() => () => {})
  tonoSignInStartMock.mockReset()
  tonoSignInVerifyMock.mockReset()
  tonoRetryRestoreMock.mockReset()
})

afterEach(async () => {
  cleanup()
  await removeCacheData(tonoStatusQueryKey)
})

describe('TonoAuthGuard', () => {
  it('redirects signedOut to /login', async () => {
    tonoStatusMock.mockResolvedValue(statusPayload('signedOut'))

    renderAt('/')

    await waitFor(() => expect(screen.getByText('login page')).toBeDefined())
    expect(screen.queryByText('dashboard page')).toBeNull()
  })

  it('redirects suspended and error to /login as well', async () => {
    tonoStatusMock.mockResolvedValue(statusPayload('suspended'))
    renderAt('/')
    await waitFor(() => expect(screen.getByText('login page')).toBeDefined())
    cleanup()

    tonoStatusMock.mockResolvedValue(statusPayload('error'))
    renderAt('/')
    await waitFor(() => expect(screen.getByText('login page')).toBeDefined())
  })

  it('redirects authenticating to /login when hit outside it', async () => {
    tonoStatusMock.mockResolvedValue(statusPayload('authenticating'))

    renderAt('/')

    await waitFor(() => expect(screen.getByText('login page')).toBeDefined())
    expect(screen.queryByText('dashboard page')).toBeNull()
  })

  it.each(['signedOut', 'suspended', 'error', 'authenticating'] as const)(
    'keeps %s on the login page (no redirect loop)',
    async (accountState) => {
      tonoStatusMock.mockResolvedValue(statusPayload(accountState))

      renderAt('/login')

      await waitFor(() => expect(screen.getByText('login page')).toBeDefined())
      expect(screen.queryByRole('progressbar')).toBeNull()
    },
  )

  it('kicks a ready account off /login back to the dashboard', async () => {
    tonoStatusMock.mockResolvedValue(statusPayload('ready'))

    renderAt('/login')

    await waitFor(() =>
      expect(screen.getByText('dashboard page')).toBeDefined(),
    )
    expect(screen.queryByText('login page')).toBeNull()
  })

  it('lets a ready account through to the dashboard', async () => {
    tonoStatusMock.mockResolvedValue(statusPayload('ready'))

    renderAt('/')

    await waitFor(() =>
      expect(screen.getByText('dashboard page')).toBeDefined(),
    )
  })

  it('shows a loading placeholder while restoring', async () => {
    tonoStatusMock.mockResolvedValue(statusPayload('restoring'))

    renderAt('/')

    await waitFor(() => expect(screen.getByRole('progressbar')).toBeDefined())
    expect(screen.queryByText('dashboard page')).toBeNull()
  })

  it('shows the loading placeholder until the first status read lands', async () => {
    // Never resolves: no snapshot, no decision.
    tonoStatusMock.mockReturnValue(new Promise(() => {}))

    renderAt('/')

    await waitFor(() => expect(screen.getByRole('progressbar')).toBeDefined())
    expect(screen.queryByText('dashboard page')).toBeNull()
  })
})

describe('login flow under status pushes', () => {
  it('keeps the sign-in form mounted when the backend flips to authenticating', async () => {
    // The P0 regression: requesting a code makes the backend emit
    // `authenticating`; mapping that to the loading placeholder unmounted the
    // form (email, code input, resend countdown) and deadlocked sign-in.
    let push: ((status: TonoStatus) => void) | undefined
    subscribeTonoStatusMock.mockImplementation((handler) => {
      push = handler as (status: TonoStatus) => void
      return () => {}
    })
    tonoStatusMock.mockResolvedValue(statusPayload('signedOut'))
    tonoSignInStartMock.mockResolvedValue({
      challengeId: 'ch-1',
      expiresIn: 600,
      message: 'sent',
    })

    // No scoped SWR provider here: the pushed status travels through the
    // global SWR mutate, so this test shares the default cache.
    render(
      <MemoryRouter initialEntries={['/login']}>
        <Routes>
          <Route
            path="/"
            element={<TonoAuthGuard>dashboard page</TonoAuthGuard>}
          />
          <Route
            path="/login"
            element={
              <TonoAuthGuard>
                <LoginPage />
              </TonoAuthGuard>
            }
          />
        </Routes>
      </MemoryRouter>,
    )

    // t() returns the key with no resources loaded.
    const emailInput = (await screen.findByPlaceholderText(
      'tono.login.emailPlaceholder',
    )) as HTMLInputElement
    fireEvent.change(emailInput, { target: { value: 'tester@example.com' } })
    fireEvent.click(
      screen.getByRole('button', { name: 'tono.login.sendCode' }),
    )

    await waitFor(() => expect(tonoSignInStartMock).toHaveBeenCalled())
    const codeInput = await screen.findByPlaceholderText(
      'tono.login.codePlaceholder',
    )
    expect(codeInput).toBeDefined()

    act(() => push?.(statusPayload('authenticating')))

    // The form — including the typed email and the code input — survives.
    expect(screen.queryByRole('progressbar')).toBeNull()
    expect(
      screen.getByRole('button', { name: 'tono.login.verify' }),
    ).toBeDefined()
    expect(
      (
        screen.getByPlaceholderText(
          'tono.login.emailPlaceholder',
        ) as HTMLInputElement
      ).value,
    ).toBe('tester@example.com')
    expect(
      screen.getByPlaceholderText('tono.login.codePlaceholder'),
    ).toBeDefined()
  })
})
