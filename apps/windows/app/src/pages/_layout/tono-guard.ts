import type { TonoStatus } from '@/services/tono'

export type TonoGuardAction = 'loading' | 'toLogin' | 'toHome' | null

/**
 * The Tono auth guard decision, pure so it can be pinned by contract tests.
 *
 * - Status not yet read, or the backend mid-restore: nothing is decidable, the
 *   layout shows a loading placeholder instead of the full UI.
 * - No usable account (signedOut/suspended/error), or mid sign-in
 *   (`authenticating`): the login screen owns the UI. `authenticating` must NOT
 *   be treated as loading — the backend flips to it the moment a sign-in code
 *   is requested and stays there until verify, so swapping in a spinner would
 *   unmount the form (and the resend countdown) mid sign-in and deadlock the
 *   flow.
 * - Ready account on /login: pushed back to the dashboard.
 */
export const resolveTonoGuard = (
  status: TonoStatus | undefined,
  pathname: string,
): TonoGuardAction => {
  const accountState = status?.accountState

  if (!status || accountState === 'restoring') {
    return 'loading'
  }

  const loginOwned =
    accountState === 'signedOut' ||
    accountState === 'suspended' ||
    accountState === 'error' ||
    accountState === 'authenticating'
  if (loginOwned && pathname !== '/login') {
    return 'toLogin'
  }

  if (accountState === 'ready' && pathname === '/login') {
    return 'toHome'
  }

  return null
}
