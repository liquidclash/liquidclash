import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

/**
 * Tono product IPC seam.
 *
 * The backend commands are implemented in Rust (`tono_*`); this module is the only place the
 * frontend spells those command/event names, and the only place the payload shapes are declared.
 */

export type TonoAccountState =
  | 'restoring'
  | 'signedOut'
  | 'authenticating'
  | 'ready'
  | 'suspended'
  | 'error'

export type TonoUiState =
  | 'notConnected'
  | 'connecting'
  | 'connected'
  | 'protectedOffline'
  | 'disconnecting'

export interface TonoSignInChallenge {
  challengeId: string
  expiresIn: number
  message: string
}

export interface TonoAccount {
  email: string
  suspended: boolean
  deviceLimit: number
}

export interface TonoDevice {
  id: string
  name: string
  createdAt: number | null
  current: boolean
}

export interface TonoServer {
  name: string
  server: string
  port: number
  selected: boolean
  /** False when the exit is known blocked (e.g. GFW); still listed for status. */
  available: boolean
}

export interface TonoCatalogStatus {
  revision: number | null
  nodeCount: number
  lastSyncedAtMs: number | null
  error: string | null
}

export interface TonoServerTestResult {
  name: string
  latencyMs: number | null
  error: string | null
}

export interface TonoKillSwitchEndpoint {
  ip: string
  port: number
  /** "tcp" | "udp" on the wire (snake_case `ProxyProtocol`). */
  protocol: string
}

export interface TonoKillSwitch {
  wanted: boolean
  live: boolean
  mode: string
  endpoints: TonoKillSwitchEndpoint[]
  // Nested DTO, not covered by the outer `rename_all = "camelCase"`:
  // `KillSwitchStatus` in the service crate carries no serde rename, so this
  // one field stays snake_case on the wire.
  last_error: string | null
}

export interface TonoStatus {
  accountState: TonoAccountState
  uiState: TonoUiState
  stage: string | null
  stageLabel: string | null
  selectedServer: string | null
  protectionBlocked: boolean
  killSwitch: TonoKillSwitch | null
  catalogRevision: number | null
  catalogRequiresChoice: boolean
  /** Monotonic owner token for the current managed controller endpoint. */
  controllerGeneration: number
}

export const TONO_STATUS_EVENT = 'tono://status'

const toError = (error: unknown): Error => {
  if (error instanceof Error) return error
  if (typeof error === 'string') return new Error(error)
  try {
    return new Error(JSON.stringify(error))
  } catch {
    return new Error(String(error))
  }
}

/** Stable Rust prefixes → i18n keys for Connect/Disconnect action errors. */
const STABLE_ERROR_KEYS: Array<{ prefix: string; key: string }> = [
  { prefix: 'TONO_SERVICE_BUSY', key: 'tono.dashboard.errors.serviceBusy' },
  {
    prefix: 'TONO_RELEASE_RECONCILING',
    key: 'tono.dashboard.errors.releaseReconciling',
  },
  {
    prefix: 'TONO_SERVICE_TOO_OLD',
    key: 'tono.dashboard.errors.serviceTooOld',
  },
  // Diagnostics upload (`diagnostics_upload_error` in tono/commands.rs).
  {
    prefix: 'TONO_DIAG_SIGNED_OUT',
    key: 'tono.progress.upload.errors.signedOut',
  },
  {
    prefix: 'TONO_DIAG_RATE_LIMITED',
    key: 'tono.progress.upload.errors.rateLimited',
  },
  {
    prefix: 'TONO_DIAG_UNREACHABLE',
    key: 'tono.progress.upload.errors.unreachable',
  },
  {
    prefix: 'TONO_DIAG_UNAVAILABLE',
    key: 'tono.progress.upload.errors.unavailable',
  },
  { prefix: 'TONO_DIAG_FAILED', key: 'tono.progress.upload.errors.failed' },
]

/**
 * Map backend error strings (including stable `TONO_*` prefixes) to a UI message.
 * Pass `t` from `useTranslation` when available; falls back to the raw string.
 */
export const formatTonoActionError = (
  error: unknown,
  t?: (key: string) => string,
): string => {
  const raw =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : String(error)
  for (const { prefix, key } of STABLE_ERROR_KEYS) {
    if (raw.startsWith(prefix) || raw.includes(`${prefix}:`)) {
      return t ? t(key) : raw
    }
  }
  return raw
}

/**
 * Whether a connect rejection means "no usable server is selected" — the
 * guard strings from the backend's `guard_snapshot` (no selection, selection
 * gone from the catalog, catalog not yet available). The dashboard answers
 * these by opening the server picker instead of printing an error the user
 * cannot act on from where they are.
 */
export const connectRejectionNeedsServerChoice = (error: unknown): boolean => {
  const raw = (
    error instanceof Error ? error.message : String(error ?? '')
  ).toLowerCase()
  return (
    raw.includes('select a server') ||
    raw.includes('pick a server') ||
    raw.includes('not in the catalog') ||
    raw.includes('catalog is not available')
  )
}

const call = <T>(command: string, args?: Record<string, unknown>): Promise<T> =>
  invoke<T>(command, args).catch((error: unknown) => {
    throw toError(error)
  })

export const tonoSignInStart = (email: string) =>
  call<TonoSignInChallenge>('tono_sign_in_start', { email })

export const tonoSignInVerify = (email: string, code: string) =>
  call<TonoAccount>('tono_sign_in_verify', { email, code })

export const tonoSignOut = () => call<void>('tono_sign_out')

export const tonoAccount = () => call<TonoAccount | null>('tono_account')

export const tonoDevices = () => call<TonoDevice[]>('tono_devices')

export const tonoRevokeDevice = (id: string) =>
  call<void>('tono_revoke_device', { id })

export const tonoServers = () => call<TonoServer[]>('tono_servers')

export const tonoCatalogStatus = () =>
  call<TonoCatalogStatus>('tono_catalog_status')

export const tonoRefreshCatalog = () =>
  call<TonoCatalogStatus>('tono_refresh_catalog')

export const tonoSelectServer = (name: string) =>
  call<void>('tono_select_server', { name })

export const tonoTestCurrentServer = () =>
  call<number>('tono_test_current_server')

export const tonoTestAvailableServers = () =>
  call<TonoServerTestResult[]>('tono_test_available_servers')

export const tonoCancelServerTests = () =>
  call<void>('tono_cancel_server_tests')

export const tonoConnect = () => call<void>('tono_connect')

export const tonoDisconnect = () => call<void>('tono_disconnect')

export const tonoStatus = () => call<TonoStatus>('tono_status')

export const tonoCloseConnection = (id: string, controllerGeneration: number) =>
  call<void>('tono_close_connection', { id, controllerGeneration })

export const tonoCloseAllConnections = (controllerGeneration: number) =>
  call<void>('tono_close_all_connections', { controllerGeneration })

export const tonoRetryRestore = () => call<void>('tono_retry_restore')

export const tonoAuditEnabled = () => call<boolean>('tono_audit_enabled')

export const tonoSetAuditEnabled = (enabled: boolean) =>
  call<void>('tono_set_audit_enabled', { enabled })

export interface TonoAuditLogInfo {
  path: string
  droppedCount: number
}

export const tonoAuditLogPath = () =>
  call<TonoAuditLogInfo>('tono_audit_log_path')

export type TonoConnectStepState =
  | 'pending'
  | 'current'
  | 'completed'
  | 'failed'

export interface TonoConnectStep {
  key: string
  label: string
  state: TonoConnectStepState
  elapsedMs: number | null
}

export interface TonoConnectProgress {
  steps: TonoConnectStep[]
  totalElapsedMs: number | null
  failedStage: string | null
  error: string | null
  retryAttempt: number
  nextRetryAtMs: number | null
}

export const tonoConnectProgress = () =>
  call<TonoConnectProgress>('tono_connect_progress')

export const tonoRetryNow = () => call<void>('tono_retry_now')

/** "Xs" or "X.Xs", the Mac diagnostics format. */
export const formatTonoElapsed = (ms: number) =>
  ms >= 10000 ? `${Math.round(ms / 1000)}s` : `${(ms / 1000).toFixed(1)}s`

// ---- Diagnostics (user-initiated upload) ----
//
// `TonoDiagnosticsReport` mirrors `tono_core::auth::DiagnosticsReport`, which
// is the single definition of the upload payload — see the wire-shape comment
// above it. The whole struct is a hand-written whitelist assembled in Rust;
// the WebView never contributes a field, and it never posts the report itself
// (`tono_upload_diagnostics` rebuilds it backend-side before sending).

export interface TonoDiagnosticsStep {
  key: string
  /** "pending" | "current" | "completed" | "failed" */
  state: string
  elapsedMs: number | null
}

export interface TonoDiagnosticsReport {
  schemaVersion: number
  reportedAtMs: number
  appVersion: string
  osVersion: string
  osArch: string
  serviceProtocol: string | null
  serviceBuild: string | null
  uiState: string
  accountState: string
  selectedServer: string | null
  catalogRevision: number | null
  killSwitchMode: string | null
  killSwitchWanted: boolean | null
  killSwitchLive: boolean | null
  killSwitchLastError: string | null
  dnsEnabled: boolean | null
  dnsLastError: string | null
  failedStage: string | null
  error: string | null
  retryAttempt: number
  totalElapsedMs: number | null
  steps: TonoDiagnosticsStep[]
  /** Fixed class tokens ("hyperV", "wsl", …), never adapter names. */
  virtualAdapters: string[]
  auditLogPath: string
  /** SYSTEM/Admins-only; the app cannot read it, only name it. */
  serviceLogPath: string
}

export interface TonoDiagnosticsReceipt {
  referenceCode: string
  receivedAt: number | null
}

/** The exact payload an upload would send. Local only — nothing is sent. */
export const tonoDiagnosticsReport = () =>
  call<TonoDiagnosticsReport>('tono_diagnostics_report')

/**
 * Upload one report and return its support reference code.
 *
 * Only ever called from an explicit user confirmation. There is no automatic,
 * silent, or on-crash caller, by design — this is a VPN.
 */
export const tonoUploadDiagnostics = () =>
  call<TonoDiagnosticsReceipt>('tono_upload_diagnostics')

/**
 * Render a report as the plain text "Copy details" puts on the clipboard.
 *
 * Deliberately the *same object* the upload sends, so what the user can read
 * and what leaves the machine can never drift apart.
 */
export const formatTonoDiagnostics = (
  report: TonoDiagnosticsReport,
): string => {
  const killSwitch =
    report.killSwitchMode == null
      ? '(unknown)'
      : report.killSwitchWanted === false && report.killSwitchLive === false
        ? `inactive (reported mode=${report.killSwitchMode}, wanted=false, live=false)`
        : `${report.killSwitchMode} (wanted=${report.killSwitchWanted}, live=${report.killSwitchLive})`
  return [
    `Tono v${report.appVersion} diagnostics`,
    `OS: ${report.osVersion} (${report.osArch})`,
    `Service protocol: ${report.serviceProtocol ?? '(unknown)'}${
      report.serviceBuild ? ` (build ${report.serviceBuild})` : ''
    }`,
    `Server: ${report.selectedServer ?? '(none)'}`,
    `UI state: ${report.uiState}`,
    `Account state: ${report.accountState}`,
    `Kill switch: ${killSwitch}`,
    `Kill switch last error: ${report.killSwitchLastError ?? '(none)'}`,
    `Protected DNS: ${
      report.dnsEnabled == null ? '(unknown)' : report.dnsEnabled
    }`,
    `DNS last error: ${report.dnsLastError ?? '(none)'}`,
    `Virtual adapters: ${
      report.virtualAdapters.length > 0
        ? report.virtualAdapters.join(', ')
        : '(none)'
    }`,
    `Failed stage: ${report.failedStage ?? '(none)'}`,
    `Error: ${report.error ?? '(none)'}`,
    `Retry attempt: ${report.retryAttempt}`,
    `Total elapsed: ${
      report.totalElapsedMs != null
        ? formatTonoElapsed(report.totalElapsedMs)
        : '(n/a)'
    }`,
    'Steps:',
    ...report.steps.map(
      (step) =>
        `  - ${step.key}: ${step.state}${
          step.elapsedMs != null
            ? ` (${formatTonoElapsed(step.elapsedMs)})`
            : ''
        }`,
    ),
    `Audit log: ${report.auditLogPath}`,
    `Service log (admin only): ${report.serviceLogPath}`,
  ].join('\n')
}

// One backend listener, shared by every subscriber (the layout guard plus the
// current page), reference-counted: the first subscriber registers it, the last
// teardown unlistens.
const statusHandlers = new Set<(status: TonoStatus) => void>()
const subscribedCallbacks = new Set<() => void>()
let sharedUnlisten: UnlistenFn | null = null
let sharedListenerLive = false
let sharedRegistration: Promise<void> | null = null

const ensureSharedListener = () => {
  if (sharedRegistration) return

  sharedRegistration = listen<TonoStatus>(TONO_STATUS_EVENT, ({ payload }) => {
    statusHandlers.forEach((handler) => handler(payload))
  })
    .then((unlisten) => {
      if (statusHandlers.size === 0) {
        // Everyone left while the registration was in flight: drop the
        // listener immediately rather than leak it.
        unlisten()
        return
      }
      sharedUnlisten = unlisten
      sharedListenerLive = true
      subscribedCallbacks.forEach((callback) => callback())
      subscribedCallbacks.clear()
    })
    .catch((error) => {
      console.error(
        `[tono] failed to subscribe to ${TONO_STATUS_EVENT}:`,
        error,
      )
    })
    .finally(() => {
      sharedRegistration = null
    })
}

/**
 * Subscribe to status pushes, returning the teardown.
 *
 * Registration is asynchronous, so it can resolve after the caller has already
 * torn down; that is tracked here rather than at each call site. `onSubscribed`
 * runs once the listener is live — re-read the status there to close the gap
 * between the first read and the registration, where a transition would
 * otherwise be missed.
 */
export const subscribeTonoStatus = (
  handler: (status: TonoStatus) => void,
  onSubscribed?: () => void,
): (() => void) => {
  statusHandlers.add(handler)
  if (onSubscribed) {
    if (sharedListenerLive) {
      onSubscribed()
    } else {
      subscribedCallbacks.add(onSubscribed)
    }
  }
  ensureSharedListener()

  return () => {
    statusHandlers.delete(handler)
    if (onSubscribed) {
      subscribedCallbacks.delete(onSubscribed)
    }
    if (statusHandlers.size === 0 && sharedUnlisten) {
      try {
        sharedUnlisten()
      } catch (error) {
        console.error('[tono] status subscription teardown failed:', error)
      }
      sharedUnlisten = null
      sharedListenerLive = false
    }
  }
}
