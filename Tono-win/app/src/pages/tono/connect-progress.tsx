import { useLockFn } from 'ahooks'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { tonoConnectProgressQueryKey } from '@/hooks/use-tono'
import { showNotice } from '@/services/notice-service'
import { useQuery } from '@/services/query-client'
import { useThemeMode } from '@/services/states'
import {
  formatTonoActionError,
  subscribeTonoStatus,
  tonoAuditLogPath,
  tonoConnectProgress,
  tonoDisconnect,
  tonoRetryNow,
  type TonoConnectStep,
  type TonoKillSwitch,
  type TonoUiState,
} from '@/services/tono'
import { GlassCard } from '@/tono-ui/GlassCard'
import { TONO_COLORS, TONO_MONO_STACK, tonoText } from '@/tono-ui/theme'
import { TonoConfirmDialog } from '@/tono-ui/TonoAccountCard'
import { version } from '@root/package.json'

/**
 * The connect-progress card (Mac Build 29 parity): the eight FSM stages with
 * per-stage state and elapsed time, retry countdown + Retry Now, the
 * standalone Restore Normal Internet escape hatch, and Copy details for
 * diagnostics. Visible while connecting / protectedOffline, or whenever an
 * uncleared failure record exists.
 */

const STEP_LABEL_KEYS: Record<string, string> = {
  preparing: 'tono.progress.steps.preparing',
  preparingService: 'tono.progress.steps.preparingService',
  startingKillSwitch: 'tono.progress.steps.startingKillSwitch',
  startingTunnel: 'tono.progress.steps.startingTunnel',
  lockingTraffic: 'tono.progress.steps.lockingTraffic',
  applyingCloudPolicy: 'tono.progress.steps.applyingCloudPolicy',
  securingDNS: 'tono.progress.steps.securingDNS',
  checkingExit: 'tono.progress.steps.checkingExit',
  verifyingTraffic: 'tono.progress.steps.verifyingTraffic',
}

const hex = (color: string, alpha: number) =>
  `${color}${Math.round(alpha * 255)
    .toString(16)
    .padStart(2, '0')
    .toUpperCase()}`

/** "Xs or X.Xs" per the Mac format. */
const formatElapsed = (ms: number) =>
  ms >= 10000 ? `${Math.round(ms / 1000)}s` : `${(ms / 1000).toFixed(1)}s`

const useConnectProgress = (active: boolean) => {
  const { data: progress, refetch } = useQuery({
    queryKey: tonoConnectProgressQueryKey,
    queryFn: tonoConnectProgress,
    // 2s polling only while a transaction is live; status pushes (below)
    // cover the transitions in between.
    refetchInterval: active ? 2000 : false,
  })

  const refetchRef = useRef(refetch)
  useEffect(() => {
    refetchRef.current = refetch
  })
  // Every status push refetches unconditionally. A gate on "idle with no
  // failure record" looks tempting, but any ref-based idleness snapshot lags
  // the pushes by a React commit: a connect that fails pre-arm within
  // milliseconds emits `connecting` and the terminal failure push back to
  // back, both land before the ref updates, and the uncleared failure record
  // then stays invisible with no polling or focus revalidation to recover it.
  useEffect(() => subscribeTonoStatus(() => void refetchRef.current()), [])

  return progress
}

const StepIcon = ({ state }: { state: TonoConnectStep['state'] }) => {
  if (state === 'current') {
    return (
      <span
        aria-hidden
        className="tono-spin"
        data-testid="tono-step-icon"
        data-state="current"
        style={{
          width: 12,
          height: 12,
          borderRadius: '50%',
          border: `1.5px solid ${hex(TONO_COLORS.accent, 0.35)}`,
          borderTopColor: TONO_COLORS.accent,
          flexShrink: 0,
        }}
      />
    )
  }
  const color =
    state === 'completed'
      ? TONO_COLORS.latencyGood
      : state === 'failed'
        ? TONO_COLORS.protectedOffline
        : 'rgba(142,142,147,0.5)'
  return (
    <span
      aria-hidden
      data-testid="tono-step-icon"
      data-state={state}
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: 12,
        height: 12,
        borderRadius: '50%',
        flexShrink: 0,
        fontSize: 9,
        fontWeight: 700,
        color: '#fff',
        background: color,
      }}
    >
      {state === 'completed' ? '✓' : state === 'failed' ? '✕' : ''}
    </span>
  )
}

interface ConnectProgressCardProps {
  uiState: TonoUiState
  selectedServer: string | null
  killSwitch: TonoKillSwitch | null
  onRefreshStatus: () => Promise<unknown>
}

export const ConnectProgressCard = ({
  uiState,
  selectedServer,
  killSwitch,
  onRefreshStatus,
}: ConnectProgressCardProps) => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)

  const active = uiState === 'connecting' || uiState === 'protectedOffline'
  const progress = useConnectProgress(active)

  const [retryError, setRetryError] = useState<string | null>(null)
  const [retrying, setRetrying] = useState(false)
  const [restoreOpen, setRestoreOpen] = useState(false)
  const [restoreError, setRestoreError] = useState<string | null>(null)
  const [nowMs, setNowMs] = useState(() => Date.now())

  const nextRetryAtMs = progress?.nextRetryAtMs ?? null

  useEffect(() => {
    if (nextRetryAtMs == null) return
    const id = window.setInterval(() => setNowMs(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [nextRetryAtMs])

  const handleRetryNow = useLockFn(async () => {
    setRetrying(true)
    setRetryError(null)
    try {
      await tonoRetryNow()
      await onRefreshStatus()
    } catch (error) {
      setRetryError(formatTonoActionError(error, t))
    } finally {
      setRetrying(false)
    }
  })

  const handleRestore = useLockFn(async () => {
    setRestoreError(null)
    try {
      await tonoDisconnect()
    } catch (error) {
      setRestoreError(formatTonoActionError(error, t))
      return
    }
    setRestoreOpen(false)
    await onRefreshStatus()
  })

  const handleCopyDetails = useLockFn(async () => {
    const logPath = await tonoAuditLogPath()
      .then((info) => info.path)
      .catch(() => '(unavailable)')
    const lines = [
      `Tono v${version} diagnostics`,
      `Server: ${selectedServer ?? '(none)'}`,
      `UI state: ${uiState}`,
      `Kill switch: ${
        killSwitch
          ? !killSwitch.wanted && !killSwitch.live
            ? `inactive (reported mode=${killSwitch.mode}, wanted=false, live=false)`
            : `${killSwitch.mode} (wanted=${killSwitch.wanted}, live=${killSwitch.live})`
          : '(unknown)'
      }`,
      `Failed stage: ${progress?.failedStage ?? '(none)'}`,
      `Error: ${progress?.error ?? '(none)'}`,
      `Retry attempt: ${progress?.retryAttempt ?? 0}`,
      `Total elapsed: ${
        progress?.totalElapsedMs != null
          ? formatElapsed(progress.totalElapsedMs)
          : '(n/a)'
      }`,
      'Steps:',
      ...(progress?.steps ?? []).map(
        (step) =>
          `  - ${step.key}: ${step.state}${
            step.elapsedMs != null ? ` (${formatElapsed(step.elapsedMs)})` : ''
          }`,
      ),
      `Audit log: ${logPath}`,
    ]
    try {
      await navigator.clipboard.writeText(lines.join('\n'))
      showNotice.success('tono.progress.copied')
    } catch (error) {
      console.warn('[ConnectProgress] copy to clipboard failed:', error)
      showNotice.error('tono.progress.copyFailed')
    }
  })

  const visible = active || progress?.error != null
  if (!visible || !progress) {
    return null
  }

  const remainSec =
    nextRetryAtMs != null
      ? Math.max(0, Math.ceil((nextRetryAtMs - nowMs) / 1000))
      : null
  const failedStepLabel = progress.failedStage
    ? t(STEP_LABEL_KEYS[progress.failedStage] ?? 'tono.progress.unknownStage')
    : null

  return (
    <GlassCard
      radius={18}
      padding={18}
      style={{
        width: 520,
        maxWidth: '100%',
      }}
    >
      {/* Header: total elapsed + retry badge */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 14,
        }}
      >
        <span
          style={{
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: 0.2,
            fontFamily: TONO_MONO_STACK,
            color: text.tertiary,
          }}
        >
          {t('tono.progress.total', {
            elapsed:
              progress.totalElapsedMs != null
                ? formatElapsed(progress.totalElapsedMs)
                : '—',
          })}
        </span>
        {progress.retryAttempt > 0 && (
          <span
            style={{
              fontSize: 11,
              fontWeight: 600,
              fontFamily: TONO_MONO_STACK,
              borderRadius: 6,
              padding: '3px 8px',
              color: TONO_COLORS.protectedOffline,
              background: hex(TONO_COLORS.protectedOffline, 0.15),
            }}
          >
            {t('tono.progress.tryBadge', { count: progress.retryAttempt + 1 })}
          </span>
        )}
      </div>

      {/* Steps */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '10px 18px',
        }}
      >
        {progress.steps.map((step) => (
          <div
            key={step.key}
            data-testid={`tono-step-${step.key}`}
            data-state={step.state}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 7,
              minWidth: 0,
            }}
          >
            <StepIcon state={step.state} />
            <span
              style={{
                flex: 1,
                fontSize: 12,
                fontWeight: step.state === 'current' ? 600 : 400,
                color:
                  step.state === 'pending'
                    ? text.tertiary
                    : step.state === 'failed'
                      ? TONO_COLORS.protectedOffline
                      : text.primary,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {t(STEP_LABEL_KEYS[step.key] ?? 'tono.progress.unknownStage')}
            </span>
            {(step.state === 'current' || step.state === 'failed') &&
              step.elapsedMs != null && (
                <span
                  style={{
                    fontSize: 11,
                    fontFamily: TONO_MONO_STACK,
                    color: text.secondary,
                    flexShrink: 0,
                  }}
                >
                  {formatElapsed(step.elapsedMs)}
                </span>
              )}
          </div>
        ))}
      </div>

      {/* Failure block */}
      {progress.error != null && (
        <div style={{ marginTop: 14 }}>
          {failedStepLabel && (
            <div
              style={{
                fontSize: 12,
                fontWeight: 600,
                color: TONO_COLORS.error,
                marginBottom: 6,
              }}
            >
              {t('tono.progress.failedAt', { stage: failedStepLabel })}
            </div>
          )}
          <pre
            data-testid="tono-progress-error"
            style={{
              margin: 0,
              padding: '10px 12px',
              borderRadius: 10,
              fontSize: 11,
              fontFamily: TONO_MONO_STACK,
              lineHeight: 1.5,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              userSelect: 'text',
              color: TONO_COLORS.error,
              background: hex(TONO_COLORS.error, 0.1),
            }}
          >
            {formatTonoActionError(progress.error, t)}
          </pre>
        </div>
      )}

      {/* Retry countdown + actions */}
      {uiState === 'protectedOffline' && nextRetryAtMs != null && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            marginTop: 14,
          }}
        >
          <span
            data-testid="tono-retry-countdown"
            style={{ flex: 1, fontSize: 11, color: text.secondary }}
          >
            {remainSec != null && remainSec > 0
              ? t('tono.progress.retryIn', {
                  n: progress.retryAttempt + 1,
                  seconds: remainSec,
                })
              : t('tono.progress.retrying')}
          </span>
          <button
            type="button"
            className="tono-button"
            onClick={handleRetryNow}
            disabled={retrying}
            style={{
              padding: '7px 13px',
              fontSize: 12,
              color: '#fff',
              background: TONO_COLORS.accent,
            }}
          >
            {retrying ? '…' : t('tono.progress.retryNow')}
          </button>
        </div>
      )}
      {retryError && (
        <div
          role="alert"
          style={{ marginTop: 6, fontSize: 11, color: TONO_COLORS.error }}
        >
          {retryError}
        </div>
      )}

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginTop: 14,
        }}
      >
        {uiState === 'protectedOffline' && (
          <button
            type="button"
            className="tono-button"
            onClick={() => {
              setRestoreError(null)
              setRestoreOpen(true)
            }}
            style={{
              flex: 1,
              padding: '9px 14px',
              fontSize: 12,
              color: '#fff',
              background: TONO_COLORS.protectedOffline,
            }}
          >
            {t('tono.progress.restore')}
          </button>
        )}
        <button
          type="button"
          className="tono-button"
          onClick={handleCopyDetails}
          style={{
            flex: uiState === 'protectedOffline' ? undefined : 1,
            padding: '9px 14px',
            fontSize: 12,
            color: text.primary,
            background: dark
              ? 'rgba(255,255,255,0.07)'
              : 'rgba(235,240,250,0.72)',
            border: `1px solid ${dark ? 'rgba(255,255,255,0.1)' : 'rgba(56,72,108,0.1)'}`,
          }}
        >
          {t('tono.progress.copyDetails')}
        </button>
      </div>

      {restoreOpen && (
        <TonoConfirmDialog
          dark={dark}
          title={t('tono.progress.restoreConfirmTitle')}
          message={t('tono.progress.restoreConfirmMessage')}
          error={restoreError}
          confirmLabel={t('tono.progress.restore')}
          cancelLabel={t('shared.actions.cancel')}
          onConfirm={handleRestore}
          onCancel={() => setRestoreOpen(false)}
        />
      )}
    </GlassCard>
  )
}
