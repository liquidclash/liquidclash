import { useLockFn } from 'ahooks'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { tonoConnectProgressQueryKey } from '@/hooks/use-tono'
import { showNotice } from '@/services/notice-service'
import { useQuery } from '@/services/query-client'
import { useThemeMode } from '@/services/states'
import {
  formatTonoActionError,
  formatTonoDiagnostics,
  formatTonoElapsed,
  subscribeTonoStatus,
  tonoConnectProgress,
  tonoDiagnosticsReport,
  tonoDisconnect,
  tonoRetryNow,
  tonoUploadDiagnostics,
  type TonoConnectStep,
  type TonoUiState,
} from '@/services/tono'
import { GlassCard } from '@/tono-ui/GlassCard'
import { TONO_COLORS, TONO_MONO_STACK, tonoText } from '@/tono-ui/theme'
import { TonoConfirmDialog } from '@/tono-ui/TonoAccountCard'

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

/** "Xs or X.Xs" per the Mac format (shared with the diagnostics renderer). */
const formatElapsed = formatTonoElapsed

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
  onRefreshStatus: () => Promise<unknown>
}

/**
 * The diagnostics upload is strictly user-initiated: idle → the user reads
 * what will be sent → confirms → one in-flight request → a reference code
 * that replaces the button. There is no path back to `idle` from `sent`
 * without remounting the card, which is the client half of the abuse
 * defence: the button cannot be pressed twice in a row, and cannot be held
 * down while a request is in flight.
 */
type UploadPhase = 'idle' | 'confirming' | 'uploading' | 'sent'

export const ConnectProgressCard = ({
  uiState,
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
  const [uploadPhase, setUploadPhase] = useState<UploadPhase>('idle')
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [referenceCode, setReferenceCode] = useState<string | null>(null)
  const [codeCopied, setCodeCopied] = useState(false)

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

  // Copy details renders the *same* structured report the upload sends
  // (`tono_diagnostics_report` is the local, nothing-leaves-the-machine half
  // of `tono_upload_diagnostics`), so the two can never disagree about what
  // the payload contains — which is what makes the disclosure below honest.
  const handleCopyDetails = useLockFn(async () => {
    let text: string
    try {
      text = formatTonoDiagnostics(await tonoDiagnosticsReport())
    } catch (error) {
      console.warn('[ConnectProgress] diagnostics report failed:', error)
      showNotice.error('tono.progress.copyFailed')
      return
    }
    try {
      await navigator.clipboard.writeText(text)
      showNotice.success('tono.progress.copied')
    } catch (error) {
      console.warn('[ConnectProgress] copy to clipboard failed:', error)
      showNotice.error('tono.progress.copyFailed')
    }
  })

  const handleUpload = useLockFn(async () => {
    setUploadPhase('uploading')
    setUploadError(null)
    try {
      const receipt = await tonoUploadDiagnostics()
      setReferenceCode(receipt.referenceCode)
      setUploadPhase('sent')
    } catch (error) {
      setUploadError(formatTonoActionError(error, t))
      // Back to the confirm dialog, which keeps the error visible next to the
      // action that produced it and lets the user retry deliberately.
      setUploadPhase('confirming')
    }
  })

  const handleCopyCode = useLockFn(async () => {
    if (!referenceCode) return
    try {
      await navigator.clipboard.writeText(referenceCode)
      setCodeCopied(true)
    } catch (error) {
      console.warn('[ConnectProgress] copy reference code failed:', error)
      showNotice.error('tono.progress.copyFailed')
    }
  })

  const visible = active || progress?.error != null
  if (!visible || !progress) {
    return null
  }

  const secondaryBackground = dark
    ? 'rgba(255,255,255,0.07)'
    : 'rgba(235,240,250,0.72)'
  const secondaryBorder = `1px solid ${
    dark ? 'rgba(255,255,255,0.1)' : 'rgba(56,72,108,0.1)'
  }`

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
          flexWrap: 'wrap',
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
              // The escape hatch keeps the full row; the two diagnostics
              // actions share the next one.
              flexBasis: '100%',
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
            flex: 1,
            padding: '9px 14px',
            fontSize: 12,
            color: text.primary,
            background: secondaryBackground,
            border: secondaryBorder,
          }}
        >
          {t('tono.progress.copyDetails')}
        </button>
        {referenceCode == null && (
          <button
            type="button"
            className="tono-button"
            data-testid="tono-upload-diagnostics"
            onClick={() => {
              setUploadError(null)
              setUploadPhase('confirming')
            }}
            // In flight: no second request, no queue of confirmations.
            disabled={uploadPhase === 'uploading'}
            style={{
              flex: 1,
              padding: '9px 14px',
              fontSize: 12,
              color: text.primary,
              background: secondaryBackground,
              border: secondaryBorder,
              opacity: uploadPhase === 'uploading' ? 0.6 : 1,
            }}
          >
            {uploadPhase === 'uploading'
              ? t('tono.progress.upload.uploading')
              : t('tono.progress.upload.action')}
          </button>
        )}
      </div>

      {/* The receipt replaces the button: after a successful upload the user
          is given a code to quote, not another chance to press send. */}
      {referenceCode != null && (
        <div
          data-testid="tono-upload-reference"
          style={{
            marginTop: 12,
            padding: '10px 12px',
            borderRadius: 10,
            background: hex(TONO_COLORS.latencyGood, 0.12),
          }}
        >
          <div style={{ fontSize: 11, color: text.secondary, marginBottom: 6 }}>
            {t('tono.progress.upload.successHint')}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <code
              style={{
                flex: 1,
                fontSize: 15,
                fontWeight: 700,
                letterSpacing: 1,
                fontFamily: TONO_MONO_STACK,
                color: text.primary,
                userSelect: 'text',
                wordBreak: 'break-all',
              }}
            >
              {referenceCode}
            </code>
            <button
              type="button"
              className="tono-button"
              onClick={handleCopyCode}
              style={{
                padding: '6px 12px',
                fontSize: 12,
                flexShrink: 0,
                color: text.primary,
                background: secondaryBackground,
                border: secondaryBorder,
              }}
            >
              {codeCopied
                ? t('tono.progress.upload.codeCopied')
                : t('tono.progress.upload.copyCode')}
            </button>
          </div>
        </div>
      )}

      {/* What will be sent, before it is sent. */}
      {(uploadPhase === 'confirming' || uploadPhase === 'uploading') && (
        <TonoConfirmDialog
          dark={dark}
          title={t('tono.progress.upload.confirmTitle')}
          message={t('tono.progress.upload.confirmMessage')}
          error={uploadError}
          confirmLabel={
            uploadPhase === 'uploading'
              ? t('tono.progress.upload.uploading')
              : t('tono.progress.upload.confirmSend')
          }
          cancelLabel={t('shared.actions.cancel')}
          onConfirm={handleUpload}
          onCancel={() => {
            if (uploadPhase === 'uploading') return
            setUploadPhase('idle')
          }}
        />
      )}

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
