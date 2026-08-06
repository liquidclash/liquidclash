import ContentCopyRoundedIcon from '@mui/icons-material/ContentCopyRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { showNotice } from '@/services/notice-service'
import { useQuery } from '@/services/query-client'
import { useThemeMode } from '@/services/states'
import {
  formatTonoActionError,
  formatTonoDiagnostics,
  tonoAuditLogPath,
  tonoDiagnosticsReport,
  tonoUploadDiagnostics,
  type TonoDiagnosticsReport,
} from '@/services/tono'
import { GlassCard } from '@/tono-ui/GlassCard'
import { TONO_COLORS, TONO_MONO_STACK, tonoText } from '@/tono-ui/theme'
import { TonoConfirmDialog } from '@/tono-ui/TonoAccountCard'

const diagnosticsQueryKey = ['tonoDiagnosticsReport'] as const
const auditLogPathQueryKey = ['tonoAuditLogPath'] as const

type UploadPhase = 'idle' | 'confirming' | 'uploading' | 'sent'

const valueOrUnknown = (value: string | null) => value ?? '—'

const boolStatus = (
  value: boolean | null,
  enabled: string,
  disabled: string,
) => (value == null ? '—' : value ? enabled : disabled)

const protectionSummary = (
  report: TonoDiagnosticsReport,
  enabled: string,
  disabled: string,
) => {
  if (report.killSwitchMode == null) return '—'
  const live = boolStatus(report.killSwitchLive, enabled, disabled)
  return `${report.killSwitchMode} · ${live}`
}

const SummaryRow = ({
  label,
  value,
  monospace = false,
}: {
  label: string
  value: string
  monospace?: boolean
}) => {
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(120px, 0.7fr) minmax(0, 1.3fr)',
        gap: 16,
        padding: '10px 0',
        borderBottom: `1px solid ${dark ? 'rgba(255,255,255,0.07)' : 'rgba(35,48,78,0.07)'}`,
      }}
    >
      <span style={{ fontSize: 12, color: text.secondary }}>{label}</span>
      <span
        style={{
          fontSize: 12,
          color: text.primary,
          fontFamily: monospace ? TONO_MONO_STACK : undefined,
          overflowWrap: 'anywhere',
          userSelect: 'text',
        }}
      >
        {value}
      </span>
    </div>
  )
}

const SupportPage = () => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  const [uploadPhase, setUploadPhase] = useState<UploadPhase>('idle')
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [referenceCode, setReferenceCode] = useState<string | null>(null)
  const [codeCopied, setCodeCopied] = useState(false)

  const {
    data: report,
    error: reportError,
    isLoading,
    refetch: refreshReport,
  } = useQuery({
    queryKey: diagnosticsQueryKey,
    queryFn: tonoDiagnosticsReport,
    retry: false,
    refetchOnWindowFocus: true,
  })
  const { data: auditLogInfo, error: auditPathError } = useQuery({
    queryKey: auditLogPathQueryKey,
    queryFn: tonoAuditLogPath,
    retry: false,
  })

  const handleCopyDetails = useLockFn(async () => {
    try {
      const { data } = await refreshReport()
      if (!data) throw new Error('Diagnostics report unavailable')
      await navigator.clipboard.writeText(formatTonoDiagnostics(data))
      showNotice.success('tono.support.detailsCopied')
    } catch (error) {
      console.warn('[Support] copy diagnostics failed:', error)
      showNotice.error('tono.support.copyFailed')
    }
  })

  const handleCopyAuditPath = useLockFn(async () => {
    if (!auditLogInfo?.path) return
    try {
      await navigator.clipboard.writeText(auditLogInfo.path)
      showNotice.success('tono.support.auditPathCopied')
    } catch (error) {
      console.warn('[Support] copy audit path failed:', error)
      showNotice.error('tono.support.copyFailed')
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
      setUploadPhase('confirming')
    }
  })

  const handleCopyCode = useLockFn(async () => {
    if (!referenceCode) return
    try {
      await navigator.clipboard.writeText(referenceCode)
      setCodeCopied(true)
    } catch (error) {
      console.warn('[Support] copy reference code failed:', error)
      showNotice.error('tono.support.copyFailed')
    }
  })

  const lastError = report
    ? (report.error ??
      report.killSwitchLastError ??
      report.dnsLastError ??
      t('tono.support.none'))
    : '—'
  const secondaryBackground = dark
    ? 'rgba(255,255,255,0.07)'
    : 'rgba(235,240,250,0.72)'
  const secondaryBorder = `1px solid ${
    dark ? 'rgba(255,255,255,0.1)' : 'rgba(56,72,108,0.1)'
  }`
  const buttonStyle = {
    padding: '9px 14px',
    fontSize: 12,
    color: text.primary,
    background: secondaryBackground,
    border: secondaryBorder,
  } as const

  return (
    <div className="tono-page">
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 18,
        }}
      >
        <div>
          <h1 className="tono-page-title" style={{ color: text.primary }}>
            {t('tono.support.title')}
          </h1>
          <p style={{ margin: '6px 0 0', fontSize: 12, color: text.secondary }}>
            {t('tono.support.subtitle')}
          </p>
        </div>
        <button
          type="button"
          className="tono-button"
          onClick={() => void refreshReport()}
          disabled={isLoading}
          style={buttonStyle}
        >
          <RefreshRoundedIcon style={{ fontSize: 15 }} />
          {t('tono.support.refresh')}
        </button>
      </div>

      <div style={{ display: 'grid', gap: 14, maxWidth: 680 }}>
        <GlassCard radius={18} padding={18}>
          <h2 style={{ margin: '0 0 6px', fontSize: 14, color: text.primary }}>
            {t('tono.support.summary.title')}
          </h2>
          {reportError && (
            <p role="alert" style={{ fontSize: 12, color: TONO_COLORS.error }}>
              {t('tono.support.loadFailed')}
            </p>
          )}
          <SummaryRow
            label={t('tono.support.summary.app')}
            value={
              report ? `Tono ${report.appVersion} · ${report.osVersion}` : '—'
            }
          />
          <SummaryRow
            label={t('tono.support.summary.service')}
            value={
              report
                ? `${valueOrUnknown(report.serviceProtocol)}${report.serviceBuild ? ` · ${report.serviceBuild}` : ''}`
                : '—'
            }
          />
          <SummaryRow
            label={t('tono.support.summary.protection')}
            value={
              report
                ? protectionSummary(
                    report,
                    t('tono.support.enabled'),
                    t('tono.support.disabled'),
                  )
                : '—'
            }
          />
          <SummaryRow
            label={t('tono.support.summary.dns')}
            value={
              report
                ? boolStatus(
                    report.dnsEnabled,
                    t('tono.support.enabled'),
                    t('tono.support.disabled'),
                  )
                : '—'
            }
          />
          <SummaryRow
            label={t('tono.support.summary.node')}
            value={report ? valueOrUnknown(report.selectedServer) : '—'}
          />
          <SummaryRow
            label={t('tono.support.summary.lastError')}
            value={lastError}
            monospace
          />
        </GlassCard>

        <GlassCard radius={18} padding={18}>
          <h2 style={{ margin: '0 0 6px', fontSize: 14, color: text.primary }}>
            {t('tono.support.audit.title')}
          </h2>
          <p
            style={{ margin: '0 0 12px', fontSize: 12, color: text.secondary }}
          >
            {t('tono.support.audit.description')}
          </p>
          {auditPathError && (
            <p role="alert" style={{ fontSize: 12, color: TONO_COLORS.error }}>
              {t('tono.support.audit.loadFailed')}
            </p>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <code
              data-testid="tono-support-audit-path"
              style={{
                flex: 1,
                minWidth: 0,
                padding: '9px 11px',
                borderRadius: 9,
                fontSize: 11,
                color: text.primary,
                background: secondaryBackground,
                overflowWrap: 'anywhere',
                userSelect: 'text',
              }}
            >
              {auditLogInfo?.path ?? '—'}
            </code>
            <button
              type="button"
              className="tono-button"
              aria-label={t('tono.support.audit.copyPath')}
              disabled={!auditLogInfo?.path}
              onClick={handleCopyAuditPath}
              style={buttonStyle}
            >
              <ContentCopyRoundedIcon style={{ fontSize: 15 }} />
              {t('tono.support.audit.copyPath')}
            </button>
          </div>
        </GlassCard>

        <GlassCard radius={18} padding={18}>
          <h2 style={{ margin: '0 0 6px', fontSize: 14, color: text.primary }}>
            {t('tono.support.diagnostics.title')}
          </h2>
          <p
            style={{ margin: '0 0 14px', fontSize: 12, color: text.secondary }}
          >
            {t('tono.support.diagnostics.description')}
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            <button
              type="button"
              className="tono-button"
              onClick={handleCopyDetails}
              disabled={!report}
              style={buttonStyle}
            >
              {t('tono.progress.copyDetails')}
            </button>
            {referenceCode == null && (
              <button
                type="button"
                className="tono-button"
                data-testid="tono-support-upload-diagnostics"
                onClick={() => {
                  setUploadError(null)
                  setUploadPhase('confirming')
                }}
                disabled={uploadPhase === 'uploading'}
                style={{
                  ...buttonStyle,
                  opacity: uploadPhase === 'uploading' ? 0.6 : 1,
                }}
              >
                {uploadPhase === 'uploading'
                  ? t('tono.progress.upload.uploading')
                  : t('tono.progress.upload.action')}
              </button>
            )}
          </div>

          {referenceCode != null && (
            <div
              data-testid="tono-support-upload-reference"
              style={{
                marginTop: 12,
                padding: '10px 12px',
                borderRadius: 10,
                background: `${TONO_COLORS.latencyGood}1F`,
              }}
            >
              <div
                style={{ fontSize: 11, color: text.secondary, marginBottom: 6 }}
              >
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
                  }}
                >
                  {referenceCode}
                </code>
                <button
                  type="button"
                  className="tono-button"
                  onClick={handleCopyCode}
                  style={buttonStyle}
                >
                  {codeCopied
                    ? t('tono.progress.upload.codeCopied')
                    : t('tono.progress.upload.copyCode')}
                </button>
              </div>
            </div>
          )}
        </GlassCard>
      </div>

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
            if (uploadPhase !== 'uploading') setUploadPhase('idle')
          }}
        />
      )}
    </div>
  )
}

export default SupportPage
