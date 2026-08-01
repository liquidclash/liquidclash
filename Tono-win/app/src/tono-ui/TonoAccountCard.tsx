import { useLockFn } from 'ahooks'
import dayjs from 'dayjs'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'

import {
  tonoAccountQueryKey,
  tonoDevicesQueryKey,
  tonoServersQueryKey,
  useTonoStatus,
} from '@/hooks/use-tono'
import { removeCacheData, useQuery } from '@/services/query-client'
import { useThemeMode } from '@/services/states'
import {
  tonoAccount,
  tonoDevices,
  tonoRevokeDevice,
  tonoSignOut,
  type TonoDevice,
} from '@/services/tono'
import { TONO_COLORS, tonoText } from '@/tono-ui/theme'

import { GlassCard } from './GlassCard'

/**
 * The Tono Account card: account email, the device list with revoke, and
 * sign-out. Embedded both by the Account page and at the top of Settings,
 * matching the macOS SettingsView account card.
 */
export const TonoAccountCard = () => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  const navigate = useNavigate()
  const { mutateTonoStatus } = useTonoStatus()

  const { data: account } = useQuery({
    queryKey: tonoAccountQueryKey,
    queryFn: tonoAccount,
  })
  const { data: devices, refetch: mutateDevices } = useQuery({
    queryKey: tonoDevicesQueryKey,
    queryFn: tonoDevices,
  })

  const [revokeTarget, setRevokeTarget] = useState<TonoDevice | null>(null)
  const [revokeError, setRevokeError] = useState<string | null>(null)
  const [signOutOpen, setSignOutOpen] = useState(false)
  const [signOutError, setSignOutError] = useState<string | null>(null)

  const handleRevoke = useLockFn(async () => {
    if (!revokeTarget) return
    setRevokeError(null)
    try {
      await tonoRevokeDevice(revokeTarget.id)
    } catch (error) {
      setRevokeError(error instanceof Error ? error.message : String(error))
      return
    }
    setRevokeTarget(null)
    await mutateDevices()
  })

  const handleSignOut = useLockFn(async () => {
    setSignOutError(null)
    try {
      await tonoSignOut()
    } catch (error) {
      // Sign-out is designed to be able to fail (the kill switch stays armed
      // when its release cannot be proven): keep the dialog open and show why.
      setSignOutError(error instanceof Error ? error.message : String(error))
      return
    }
    setSignOutOpen(false)
    // Drop account-scoped caches so the next sign-in never flashes the
    // previous account's email/devices/servers.
    removeCacheData(tonoAccountQueryKey)
    removeCacheData(tonoDevicesQueryKey)
    removeCacheData(tonoServersQueryKey)
    await mutateTonoStatus()
    navigate('/login', { replace: true })
  })

  const deviceList = devices ?? []

  return (
    <GlassCard padding={20}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 12,
        }}
      >
        <span style={{ fontSize: 15, fontWeight: 600, color: text.primary }}>
          {t('tono.settings.account')}
        </span>
        {account && (
          <span
            style={{
              fontSize: 11,
              fontWeight: 500,
              color: text.secondary,
              borderRadius: 8,
              padding: '3px 8px',
              background: dark
                ? 'rgba(255,255,255,0.08)'
                : 'rgba(20,22,30,0.06)',
            }}
          >
            {t('tono.account.deviceLimit', {
              count: deviceList.length,
              limit: account.deviceLimit,
            })}
          </span>
        )}
      </div>

      <div className="tono-row" style={{ borderTop: 'none' }}>
        <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <span style={{ fontSize: 13, fontWeight: 500, color: text.primary }}>
            {t('tono.account.email')}
          </span>
          <span style={{ fontSize: 11, color: text.secondary }}>
            {account?.email ?? '—'}
          </span>
        </span>
      </div>

      {deviceList.map((device) => (
        <div className="tono-row" key={device.id}>
          <span style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
            <span
              style={{
                fontSize: 13,
                fontWeight: 500,
                color: text.primary,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {device.name}
              {device.current && (
                <span
                  style={{
                    marginLeft: 6,
                    fontSize: 10,
                    fontWeight: 600,
                    color: TONO_COLORS.accent,
                  }}
                >
                  {t('tono.account.currentDevice')}
                </span>
              )}
            </span>
            {device.createdAt != null && (
              <span style={{ fontSize: 11, color: text.secondary }}>
                {dayjs(device.createdAt * 1000).format('YYYY-MM-DD HH:mm')}
              </span>
            )}
          </span>
          {!device.current && (
            <button
              type="button"
              className="tono-link"
              style={{ fontSize: 12, color: TONO_COLORS.error, flexShrink: 0 }}
              onClick={() => {
                setRevokeError(null)
                setRevokeTarget(device)
              }}
            >
              {t('tono.account.revoke')}
            </button>
          )}
        </div>
      ))}

      <div style={{ marginTop: 14 }}>
        <button
          type="button"
          className="tono-button"
          style={{
            padding: '8px 16px',
            fontSize: 12,
            color: '#fff',
            background: TONO_COLORS.error,
          }}
          onClick={() => {
            setSignOutError(null)
            setSignOutOpen(true)
          }}
        >
          {t('tono.account.signOut')}
        </button>
      </div>

      {/* Revoke confirm */}
      {revokeTarget && (
        <TonoConfirmDialog
          dark={dark}
          title={t('tono.account.revokeConfirmTitle')}
          message={t('tono.account.revokeConfirmMessage', {
            name: revokeTarget.name,
          })}
          error={revokeError}
          confirmLabel={t('shared.actions.confirm')}
          cancelLabel={t('shared.actions.cancel')}
          onConfirm={handleRevoke}
          onCancel={() => setRevokeTarget(null)}
        />
      )}

      {/* Sign-out confirm */}
      {signOutOpen && (
        <TonoConfirmDialog
          dark={dark}
          title={t('tono.account.signOutConfirmTitle')}
          message={t('tono.account.signOutConfirmMessage')}
          error={signOutError}
          confirmLabel={t('tono.account.signOut')}
          cancelLabel={t('shared.actions.cancel')}
          onConfirm={handleSignOut}
          onCancel={() => setSignOutOpen(false)}
        />
      )}
    </GlassCard>
  )
}

interface ConfirmDialogProps {
  dark: boolean
  title: string
  message: string
  error?: string | null
  confirmLabel: string
  cancelLabel: string
  onConfirm: () => void
  onCancel: () => void
}

export const TonoConfirmDialog = ({
  dark,
  title,
  message,
  error,
  confirmLabel,
  cancelLabel,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) => {
  const text = tonoText(dark)
  return (
    <div
      role="dialog"
      aria-label={title}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 100,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(0,0,0,0.35)',
      }}
      onClick={onCancel}
    >
      <div
        style={{
          width: 340,
          borderRadius: 16,
          padding: 20,
          background: dark ? '#23242c' : '#ffffff',
          boxShadow: '0 12px 40px rgba(0,0,0,0.35)',
        }}
        onClick={(event) => event.stopPropagation()}
      >
        <div style={{ fontSize: 15, fontWeight: 600, color: text.primary, marginBottom: 8 }}>
          {title}
        </div>
        <div style={{ fontSize: 13, color: text.secondary, marginBottom: 12 }}>
          {message}
        </div>
        {error && (
          <div
            role="alert"
            style={{
              fontSize: 12,
              color: TONO_COLORS.error,
              borderRadius: 8,
              padding: '8px 10px',
              background: `${TONO_COLORS.error}1F`,
              marginBottom: 12,
            }}
          >
            {error}
          </div>
        )}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button
            type="button"
            className="tono-button"
            style={{
              padding: '7px 14px',
              fontSize: 12,
              color: text.primary,
              background: dark ? 'rgba(255,255,255,0.1)' : 'rgba(20,22,30,0.08)',
            }}
            onClick={onCancel}
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            className="tono-button"
            style={{
              padding: '7px 14px',
              fontSize: 12,
              color: '#fff',
              background: TONO_COLORS.error,
            }}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
