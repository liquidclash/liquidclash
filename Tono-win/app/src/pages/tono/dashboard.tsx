import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router'

import { useTonoStatus } from '@/hooks/use-tono'
import { useTrafficData } from '@/hooks/use-traffic-data'
import { useThemeMode } from '@/services/states'
import {
  formatTonoActionError,
  tonoConnect,
  tonoDisconnect,
} from '@/services/tono'
import { ConnectPill } from '@/tono-ui/ConnectPill'
import { GlassCard } from '@/tono-ui/GlassCard'
import {
  TONO_COLORS,
  TONO_MONO_STACK,
  TONO_SPRING,
  tonoText,
} from '@/tono-ui/theme'
import parseTraffic from '@/utils/parse-traffic'

import { ConnectProgressCard } from './connect-progress'
import { latencyColor, readNodeLatency } from './node-latency'
import { nodeFlag, nodeDisplayName } from './node-meta'

const LockIcon = ({ locked }: { locked: boolean }) => (
  <svg
    width="12"
    height="12"
    viewBox="0 0 24 24"
    fill="currentColor"
    aria-hidden
  >
    {locked ? (
      <path d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5zm-3 8V7a3 3 0 1 1 6 0v3H9z" />
    ) : (
      <path d="M12 2a5 5 0 0 1 5 5v2h-2V7a3 3 0 1 0-6 0v3h9a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1V7a5 5 0 0 1 5-5z" />
    )}
  </svg>
)

const hex = (color: string, alpha: number) =>
  `${color}${Math.round(alpha * 255)
    .toString(16)
    .padStart(2, '0')
    .toUpperCase()}`

const ActiveNodeCard = ({
  serverName,
  connected,
}: {
  serverName: string
  connected: boolean
}) => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  const navigate = useNavigate()
  const [latencyState, setLatencyState] = useState(() => ({
    name: serverName,
    latency: readNodeLatency(serverName),
  }))

  // Re-read latency when the selected node changes: adjusting state during
  // render is the sanctioned alternative to a sync setState inside an effect.
  if (latencyState.name !== serverName) {
    setLatencyState({ name: serverName, latency: readNodeLatency(serverName) })
  }
  const latency = latencyState.latency

  return (
    <GlassCard
      radius={18}
      padding={0}
      style={{
        width: 520,
        maxWidth: '100%',
        overflow: 'hidden',
        animation: `tono-card-in 0.5s ${TONO_SPRING}`,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '13px 16px 10px',
        }}
      >
        <span
          style={{
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: 0.15,
            color: text.secondary,
          }}
        >
          {connected
            ? t('tono.node.activeServer')
            : t('tono.node.selectedServer')}
        </span>
        <button
          type="button"
          className="tono-link"
          onClick={() => navigate('/servers')}
          style={{
            minHeight: 30,
            padding: '5px 9px',
            fontSize: 12,
            fontWeight: 600,
            color: dark ? '#A9B7FF' : '#3453D5',
            background: hex(TONO_COLORS.accent, dark ? 0.12 : 0.08),
          }}
        >
          {t('tono.node.switch')}
        </button>
      </div>

      <div style={{ padding: '0 10px 10px' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            borderRadius: 13,
            padding: '13px 15px',
            background: dark
              ? 'rgba(255,255,255,0.055)'
              : 'rgba(235,240,250,0.68)',
            border: `1px solid ${dark ? 'rgba(255,255,255,0.08)' : 'rgba(56,72,108,0.08)'}`,
          }}
        >
          <span
            aria-hidden
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 36,
              height: 36,
              borderRadius: 11,
              fontSize: 18,
              background: dark
                ? 'rgba(255,255,255,0.08)'
                : 'rgba(255,255,255,0.82)',
              flexShrink: 0,
            }}
          >
            {nodeFlag(serverName)}
          </span>
          <span
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: 1,
              flex: 1,
              minWidth: 0,
            }}
          >
            <span
              style={{
                fontSize: 14,
                fontWeight: 650,
                color: text.primary,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {nodeDisplayName(serverName)}
            </span>
            <span style={{ fontSize: 11, color: text.tertiary }}>
              {t('tono.node.group')}
            </span>
          </span>
          <span
            style={{
              fontSize: 11,
              fontWeight: 600,
              fontFamily: TONO_MONO_STACK,
              borderRadius: 8,
              padding: '5px 9px',
              color: latency !== null ? latencyColor(latency) : text.tertiary,
              background:
                latency !== null
                  ? hex(latencyColor(latency), 0.15)
                  : 'transparent',
            }}
          >
            {latency !== null ? `${latency}ms` : '—'}
          </span>
        </div>
      </div>
    </GlassCard>
  )
}

const InfoItem = ({
  label,
  value,
  valueColor,
}: {
  label: string
  value: string
  valueColor?: string
}) => {
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  return (
    <span
      style={{ display: 'flex', flexDirection: 'column', gap: 3, minWidth: 76 }}
    >
      <span
        style={{
          fontSize: 10,
          fontWeight: 600,
          letterSpacing: 0.2,
          color: text.tertiary,
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontSize: 12,
          fontWeight: 600,
          color: valueColor ?? text.primary,
          fontFamily: TONO_MONO_STACK,
        }}
      >
        {value}
      </span>
    </span>
  )
}

const DashboardPage = () => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  const { status, mutateTonoStatus } = useTonoStatus()
  const [actionError, setActionError] = useState<string | null>(null)

  const uiState = status?.uiState ?? 'notConnected'
  const connected = uiState === 'connected'

  const {
    response: { data: traffic },
  } = useTrafficData({ enabled: connected })

  const handleConnect = useLockFn(async () => {
    setActionError(null)
    try {
      await tonoConnect()
      await mutateTonoStatus()
    } catch (error) {
      setActionError(formatTonoActionError(error, t))
    }
  })

  const handleDisconnect = useLockFn(async () => {
    setActionError(null)
    try {
      await tonoDisconnect()
      await mutateTonoStatus()
    } catch (error) {
      setActionError(formatTonoActionError(error, t))
    }
  })

  const [up, upUnit] = parseTraffic(traffic?.up ?? 0)
  const [down, downUnit] = parseTraffic(traffic?.down ?? 0)

  return (
    <div className="tono-page tono-dashboard">
      {status?.catalogRequiresChoice && (
        <div
          style={{ display: 'flex', justifyContent: 'center', marginBottom: 8 }}
        >
          <Link
            to="/servers"
            style={{
              fontSize: 12,
              fontWeight: 500,
              color: TONO_COLORS.protectedOffline,
              borderRadius: 10,
              padding: '8px 12px',
              background: hex(TONO_COLORS.protectedOffline, 0.12),
              textDecoration: 'none',
            }}
          >
            {t('tono.dashboard.catalogRequiresChoice')}
          </Link>
        </div>
      )}
      {status?.killSwitch?.last_error && (
        <div
          style={{ display: 'flex', justifyContent: 'center', marginBottom: 8 }}
        >
          <span
            style={{
              fontSize: 13,
              fontWeight: 500,
              color: TONO_COLORS.error,
              borderRadius: 10,
              padding: '8px 12px',
              background: hex(TONO_COLORS.error, 0.12),
            }}
          >
            {t('tono.dashboard.killSwitchError', {
              message: status.killSwitch.last_error,
            })}{' '}
            <span style={{ opacity: 0.7 }}>
              {t('tono.dashboard.killSwitchErrorNote')}
            </span>
          </span>
        </div>
      )}
      {actionError && (
        <div
          style={{ display: 'flex', justifyContent: 'center', marginBottom: 8 }}
        >
          <span
            style={{
              fontSize: 13,
              fontWeight: 500,
              color: TONO_COLORS.error,
              borderRadius: 10,
              padding: '8px 12px',
              background: hex(TONO_COLORS.error, 0.12),
            }}
          >
            {actionError}
          </span>
        </div>
      )}

      {/* Center stack */}
      <div className="tono-dashboard__content">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 7,
            minHeight: 30,
            padding: '5px 11px',
            borderRadius: 999,
            fontSize: 12,
            fontWeight: 600,
            color: connected ? TONO_COLORS.connected : text.secondary,
            background: connected
              ? hex(TONO_COLORS.connected, dark ? 0.12 : 0.09)
              : dark
                ? 'rgba(255,255,255,0.06)'
                : 'rgba(255,255,255,0.58)',
            border: `1px solid ${
              connected
                ? hex(TONO_COLORS.connected, 0.18)
                : dark
                  ? 'rgba(255,255,255,0.08)'
                  : 'rgba(40,54,86,0.08)'
            }`,
          }}
        >
          <LockIcon locked={connected} />
          <span>
            {connected
              ? t('tono.pill.statusProtected')
              : t('tono.pill.statusReality')}
          </span>
        </div>
        <div
          style={{
            transition: `all 0.5s ${TONO_SPRING}`,
          }}
        >
          <ConnectPill
            uiState={uiState}
            stageLabel={status?.stageLabel}
            onConnect={handleConnect}
            onDisconnect={handleDisconnect}
          />
        </div>
        <ConnectProgressCard
          uiState={uiState}
          selectedServer={status?.selectedServer ?? null}
          killSwitch={status?.killSwitch ?? null}
          onRefreshStatus={mutateTonoStatus}
        />
        {status?.selectedServer && (
          <ActiveNodeCard
            serverName={status.selectedServer}
            connected={connected}
          />
        )}
      </div>

      {/* Bottom info bar, connected only */}
      {connected && (
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 22,
              width: 520,
              maxWidth: '100%',
              borderRadius: 16,
              padding: '12px 16px',
              background: dark
                ? 'rgba(16,21,33,0.58)'
                : 'rgba(255,255,255,0.62)',
              border: `1px solid ${dark ? 'rgba(255,255,255,0.09)' : 'rgba(255,255,255,0.72)'}`,
              backdropFilter: 'blur(18px)',
            }}
          >
            <InfoItem
              label={t('tono.dashboard.info.protection')}
              value={t('tono.dashboard.killSwitchModes.locked')}
              valueColor={TONO_COLORS.connected}
            />
            <InfoItem label={t('tono.dashboard.info.dns')} value="127.0.0.1" />
            <InfoItem
              label={t('tono.dashboard.info.upload')}
              value={`↑ ${up} ${upUnit}/s`}
            />
            <InfoItem
              label={t('tono.dashboard.info.download')}
              value={`↓ ${down} ${downUnit}/s`}
            />
          </div>
        </div>
      )}
    </div>
  )
}

export default DashboardPage
