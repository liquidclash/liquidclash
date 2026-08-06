import CloseRoundedIcon from '@mui/icons-material/CloseRounded'
import SearchRoundedIcon from '@mui/icons-material/SearchRounded'
import { useCallback, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { VirtualList } from '@/components/base/virtual-list'
import { useConnectionData } from '@/hooks/use-connection-data'
import { useTonoStatus } from '@/hooks/use-tono'
import { showNotice } from '@/services/notice-service'
import { useThemeMode } from '@/services/states'
import { tonoCloseAllConnections, tonoCloseConnection } from '@/services/tono'
import { GlassCard } from '@/tono-ui/GlassCard'
import {
  TONO_COLORS,
  TONO_MONO_STACK,
  TONO_PAGE_LAYOUT,
  tonoText,
} from '@/tono-ui/theme'

import { type ActivityRoute, toActivityRow } from './activity-model'

type ActivityFilter = 'all' | ActivityRoute

const MAX_ACTIVITY_CONNECTIONS = 2_000
const EMPTY_CONNECTIONS: IConnectionsItem[] = []
const FILTERS: ActivityFilter[] = ['all', 'proxied', 'direct', 'rejected']
const ACTIVITY_GRID_COLUMNS =
  'minmax(120px, 1.1fr) minmax(150px, 1.4fr) 90px 88px minmax(110px, 1fr) 34px'

const RouteBadge = ({ route }: { route: ActivityRoute }) => {
  const { t } = useTranslation()
  const color =
    route === 'proxied'
      ? TONO_COLORS.accent
      : route === 'direct'
        ? TONO_COLORS.connected
        : TONO_COLORS.error
  return (
    <span
      style={{
        borderRadius: 8,
        padding: '4px 8px',
        color,
        background: `${color}1A`,
        fontSize: 11,
        fontWeight: 650,
        whiteSpace: 'nowrap',
      }}
    >
      {t(`tono.activity.routes.${route}`)}
    </span>
  )
}

const ActivityPage = () => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  const { status } = useTonoStatus()
  const connected = status?.uiState === 'connected'
  const generation = status?.controllerGeneration
  const [filter, setFilter] = useState<ActivityFilter>('all')
  const [query, setQuery] = useState('')
  const [closingId, setClosingId] = useState<string | null>(null)
  const [closingAll, setClosingAll] = useState(false)
  const {
    response: { data },
  } = useConnectionData({ enabled: connected, generation })

  const activeConnections = data?.activeConnections ?? EMPTY_CONNECTIONS
  const capped = useMemo(
    () => activeConnections.slice(0, MAX_ACTIVITY_CONNECTIONS),
    [activeConnections],
  )
  const rows = useMemo(() => capped.map(toActivityRow), [capped])
  const normalizedQuery = query.trim().toLowerCase()
  const visibleRows = useMemo(
    () =>
      rows.filter(
        (row) =>
          (filter === 'all' || row.route === filter) &&
          (!normalizedQuery || row.searchText.includes(normalizedQuery)),
      ),
    [filter, normalizedQuery, rows],
  )

  const handleClose = useCallback(
    async (id: string) => {
      setClosingId(id)
      try {
        if (generation == null) throw new Error('controller unavailable')
        await tonoCloseConnection(id, generation)
      } catch {
        showNotice.error('tono.activity.closeFailed')
      } finally {
        setClosingId(null)
      }
    },
    [generation],
  )

  const handleCloseAll = useCallback(async () => {
    setClosingAll(true)
    try {
      if (generation == null) throw new Error('controller unavailable')
      await tonoCloseAllConnections(generation)
    } catch {
      showNotice.error('tono.activity.closeAllFailed')
    } finally {
      setClosingAll(false)
    }
  }, [generation])

  const renderRow = useCallback(
    (index: number) => {
      const row = visibleRows[index]
      return (
        <div
          role="listitem"
          data-testid={`activity-row-${row.id}`}
          style={{
            minHeight: 74,
            boxSizing: 'border-box',
            display: 'grid',
            gridTemplateColumns: ACTIVITY_GRID_COLUMNS,
            alignItems: 'center',
            gap: 12,
            padding: '10px 14px',
            borderBottom: `1px solid ${dark ? 'rgba(255,255,255,0.07)' : 'rgba(30,42,70,0.08)'}`,
            color: text.primary,
          }}
        >
          <span style={{ minWidth: 0 }}>
            <strong
              title={row.process}
              style={{
                display: 'block',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                fontSize: 13,
              }}
            >
              {row.process}
            </strong>
          </span>
          <span
            title={row.target}
            style={{
              minWidth: 0,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              fontFamily: TONO_MONO_STACK,
              fontSize: 12,
            }}
          >
            {row.target}
          </span>
          <span
            style={{
              color: text.secondary,
              fontFamily: TONO_MONO_STACK,
              fontSize: 11,
            }}
          >
            {row.protocol}
          </span>
          <RouteBadge route={row.route} />
          <span
            title={row.rule}
            style={{
              minWidth: 0,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              color: text.secondary,
              fontSize: 11,
            }}
          >
            {row.rule}
          </span>
          <button
            type="button"
            className="tono-link"
            aria-label={t('tono.activity.closeConnection', {
              target: row.target,
            })}
            disabled={closingId === row.id || closingAll}
            onClick={() => void handleClose(row.id)}
            style={{ width: 30, height: 30, color: text.secondary }}
          >
            <CloseRoundedIcon fontSize="small" />
          </button>
        </div>
      )
    },
    [
      closingAll,
      closingId,
      dark,
      handleClose,
      t,
      text.primary,
      text.secondary,
      visibleRows,
    ],
  )

  return (
    <div
      className="tono-page"
      style={{
        ...TONO_PAGE_LAYOUT,
        height: '100%',
        minHeight: 520,
        overflow: 'hidden',
        gap: 18,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 16,
        }}
      >
        <div>
          <h1 className="tono-page-title" style={{ color: text.primary }}>
            {t('tono.activity.title')}
          </h1>
          <p style={{ margin: '6px 0 0', color: text.secondary, fontSize: 13 }}>
            {t('tono.activity.subtitle')}
          </p>
        </div>
        <button
          type="button"
          className="tono-button"
          disabled={!connected || activeConnections.length === 0 || closingAll}
          onClick={() => void handleCloseAll()}
          style={{
            padding: '8px 13px',
            color: '#fff',
            background: TONO_COLORS.error,
          }}
        >
          {closingAll
            ? t('tono.activity.closingAll')
            : t('shared.actions.closeAll')}
        </button>
      </div>

      <GlassCard
        radius={18}
        padding={0}
        style={{
          flex: 1,
          minHeight: 0,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: 14,
            borderBottom: `1px solid ${dark ? 'rgba(255,255,255,0.08)' : 'rgba(30,42,70,0.08)'}`,
          }}
        >
          <label style={{ position: 'relative', flex: 1, minWidth: 180 }}>
            <SearchRoundedIcon
              aria-hidden
              fontSize="small"
              style={{
                position: 'absolute',
                left: 11,
                top: 9,
                color: text.tertiary,
              }}
            />
            <input
              className="tono-input"
              aria-label={t('tono.activity.search')}
              placeholder={t('tono.activity.search')}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              style={{
                padding: '9px 12px 9px 38px',
                color: text.primary,
                border: `1px solid ${dark ? 'rgba(255,255,255,0.13)' : 'rgba(30,42,70,0.12)'}`,
                background: dark
                  ? 'rgba(255,255,255,0.055)'
                  : 'rgba(255,255,255,0.7)',
              }}
            />
          </label>
          <div
            role="group"
            aria-label={t('tono.activity.routeFilter')}
            style={{ display: 'flex', gap: 4 }}
          >
            {FILTERS.map((value) => (
              <button
                key={value}
                type="button"
                className="tono-button"
                aria-pressed={filter === value}
                onClick={() => setFilter(value)}
                style={{
                  minHeight: 34,
                  padding: '6px 10px',
                  fontSize: 11,
                  color: filter === value ? '#fff' : text.secondary,
                  background:
                    filter === value
                      ? TONO_COLORS.accent
                      : dark
                        ? 'rgba(255,255,255,0.06)'
                        : 'rgba(30,42,70,0.06)',
                }}
              >
                {t(`tono.activity.filters.${value}`)}
              </button>
            ))}
          </div>
        </div>

        {!connected ? (
          <div
            style={{
              margin: 'auto',
              padding: 28,
              textAlign: 'center',
              color: text.secondary,
            }}
          >
            {t('tono.activity.disconnected')}
          </div>
        ) : visibleRows.length === 0 ? (
          <div
            style={{
              margin: 'auto',
              padding: 28,
              textAlign: 'center',
              color: text.secondary,
            }}
          >
            {t(
              normalizedQuery || filter !== 'all'
                ? 'tono.activity.noMatches'
                : 'tono.activity.empty',
            )}
          </div>
        ) : (
          <>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: ACTIVITY_GRID_COLUMNS,
                gap: 12,
                padding: '9px 14px',
                color: text.tertiary,
                fontSize: 10,
                fontWeight: 650,
                letterSpacing: 0.25,
                textTransform: 'uppercase',
              }}
            >
              <span>{t('tono.activity.columns.process')}</span>
              <span>{t('tono.activity.columns.target')}</span>
              <span>{t('tono.activity.columns.protocol')}</span>
              <span>{t('tono.activity.columns.route')}</span>
              <span>{t('tono.activity.columns.rule')}</span>
              <span />
            </div>
            <VirtualList
              count={visibleRows.length}
              estimateSize={74}
              overscan={8}
              getItemKey={(index) => visibleRows[index].id}
              renderItem={renderRow}
              style={{ flex: 1, minHeight: 0 }}
            />
          </>
        )}
        <div
          style={{
            padding: '8px 14px',
            borderTop: `1px solid ${dark ? 'rgba(255,255,255,0.07)' : 'rgba(30,42,70,0.08)'}`,
            color: text.tertiary,
            fontSize: 11,
          }}
        >
          {t('tono.activity.connectionCount', { count: visibleRows.length })}
          {activeConnections.length > MAX_ACTIVITY_CONNECTIONS &&
            ` · ${t('tono.activity.limitNotice', { count: MAX_ACTIVITY_CONNECTIONS })}`}
        </div>
      </GlassCard>
    </div>
  )
}

export default ActivityPage
