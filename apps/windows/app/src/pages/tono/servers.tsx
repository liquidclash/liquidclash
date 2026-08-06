import { useLockFn } from 'ahooks'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { tonoServersQueryKey, useTonoStatus } from '@/hooks/use-tono'
import { useQuery } from '@/services/query-client'
import { useThemeMode } from '@/services/states'
import {
  tonoCancelServerTests,
  tonoCatalogStatus,
  tonoRefreshCatalog,
  tonoSelectServer,
  tonoServers,
  tonoTestAvailableServers,
  tonoTestCurrentServer,
} from '@/services/tono'
import {
  TONO_COLORS,
  TONO_EASE,
  TONO_MONO_STACK,
  tonoText,
} from '@/tono-ui/theme'

import { latencyColor, readNodeLatency } from './node-latency'
import {
  nodeDisplayName,
  nodeFlag,
  nodeProtocol,
  nodeRegion,
} from './node-meta'

const catalogStatusQueryKey = ['tono', 'catalog-status'] as const

type EndpointTestState = {
  revision: number | null
  latencies: Record<string, number>
  failures: Record<string, 'timeout' | 'failed'>
}

const hex = (color: string, alpha: number) =>
  `${color}${Math.round(alpha * 255)
    .toString(16)
    .padStart(2, '0')
    .toUpperCase()}`

const ServersPage = () => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  const { status, mutateTonoStatus } = useTonoStatus()
  const [selectError, setSelectError] = useState<string | null>(null)
  const [testing, setTesting] = useState(false)
  const [testingAll, setTestingAll] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshFeedback, setRefreshFeedback] = useState<string | null>(null)
  const cancelRequestedRef = useRef(false)
  const [currentExitTest, setCurrentExitTest] = useState<{
    name: string
    latency: number
  } | null>(null)
  const [endpointTests, setEndpointTests] = useState<EndpointTestState>({
    revision: null,
    latencies: {},
    failures: {},
  })

  const { data: servers, refetch: mutateServers } = useQuery({
    queryKey: tonoServersQueryKey,
    queryFn: tonoServers,
  })
  const { data: catalog, refetch: mutateCatalog } = useQuery({
    queryKey: catalogStatusQueryKey,
    queryFn: tonoCatalogStatus,
    refetchInterval: 30_000,
  })

  useEffect(
    () => () => {
      void tonoCancelServerTests().catch(() => {})
    },
    [],
  )

  const handleSelect = useLockFn(
    async (name: string, selected: boolean, available: boolean) => {
      if (selected) return
      if (!available) {
        setSelectError(t('tono.nodes.unavailableHint'))
        return
      }
      setSelectError(null)
      try {
        await tonoSelectServer(name)
        await Promise.all([mutateServers(), mutateTonoStatus()])
      } catch (error) {
        setSelectError(error instanceof Error ? error.message : String(error))
      }
    },
  )

  const handleTestCurrent = useLockFn(async () => {
    if (!selected) return
    setTesting(true)
    setSelectError(null)
    try {
      const latency = await tonoTestCurrentServer()
      setCurrentExitTest({ name: selected.name, latency })
    } catch (error) {
      setSelectError(error instanceof Error ? error.message : String(error))
    } finally {
      setTesting(false)
    }
  })

  const handleTestAll = useLockFn(async () => {
    setTestingAll(true)
    cancelRequestedRef.current = false
    setSelectError(null)
    try {
      const results = await tonoTestAvailableServers()
      setEndpointTests({
        revision: catalog?.revision ?? null,
        latencies: Object.fromEntries(
          results.flatMap((result) =>
            result.latencyMs === null ? [] : [[result.name, result.latencyMs]],
          ),
        ),
        failures: Object.fromEntries(
          results
            .filter((result) => result.latencyMs === null)
            .map((result) => [
              result.name,
              result.error === 'timeout' ? 'timeout' : 'failed',
            ]),
        ),
      })
    } catch (error) {
      if (!cancelRequestedRef.current) {
        setSelectError(error instanceof Error ? error.message : String(error))
      }
    } finally {
      setTestingAll(false)
      cancelRequestedRef.current = false
    }
  })

  const handleCancelTests = async () => {
    cancelRequestedRef.current = true
    await tonoCancelServerTests()
  }

  const handleRefresh = useLockFn(async () => {
    setRefreshing(true)
    setRefreshFeedback(null)
    setSelectError(null)
    try {
      await tonoRefreshCatalog()
      await Promise.all([mutateServers(), mutateCatalog(), mutateTonoStatus()])
      setRefreshFeedback(t('tono.nodes.refreshSuccess'))
    } catch (error) {
      setSelectError(error instanceof Error ? error.message : String(error))
      await mutateCatalog()
    } finally {
      setRefreshing(false)
    }
  })

  const selected = (servers ?? []).find((server) => server.selected)
  const serverGroups = useMemo(() => {
    const usable = (servers ?? []).filter(
      (server) => server.available !== false,
    )
    return [
      {
        key: 'us',
        label: 'tono.nodes.regions.us' as const,
        servers: usable.filter((server) => nodeRegion(server.name) === 'us'),
      },
      {
        key: 'jp',
        label: 'tono.nodes.regions.jp' as const,
        servers: usable.filter((server) => nodeRegion(server.name) === 'jp'),
      },
      {
        key: 'other',
        label: 'tono.nodes.regions.other' as const,
        servers: usable.filter((server) => nodeRegion(server.name) === 'other'),
      },
      {
        key: 'unavailable',
        label: 'tono.nodes.regions.unavailable' as const,
        servers: (servers ?? []).filter((server) => server.available === false),
      },
    ].filter((group) => group.servers.length > 0)
  }, [servers])
  const canTestAll =
    status?.uiState === 'notConnected' &&
    catalog?.revision !== null &&
    catalog?.revision !== undefined &&
    (servers ?? []).some((server) => server.available !== false)

  return (
    <div className="tono-page">
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 24,
        }}
      >
        <h1 className="tono-page-title" style={{ color: text.primary }}>
          {t('tono.nodes.title')}
        </h1>
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            flexWrap: 'wrap',
            gap: 8,
          }}
        >
          <button
            type="button"
            className="tono-button"
            onClick={() => void handleRefresh()}
            disabled={refreshing || status?.accountState !== 'ready'}
          >
            {refreshing ? t('tono.nodes.refreshing') : t('tono.nodes.refresh')}
          </button>
          <button
            type="button"
            className="tono-button"
            onClick={testingAll ? handleCancelTests : handleTestAll}
            disabled={testing || (!testingAll && !canTestAll)}
          >
            <span style={{ fontSize: 12 }}>⚡</span>
            {testingAll ? t('tono.nodes.cancelTest') : t('tono.nodes.testAll')}
          </button>
          <button
            type="button"
            className="tono-button"
            onClick={handleTestCurrent}
            disabled={
              testing ||
              testingAll ||
              !selected ||
              status?.uiState !== 'connected'
            }
          >
            <span style={{ fontSize: 12 }}>⚡</span>
            {testing ? '…' : t('tono.nodes.testCurrent')}
          </button>
        </div>
      </div>

      <div
        style={{
          marginBottom: 18,
          padding: '12px 14px',
          borderRadius: 14,
          color: text.secondary,
          background: dark ? 'rgba(16,21,33,0.55)' : 'rgba(255,255,255,0.62)',
          border: `1px solid ${dark ? 'rgba(255,255,255,0.08)' : 'rgba(56,72,108,0.08)'}`,
          fontSize: 12,
        }}
      >
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <span>
            {t('tono.nodes.catalogRevision', {
              revision: catalog?.revision ?? '—',
            })}
          </span>
          <span>
            {t('tono.nodes.catalogNodes', {
              count: catalog?.nodeCount ?? (servers ?? []).length,
            })}
          </span>
          <span>
            {catalog?.lastSyncedAtMs
              ? t('tono.nodes.lastSynced', {
                  time: new Date(catalog.lastSyncedAtMs).toLocaleString(),
                })
              : t('tono.nodes.waitingForSync')}
          </span>
        </div>
        <div style={{ marginTop: 5, color: text.tertiary }}>
          {t('tono.nodes.verifiedSyncHint')}
        </div>
        {(catalog?.error || refreshFeedback) && (
          <div
            role={catalog?.error ? 'alert' : 'status'}
            style={{
              marginTop: 7,
              color: catalog?.error
                ? TONO_COLORS.error
                : TONO_COLORS.latencyGood,
            }}
          >
            {catalog?.error
              ? t('tono.nodes.catalogError', { error: catalog.error })
              : refreshFeedback}
          </div>
        )}
      </div>

      <div
        style={{
          fontSize: 12,
          fontWeight: 600,
          letterSpacing: 0.15,
          color: text.tertiary,
          marginBottom: 10,
        }}
      >
        {t('tono.nodes.cloudServers')}
      </div>

      {selectError && (
        <p
          role="alert"
          style={{ margin: '0 0 8px', fontSize: 12, color: TONO_COLORS.error }}
        >
          {selectError}
        </p>
      )}

      {(servers ?? []).length === 0 ? (
        <p style={{ fontSize: 13, color: text.secondary }}>
          {t('tono.nodes.empty')}
        </p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {serverGroups.map((group) => (
            <section key={group.key}>
              <div
                style={{
                  marginBottom: 8,
                  color: text.tertiary,
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: 0.35,
                  textTransform: 'uppercase',
                }}
              >
                {t(group.label)}
              </div>
              {group.key === 'unavailable' && (
                <p
                  style={{
                    margin: '-2px 0 9px',
                    color: text.tertiary,
                    fontSize: 11,
                  }}
                >
                  {t('tono.nodes.unavailableHint')}
                </p>
              )}
              <div className="tono-server-grid">
                {group.servers.map((server) => {
                  const endpointTestsCurrent =
                    endpointTests.revision === (catalog?.revision ?? null)
                  const endpointLatency = endpointTestsCurrent
                    ? endpointTests.latencies[server.name]
                    : undefined
                  const endpointFailure = endpointTestsCurrent
                    ? endpointTests.failures[server.name]
                    : undefined
                  const exitLatency =
                    currentExitTest?.name === server.name
                      ? currentExitTest.latency
                      : undefined
                  const cachedLatency = readNodeLatency(server.name)
                  const latency =
                    endpointLatency ?? exitLatency ?? cachedLatency
                  const latencyLabel =
                    endpointLatency !== undefined
                      ? t('tono.nodes.tcpLatency', {
                          latency: endpointLatency,
                        })
                      : exitLatency !== undefined
                        ? t('tono.nodes.exitLatency', {
                            latency: exitLatency,
                          })
                        : cachedLatency !== null
                          ? t('tono.nodes.cachedLatency', {
                              latency: cachedLatency,
                            })
                          : '—'
                  const available = server.available !== false
                  return (
                    <button
                      key={server.name}
                      type="button"
                      className="tono-server-card"
                      disabled={!available}
                      onClick={() =>
                        void handleSelect(
                          server.name,
                          server.selected,
                          available,
                        )
                      }
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 11,
                        minHeight: 66,
                        padding: '12px 14px',
                        borderRadius: 16,
                        fontFamily: 'inherit',
                        textAlign: 'left',
                        cursor: !available
                          ? 'not-allowed'
                          : server.selected
                            ? 'default'
                            : 'pointer',
                        opacity: available ? 1 : 0.55,
                        color: text.primary,
                        background: server.selected
                          ? hex(TONO_COLORS.accent, 0.15)
                          : dark
                            ? 'rgba(16,21,33,0.68)'
                            : 'rgba(255,255,255,0.72)',
                        border: server.selected
                          ? `1px solid ${hex(TONO_COLORS.accent, 0.5)}`
                          : `1px solid ${dark ? 'rgba(255,255,255,0.1)' : 'rgba(56,72,108,0.09)'}`,
                        boxShadow: server.selected
                          ? `0 14px 30px -24px ${hex(TONO_COLORS.accent, 0.75)}`
                          : 'none',
                        transition: `background 0.15s ${TONO_EASE}, border-color 0.15s ${TONO_EASE}, transform 0.15s ${TONO_EASE}`,
                      }}
                    >
                      <span
                        aria-hidden
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          width: 34,
                          height: 34,
                          borderRadius: 10,
                          fontSize: 17,
                          flexShrink: 0,
                          background: dark
                            ? 'rgba(255,255,255,0.07)'
                            : 'rgba(235,240,250,0.78)',
                        }}
                      >
                        {nodeFlag(server.name)}
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
                            fontSize: 13,
                            fontWeight: 600,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {nodeDisplayName(server.name)}
                        </span>
                        <span style={{ fontSize: 11, color: text.tertiary }}>
                          {nodeProtocol(server.name)}
                        </span>
                      </span>
                      <span
                        style={{
                          fontSize: 11,
                          fontWeight: 600,
                          fontFamily: TONO_MONO_STACK,
                          flexShrink: 0,
                          padding: '4px 7px',
                          borderRadius: 7,
                          color:
                            !available || endpointFailure
                              ? TONO_COLORS.error
                              : latency !== null
                                ? latencyColor(latency)
                                : text.tertiary,
                          background:
                            !available || endpointFailure
                              ? hex(TONO_COLORS.error, 0.12)
                              : latency !== null
                                ? hex(latencyColor(latency), 0.11)
                                : 'transparent',
                        }}
                      >
                        {!available
                          ? t('tono.nodes.unavailable')
                          : endpointFailure === 'timeout'
                            ? t('tono.nodes.timeout')
                            : endpointFailure
                              ? t('tono.nodes.testFailed')
                              : latencyLabel}
                      </span>
                    </button>
                  )
                })}
              </div>
            </section>
          ))}
        </div>
      )}
    </div>
  )
}

export default ServersPage
