import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { tonoServersQueryKey, useTonoStatus } from '@/hooks/use-tono'
import { useQuery } from '@/services/query-client'
import { useThemeMode } from '@/services/states'
import {
  tonoSelectServer,
  tonoServers,
  tonoTestCurrentServer,
} from '@/services/tono'
import {
  TONO_COLORS,
  TONO_EASE,
  TONO_MONO_STACK,
  tonoText,
} from '@/tono-ui/theme'

import { latencyColor, readNodeLatency } from './node-latency'
import { nodeFlag, nodeDisplayName, nodeProtocol } from './node-meta'

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
  const [measuredLatency, setMeasuredLatency] = useState<
    Record<string, number>
  >({})

  const { data: servers, refetch: mutateServers } = useQuery({
    queryKey: tonoServersQueryKey,
    queryFn: tonoServers,
  })

  const handleSelect = useLockFn(async (name: string, selected: boolean) => {
    if (selected) return
    setSelectError(null)
    try {
      await tonoSelectServer(name)
      await Promise.all([mutateServers(), mutateTonoStatus()])
    } catch (error) {
      setSelectError(error instanceof Error ? error.message : String(error))
    }
  })

  const handleTestCurrent = useLockFn(async () => {
    if (!selected) return
    setTesting(true)
    setSelectError(null)
    try {
      const latency = await tonoTestCurrentServer()
      setMeasuredLatency((current) => ({
        ...current,
        [selected.name]: latency,
      }))
    } catch (error) {
      setSelectError(error instanceof Error ? error.message : String(error))
    } finally {
      setTesting(false)
    }
  })

  const selected = (servers ?? []).find((server) => server.selected)

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
        <button
          type="button"
          className="tono-button"
          onClick={handleTestCurrent}
          disabled={testing || !selected || status?.uiState !== 'connected'}
          style={{
            padding: '8px 14px',
            fontSize: 13,
            fontWeight: 600,
            color: text.primary,
            background: dark
              ? 'rgba(255,255,255,0.07)'
              : 'rgba(255,255,255,0.68)',
            border: `1px solid ${dark ? 'rgba(255,255,255,0.1)' : 'rgba(56,72,108,0.1)'}`,
            backdropFilter: 'blur(10px)',
          }}
        >
          <span style={{ fontSize: 12 }}>⚡</span>
          {testing ? '…' : t('tono.nodes.testCurrent')}
        </button>
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
        <div className="tono-server-grid">
          {(servers ?? []).map((server) => {
            const latency =
              measuredLatency[server.name] ?? readNodeLatency(server.name)
            return (
              <button
                key={server.name}
                type="button"
                className="tono-server-card"
                onClick={() => void handleSelect(server.name, server.selected)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 11,
                  minHeight: 66,
                  padding: '12px 14px',
                  borderRadius: 16,
                  fontFamily: 'inherit',
                  textAlign: 'left',
                  cursor: server.selected ? 'default' : 'pointer',
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
                      latency !== null ? latencyColor(latency) : text.tertiary,
                    background:
                      latency !== null
                        ? hex(latencyColor(latency), 0.11)
                        : 'transparent',
                  }}
                >
                  {latency !== null ? `${latency}ms` : '—'}
                </span>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default ServersPage
