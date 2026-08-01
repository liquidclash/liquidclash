import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { tonoServersQueryKey, useTonoStatus } from '@/hooks/use-tono'
import { useQuery } from '@/services/query-client'
import { useThemeMode } from '@/services/states'
import { tonoSelectServer, tonoServers } from '@/services/tono'
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
  const { mutateTonoStatus } = useTonoStatus()
  const [selectError, setSelectError] = useState<string | null>(null)
  const [testing, setTesting] = useState(false)
  // Bump to re-read latency history from the delay manager.
  const [latencyTick, setLatencyTick] = useState(0)

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
    setTesting(true)
    try {
      // The delay manager measures through the running core; re-read its
      // history after a beat. A dedicated backend test command will replace
      // this when one exists.
      await new Promise((resolve) => setTimeout(resolve, 400))
      setLatencyTick((v) => v + 1)
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
          marginBottom: 18,
        }}
      >
        <h1 className="tono-page-title" style={{ color: text.primary }}>
          {t('tono.nodes.title')}
        </h1>
        <button
          type="button"
          className="tono-button"
          onClick={handleTestCurrent}
          disabled={testing || !selected}
          style={{
            padding: '8px 16px',
            fontSize: 12,
            fontWeight: 600,
            color: text.primary,
            background: dark
              ? 'rgba(255,255,255,0.08)'
              : 'rgba(255,255,255,0.5)',
            border: `1px solid ${dark ? 'rgba(255,255,255,0.16)' : 'rgba(255,255,255,0.7)'}`,
            backdropFilter: 'blur(20px)',
          }}
        >
          <span style={{ fontSize: 12 }}>⚡</span>
          {testing ? '…' : t('tono.nodes.testCurrent')}
        </button>
      </div>

      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: 0.6,
          textTransform: 'uppercase',
          color: text.tertiary,
          marginBottom: 8,
        }}
      >
        {t('tono.nodes.cloudServers')}
      </div>

      {selectError && (
        <p role="alert" style={{ margin: '0 0 8px', fontSize: 12, color: TONO_COLORS.error }}>
          {selectError}
        </p>
      )}

      {(servers ?? []).length === 0 ? (
        <p style={{ fontSize: 13, color: text.secondary }}>
          {t('tono.nodes.empty')}
        </p>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 10,
          }}
        >
          {(servers ?? []).map((server) => {
            const latency = readNodeLatency(server.name)
            void latencyTick
            return (
              <button
                key={server.name}
                type="button"
                onClick={() => void handleSelect(server.name, server.selected)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: 10,
                  borderRadius: 12,
                  fontFamily: 'inherit',
                  textAlign: 'left',
                  cursor: server.selected ? 'default' : 'pointer',
                  color: text.primary,
                  background: server.selected
                    ? hex(TONO_COLORS.accent, 0.15)
                    : dark
                      ? 'rgba(255,255,255,0.06)'
                      : 'rgba(255,255,255,0.7)',
                  border: server.selected
                    ? `1px solid ${hex(TONO_COLORS.accent, 0.5)}`
                    : `0.5px solid ${dark ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.9)'}`,
                  transition: `background 0.15s ${TONO_EASE}, border-color 0.15s ${TONO_EASE}`,
                }}
              >
                <span aria-hidden style={{ fontSize: 14, flexShrink: 0 }}>
                  {nodeFlag(server.name)}
                </span>
                <span style={{ display: 'flex', flexDirection: 'column', gap: 1, flex: 1, minWidth: 0 }}>
                  <span
                    style={{
                      fontSize: 12,
                      fontWeight: 500,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {nodeDisplayName(server.name)}
                  </span>
                  <span style={{ fontSize: 10, color: text.tertiary }}>
                    {nodeProtocol(server.name)}
                  </span>
                </span>
                <span
                  style={{
                    fontSize: 10,
                    fontFamily: TONO_MONO_STACK,
                    flexShrink: 0,
                    color:
                      latency !== null
                        ? latencyColor(latency)
                        : text.tertiary,
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
