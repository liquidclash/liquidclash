import { useTranslation } from 'react-i18next'

import { useThemeMode } from '@/services/states'
import type { TonoUiState } from '@/services/tono'

import { TONO_COLORS, TONO_EASE, tonoText } from './theme'
import { TonoLogo } from './TonoLogo'

/**
 * ConnectPill — the primary dashboard action. The wider desktop target keeps
 * the five-state color system while making the click affordance and live stage
 * text legible at Windows display scaling.
 */

interface StateSpec {
  color: string
  glowOpacity: number
  glowScale: number
  titleKey: string
  /** State color for the title; `notConnected` uses the primary text color. */
  titleColored: boolean
  indicator: 'dot' | 'spinner'
  disabled: boolean
}

const STATE_SPECS: Record<TonoUiState, StateSpec> = {
  notConnected: {
    color: TONO_COLORS.accent,
    glowOpacity: 0.18,
    glowScale: 1,
    titleKey: 'tono.pill.title.notConnected',
    titleColored: false,
    indicator: 'dot',
    disabled: false,
  },
  connecting: {
    color: TONO_COLORS.accent,
    glowOpacity: 0.26,
    glowScale: 1.03,
    titleKey: 'tono.pill.title.connecting',
    titleColored: true,
    indicator: 'spinner',
    disabled: true,
  },
  connected: {
    color: TONO_COLORS.connected,
    glowOpacity: 0.25,
    glowScale: 1.03,
    titleKey: 'tono.pill.title.connected',
    titleColored: true,
    indicator: 'dot',
    disabled: false,
  },
  protectedOffline: {
    color: TONO_COLORS.protectedOffline,
    glowOpacity: 0.22,
    glowScale: 1,
    titleKey: 'tono.pill.title.protectedOffline',
    titleColored: true,
    indicator: 'dot',
    disabled: false,
  },
  disconnecting: {
    color: TONO_COLORS.accent,
    glowOpacity: 0.24,
    glowScale: 1.03,
    titleKey: 'tono.pill.title.disconnecting',
    titleColored: true,
    indicator: 'spinner',
    disabled: true,
  },
}

const hex = (color: string, alpha: number) =>
  `${color}${Math.round(alpha * 255)
    .toString(16)
    .padStart(2, '0')
    .toUpperCase()}`

interface ConnectPillProps {
  uiState: TonoUiState
  /** Backend stage text ("Locking traffic…") shown while connecting. */
  stageLabel?: string | null
  onConnect: () => void
  onDisconnect: () => void
}

export const ConnectPill = ({
  uiState,
  stageLabel,
  onConnect,
  onDisconnect,
}: ConnectPillProps) => {
  const { t } = useTranslation()
  const dark = useThemeMode() !== 'light'
  const text = tonoText(dark)
  const spec = STATE_SPECS[uiState]

  const subtitle =
    uiState === 'connecting'
      ? (stageLabel ?? t('tono.pill.subtitle.starting'))
      : uiState === 'notConnected'
        ? t('tono.pill.subtitle.tapToConnect')
        : uiState === 'connected'
          ? t('tono.pill.subtitle.tapToDisconnect')
          : uiState === 'protectedOffline'
            ? t('tono.pill.subtitle.tapToRestore')
            : t('tono.pill.subtitle.restoringAccess')

  const handleClick = () => {
    if (spec.disabled) return
    if (uiState === 'connected' || uiState === 'protectedOffline') {
      onDisconnect()
    } else {
      onConnect()
    }
  }

  const transition = `0.22s ${TONO_EASE}`

  return (
    <button
      type="button"
      className="tono-pill"
      disabled={spec.disabled}
      onClick={handleClick}
      aria-label={`${t(spec.titleKey)} — ${subtitle}`}
      style={{
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        width: 340,
        maxWidth: 'calc(100vw - 230px)',
        minHeight: 96,
        padding: '11px 14px 11px 11px',
        border: `1px solid ${hex(spec.color, dark ? 0.32 : 0.24)}`,
        borderRadius: 28,
        cursor: spec.disabled ? 'default' : 'pointer',
        color: text.primary,
        background: `linear-gradient(120deg, ${hex(spec.color, dark ? 0.12 : 0.09)} 0%, ${hex(spec.color, 0)} 58%), ${
          dark ? 'rgba(13,18,29,0.84)' : 'rgba(255,255,255,0.82)'
        }`,
        backdropFilter: 'var(--tono-glass-blur)',
        WebkitBackdropFilter: 'var(--tono-glass-blur)',
        boxShadow:
          uiState === 'connected'
            ? `0 18px 42px -28px ${hex(TONO_COLORS.connected, 0.72)}, inset 0 1px 0 ${hex('#FFFFFF', dark ? 0.06 : 0.65)}`
            : dark
              ? '0 22px 48px -32px rgba(0,0,0,0.9), inset 0 1px 0 rgba(255,255,255,0.05)'
              : '0 22px 48px -32px rgba(55,72,110,0.38), inset 0 1px 0 rgba(255,255,255,0.65)',
        transition: `background ${transition}, border-color ${transition}, box-shadow ${transition}, transform ${transition}`,
      }}
    >
      {/* Icon zone */}
      <span
        style={{
          position: 'relative',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: 72,
          height: 72,
          flexShrink: 0,
        }}
      >
        <span
          aria-hidden
          style={{
            position: 'absolute',
            width: 64,
            height: 64,
            borderRadius: 20,
            background: `radial-gradient(circle at 50% 45%, ${hex(spec.color, 0.42)} 0%, ${hex(spec.color, 0.16)} 46%, ${hex(spec.color, 0)} 74%)`,
            filter: 'blur(7px)',
            opacity: spec.glowOpacity,
            transform: `scale(${spec.glowScale})`,
            transition: `opacity ${transition}, transform ${transition}, background ${transition}`,
          }}
        />
        <TonoLogo connected={uiState === 'connected'} size={54} />
      </span>

      {/* Text zone */}
      <span
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'flex-start',
          justifyContent: 'center',
          gap: 6,
          flex: 1,
          minWidth: 0,
          textAlign: 'left',
        }}
      >
        <span
          style={{
            fontSize: 21,
            fontWeight: 650,
            lineHeight: 1.15,
            letterSpacing: -0.35,
            color: spec.titleColored ? spec.color : text.primary,
            transition: `color ${transition}`,
          }}
        >
          {t(spec.titleKey)}
        </span>
        <span
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 5,
            maxWidth: '100%',
            fontSize: 12,
            fontWeight: 500,
            lineHeight: 1.25,
            color: text.secondary,
          }}
        >
          {spec.indicator === 'dot' ? (
            <span
              aria-hidden
              style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                flexShrink: 0,
                background: spec.color,
                transition: `background ${transition}`,
              }}
            />
          ) : (
            <span
              aria-hidden
              className="tono-spin"
              style={{
                width: 10,
                height: 10,
                flexShrink: 0,
                borderRadius: '50%',
                border: `1.5px solid ${hex(spec.color, 0.35)}`,
                borderTopColor: spec.color,
              }}
            />
          )}
          <span
            style={{
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {subtitle}
          </span>
        </span>
      </span>

      <span
        aria-hidden
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: 36,
          height: 36,
          flexShrink: 0,
          borderRadius: 12,
          color: spec.color,
          background: hex(spec.color, dark ? 0.14 : 0.1),
          border: `1px solid ${hex(spec.color, 0.18)}`,
        }}
      >
        <svg aria-hidden width="17" height="17" viewBox="0 0 24 24" fill="none">
          <title>Connection power</title>
          <path
            d="M12 2v10M5.9 5.9a8.5 8.5 0 1 0 12.2 0"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>
      </span>
    </button>
  )
}
