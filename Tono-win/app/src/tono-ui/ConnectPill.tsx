import { useTranslation } from 'react-i18next'

import { useThemeMode } from '@/services/states'
import type { TonoUiState } from '@/services/tono'

import { TONO_COLORS, TONO_EASE, tonoText } from './theme'
import { TonoLogo } from './TonoLogo'

/**
 * ConnectPill — the centerpiece of the Tono dashboard, pixel-matched to
 * ConnectPill.swift: a 240×72 glass capsule with a radial halo behind the
 * mark, a five-state color system, and easeOut(0.22) transitions. No
 * breathing, no rotation.
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
    color: TONO_COLORS.notConnected,
    glowOpacity: 0.48,
    glowScale: 0.96,
    titleKey: 'tono.pill.title.notConnected',
    titleColored: false,
    indicator: 'dot',
    disabled: false,
  },
  connecting: {
    color: TONO_COLORS.connecting,
    glowOpacity: 0.78,
    glowScale: 1.08,
    titleKey: 'tono.pill.title.connecting',
    titleColored: true,
    indicator: 'spinner',
    disabled: true,
  },
  connected: {
    color: TONO_COLORS.connected,
    glowOpacity: 0.78,
    glowScale: 1.08,
    titleKey: 'tono.pill.title.connected',
    titleColored: true,
    indicator: 'dot',
    disabled: false,
  },
  protectedOffline: {
    color: TONO_COLORS.protectedOffline,
    glowOpacity: 0.48,
    glowScale: 0.96,
    titleKey: 'tono.pill.title.protectedOffline',
    titleColored: true,
    indicator: 'dot',
    disabled: false,
  },
  disconnecting: {
    color: TONO_COLORS.connecting,
    glowOpacity: 0.78,
    glowScale: 1.08,
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

/** 96×96 halo: clear inner radius 12 → main color at 0.72 by radius 44. */
const haloBackground = (color: string) =>
  `radial-gradient(circle 44px at 50% 50%, ${hex(color, 0)} 12px, ${hex(
    color,
    0.18,
  )} 22px, ${hex(color, 0.48)} 33px, ${hex(color, 0.72)} 44px)`

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
      style={{
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        width: 240,
        height: 72,
        padding: 0,
        border: 'none',
        borderRadius: 36,
        cursor: spec.disabled ? 'default' : 'pointer',
        color: text.primary,
        background: dark
          ? 'rgba(0, 0, 0, 0.55)'
          : 'rgba(255, 255, 255, 0.06)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        boxShadow:
          uiState === 'connected'
            ? `0 5px 15px ${hex(TONO_COLORS.connected, 0.25)}`
            : dark
              ? '0 5px 15px rgba(0, 0, 0, 0.35)'
              : '0 5px 15px rgba(0, 0, 0, 0.1)',
        transition: `background ${transition}, box-shadow ${transition}`,
      }}
    >
      {/* Icon zone: 80 wide, halo 96×96 behind the 52×52 mark. */}
      <span
        style={{
          position: 'relative',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: 80,
          height: '100%',
          flexShrink: 0,
        }}
      >
        <span
          aria-hidden
          style={{
            position: 'absolute',
            width: 96,
            height: 96,
            borderRadius: '50%',
            background: haloBackground(spec.color),
            opacity: spec.glowOpacity,
            transform: `scale(${spec.glowScale})`,
            transition: `opacity ${transition}, transform ${transition}, background ${transition}`,
          }}
        />
        <TonoLogo connected={uiState === 'connected'} size={52} />
      </span>

      {/* Text zone: 160 wide, pulled 20 towards the mark. */}
      <span
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'flex-start',
          gap: 3,
          width: 160,
          transform: 'translateX(-20px)',
          textAlign: 'left',
        }}
      >
        <span
          style={{
            fontSize: 22,
            fontWeight: 600,
            lineHeight: 1.15,
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
            fontSize: 11,
            fontWeight: 500,
            letterSpacing: 1.1,
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
          <span>{subtitle}</span>
        </span>
      </span>
    </button>
  )
}
