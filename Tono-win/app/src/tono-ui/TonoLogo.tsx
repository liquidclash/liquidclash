import { useId } from 'react'

import { TONO_COLORS, TONO_EASE } from './theme'

/**
 * The Tono mark, redrawn from LiquidClashLogo.swift: two interlocking block
 * shapes (normalized-bezier paths ×100) plus the "eye". Colors animate with
 * the connection state (easeOut 0.22s), exactly like the SwiftUI original.
 */

const WHITE_SHAPE =
  'M19.53,27.34 C35.16,27.34 46.88,39.06 50.78,62.5 L66.41,62.5 C62.5,31.25 46.88,15.63 19.53,15.63 Z'
const COLOR_SHAPE =
  'M19.53,74.22 C39.06,74.22 50.78,58.59 58.59,31.25 L74.22,31.25 C66.41,70.31 46.88,85.94 19.53,85.94 Z'

// [start, mid1, mid2, end] stops of the diagonal gradients.
const BLOCK_CONNECTED = ['#0E5A2B', '#1B9A4C', '#2ED573', '#7BED9F']
const BLOCK_DISCONNECTED = ['#FF3B30', '#FF5A4F', '#FF7A70', '#FFC1BC']
const EYE_OUTER_CONNECTED = ['#E0F8E9', '#B8F0CC', '#7BED9F']
const EYE_OUTER_DISCONNECTED = ['#FFFFFF', '#EAEAEA', '#8B8B8D']

interface TonoLogoProps {
  connected: boolean
  /** Pixel size; the mark is square. */
  size?: number
  /** Sidebar/inline variant: neutral eye, smaller shadow, no state animation. */
  compact?: boolean
}

export const TonoLogo = ({ connected, size = 52, compact = false }: TonoLogoProps) => {
  const gradientId = `tono-logo-${useId().replace(/[^a-zA-Z0-9]/g, '')}`
  const glowColor = connected ? TONO_COLORS.connected : TONO_COLORS.error
  const block = connected ? BLOCK_CONNECTED : BLOCK_DISCONNECTED
  const eyeOuter = connected ? EYE_OUTER_CONNECTED : EYE_OUTER_DISCONNECTED
  const eyeInner = connected
    ? '#FFFFFF'
    : compact
      ? '#121214'
      : glowColor

  const outerR = compact ? 17 : 13
  const innerR = compact ? 6 : connected ? 8 : 5
  const innerScale = compact ? 1 : connected ? 1.08 : 0.94
  const innerOpacity = compact ? 1 : connected ? 1 : 0.86

  const id = gradientId

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      role="img"
      aria-hidden
      style={{
        display: 'block',
        filter: compact
          ? 'drop-shadow(0 1px 2.5px rgba(0,0,0,0.16))'
          : `drop-shadow(0 4px 7px ${glowColor}2E)`, // glow at 18%
        transition: compact ? undefined : `filter 0.22s ${TONO_EASE}`,
      }}
    >
      <defs>
        <linearGradient id={`${id}-white`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#FFFFFF" />
          <stop offset="0.5" stopColor="#EAEAEA" />
          <stop offset="1" stopColor="#8B8B8D" />
        </linearGradient>
        <linearGradient id={`${id}-block`} x1="0" y1="1" x2="1" y2="0">
          <stop offset="0" stopColor={block[0]} style={{ transition: `stop-color 0.22s ${TONO_EASE}` }} />
          <stop offset="0.5" stopColor={block[1]} style={{ transition: `stop-color 0.22s ${TONO_EASE}` }} />
          <stop offset="0.75" stopColor={block[2]} style={{ transition: `stop-color 0.22s ${TONO_EASE}` }} />
          <stop offset="1" stopColor={block[3]} style={{ transition: `stop-color 0.22s ${TONO_EASE}` }} />
        </linearGradient>
        <linearGradient id={`${id}-eye`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor={eyeOuter[0]} style={{ transition: `stop-color 0.22s ${TONO_EASE}` }} />
          <stop offset="0.5" stopColor={eyeOuter[1]} style={{ transition: `stop-color 0.22s ${TONO_EASE}` }} />
          <stop offset="1" stopColor={eyeOuter[2]} style={{ transition: `stop-color 0.22s ${TONO_EASE}` }} />
        </linearGradient>
      </defs>
      <path d={WHITE_SHAPE} fill={`url(#${id}-white)`} />
      <path d={COLOR_SHAPE} fill={`url(#${id}-block)`} />
      <circle cx={50} cy={50} r={outerR} fill={`url(#${id}-eye)`} />
      <circle
        cx={50}
        cy={50}
        r={innerR * innerScale}
        fill={eyeInner}
        opacity={innerOpacity}
        style={{
          transition: compact
            ? undefined
            : `r 0.22s ${TONO_EASE}, fill 0.22s ${TONO_EASE}, opacity 0.22s ${TONO_EASE}`,
          filter: compact
            ? undefined
            : `drop-shadow(0 0 ${connected ? 6 : 2}px ${glowColor}${connected ? '8C' : '38'})`,
        }}
      />
    </svg>
  )
}
