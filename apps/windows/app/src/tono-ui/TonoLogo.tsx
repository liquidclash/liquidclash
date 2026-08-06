import brandIcon from '@/assets/image/logo.ico'

import { TONO_COLORS, TONO_EASE } from './theme'

/**
 * The shared Tono product mark used by the Windows shell and primary action.
 * Connection state changes only the restrained outer shadow, never the brand
 * artwork itself.
 */

interface TonoLogoProps {
  connected: boolean
  /** Pixel size; the mark is square. */
  size?: number
  /** Sidebar/inline variant: smaller neutral shadow and no state animation. */
  compact?: boolean
}

export const TonoLogo = ({
  connected,
  size = 52,
  compact = false,
}: TonoLogoProps) => {
  return (
    <img
      src={brandIcon}
      alt=""
      aria-hidden
      draggable={false}
      width={size}
      height={size}
      style={{
        display: 'block',
        width: size,
        height: size,
        objectFit: 'contain',
        filter: compact
          ? 'drop-shadow(0 1px 2px rgba(14,24,54,0.2))'
          : connected
            ? `drop-shadow(0 6px 12px ${TONO_COLORS.connected}52)`
            : `drop-shadow(0 5px 10px ${TONO_COLORS.accent}38)`,
        transition: compact ? undefined : `filter 0.22s ${TONO_EASE}`,
      }}
    />
  )
}
