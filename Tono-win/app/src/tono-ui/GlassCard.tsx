import type { CSSProperties, ReactNode } from 'react'

import { useThemeMode } from '@/services/states'

/**
 * The Tono glass card: white-tinted background at the stepped opacities the
 * macOS design uses (4/6/8/12/24/40%), a 1px white border, rounded corners,
 * and a blurred backdrop. Defaults match the settings cards (light 40% /
 * dark 8%, radius 24); dashboard cards pass their own step.
 */

interface GlassCardProps {
  children: ReactNode
  radius?: number
  /** CSS background for the tint; defaults to the settings-card step. */
  tint?: string
  border?: boolean
  padding?: CSSProperties['padding']
  style?: CSSProperties
  className?: string
}

export const GlassCard = ({
  children,
  radius = 24,
  tint,
  border = true,
  padding = 24,
  style,
  className,
}: GlassCardProps) => {
  const dark = useThemeMode() !== 'light'

  return (
    <div
      className={className}
      style={{
        borderRadius: radius,
        padding,
        background:
          tint ?? (dark ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.4)'),
        border: border
          ? `1px solid ${dark ? 'rgba(255,255,255,0.18)' : 'rgba(255,255,255,0.7)'}`
          : 'none',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        ...style,
      }}
    >
      {children}
    </div>
  )
}
