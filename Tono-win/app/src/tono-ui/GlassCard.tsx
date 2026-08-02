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
      className={['tono-glass-card', className].filter(Boolean).join(' ')}
      style={{
        borderRadius: radius,
        padding,
        background:
          tint ?? (dark ? 'rgba(16,21,33,0.72)' : 'rgba(255,255,255,0.72)'),
        border: border
          ? `1px solid ${dark ? 'rgba(255,255,255,0.12)' : 'rgba(255,255,255,0.78)'}`
          : 'none',
        boxShadow: dark
          ? '0 20px 48px -32px rgba(0,0,0,0.75), inset 0 1px 0 rgba(255,255,255,0.04)'
          : '0 20px 48px -32px rgba(55,72,110,0.3), inset 0 1px 0 rgba(255,255,255,0.5)',
        backdropFilter: 'blur(12px) saturate(1.08)',
        WebkitBackdropFilter: 'blur(12px) saturate(1.08)',
        ...style,
      }}
    >
      {children}
    </div>
  )
}
