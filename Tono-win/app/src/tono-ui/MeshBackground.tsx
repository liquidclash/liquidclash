import { glassOpacity, useGlassTransparency } from './theme'

/**
 * The frosted-glass window background (MeshGradientBackground.swift): a soft
 * ambient gradient sheet under a near-opaque wash whose alpha follows the
 * Appearance slider. The gradients are already soft, so the previous full-window
 * 40px backdrop blur only forced continuous WebView2 GPU composition.
 */

const LIGHT_MESH = [
  'radial-gradient(52% 64% at 18% 12%, rgba(176, 196, 255, 0.75) 0%, rgba(176, 196, 255, 0) 100%)',
  'radial-gradient(48% 58% at 82% 8%, rgba(198, 224, 255, 0.7) 0%, rgba(198, 224, 255, 0) 100%)',
  'radial-gradient(60% 66% at 78% 88%, rgba(214, 206, 244, 0.65) 0%, rgba(214, 206, 244, 0) 100%)',
  'radial-gradient(56% 60% at 12% 86%, rgba(188, 210, 235, 0.6) 0%, rgba(188, 210, 235, 0) 100%)',
  'linear-gradient(160deg, #eef1f8 0%, #e6eaf3 100%)',
].join(', ')

const DARK_MESH = [
  'radial-gradient(52% 64% at 18% 12%, rgba(46, 64, 128, 0.6) 0%, rgba(46, 64, 128, 0) 100%)',
  'radial-gradient(48% 58% at 82% 8%, rgba(32, 52, 96, 0.55) 0%, rgba(32, 52, 96, 0) 100%)',
  'radial-gradient(60% 66% at 78% 88%, rgba(40, 36, 84, 0.5) 0%, rgba(40, 36, 84, 0) 100%)',
  'radial-gradient(56% 60% at 12% 86%, rgba(24, 38, 72, 0.55) 0%, rgba(24, 38, 72, 0) 100%)',
  'linear-gradient(160deg, #0b0e18 0%, #090b12 100%)',
].join(', ')

export const MeshBackground = ({ dark }: { dark: boolean }) => {
  const transparency = useGlassTransparency()
  const opacity = glassOpacity(transparency)

  return (
    <div
      aria-hidden
      style={{ position: 'absolute', inset: 0, overflow: 'hidden' }}
    >
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: dark ? DARK_MESH : LIGHT_MESH,
        }}
      />
      <div
        className="tono-mesh-wash"
        style={{
          position: 'absolute',
          inset: 0,
          background: dark
            ? `rgba(9, 11, 18, ${opacity})`
            : `rgba(243, 245, 250, ${opacity})`,
          transition: 'background 0.2s ease',
        }}
      />
    </div>
  )
}
