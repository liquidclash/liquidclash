import { useSyncExternalStore } from 'react'

/**
 * Tono design tokens, extracted 1:1 from the macOS SwiftUI sources
 * (Tono/Views/*.swift). Web rendering notes per token live next to it.
 */

export const TONO_COLORS = {
  accent: '#4B6EFF',
  connected: '#2ED573',
  latencyGood: '#30D158',
  connecting: '#FFD60A',
  protectedOffline: '#FF9F0A',
  error: '#FF3B30',
  errorDark: '#FF453A',
  notConnected: '#E83B3B',
  gray: '#8E8E93',
} as const

/** SwiftUI .easeOut(0.22) — used for every ConnectPill color/glow transition. */
export const TONO_EASE = 'cubic-bezier(0.25, 0.1, 0.25, 1)'
/** SwiftUI .spring(0.5, bounce 0.15) — page-level state switches. */
export const TONO_SPRING = 'cubic-bezier(0.34, 1.3, 0.64, 1)'

export const TONO_FONT_STACK =
  '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI Variable Text", "Segoe UI", "Microsoft YaHei UI", "Microsoft YaHei", "Helvetica Neue", Arial, sans-serif'

export const TONO_MONO_STACK =
  'ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, "Microsoft YaHei UI", "Microsoft YaHei", monospace'

/**
 * `.tono-page`'s structural rules, for pages to also set inline.
 *
 * A customer machine was found rendering with no layout stylesheet applied,
 * which left every page as an unstyled top-left column — and a page that
 * relies on the class for `display: flex` cannot centre itself with inline
 * `alignItems` alone. Inline structure keeps the layout under that failure.
 */
export const TONO_PAGE_LAYOUT = {
  minHeight: '100%',
  boxSizing: 'border-box',
  display: 'flex',
  flexDirection: 'column',
  padding: '48px 40px 36px',
} as const

/** Text/foreground ramps. macOS resolves these from semantic colors. */
export const tonoText = (dark: boolean) => ({
  primary: dark ? 'rgba(255,255,255,0.96)' : 'rgba(20,22,30,0.94)',
  secondary: dark ? 'rgba(255,255,255,0.72)' : 'rgba(20,22,30,0.68)',
  tertiary: dark ? 'rgba(255,255,255,0.5)' : 'rgba(20,22,30,0.52)',
})

// ---------------------------------------------------------------------------
// Glass transparency (Appearance card): 0–100, default 50. The content-layer
// background opacity is `0.94 - t/100 * 0.22` (t=50 → 0.83, matching the
// macOS frosted default). Persisted in localStorage.
// ---------------------------------------------------------------------------

const GLASS_STORAGE_KEY = 'tono-glass-transparency'
const GLASS_DEFAULT = 50
const GLASS_EVENT = 'tono://glass-transparency'

export const getGlassTransparency = (): number => {
  try {
    const raw = window.localStorage.getItem(GLASS_STORAGE_KEY)
    const value = raw === null ? NaN : Number(raw)
    if (Number.isFinite(value) && value >= 0 && value <= 100) return value
  } catch {
    // storage unavailable — fall through to default
  }
  return GLASS_DEFAULT
}

export const setGlassTransparency = (value: number) => {
  const clamped = Math.min(100, Math.max(0, Math.round(value)))
  try {
    window.localStorage.setItem(GLASS_STORAGE_KEY, String(clamped))
  } catch {
    // storage unavailable — the in-memory event still updates this session
  }
  window.dispatchEvent(new CustomEvent(GLASS_EVENT))
}

const subscribeGlass = (onChange: () => void) => {
  window.addEventListener(GLASS_EVENT, onChange)
  return () => window.removeEventListener(GLASS_EVENT, onChange)
}

export const useGlassTransparency = () =>
  useSyncExternalStore(
    subscribeGlass,
    getGlassTransparency,
    () => GLASS_DEFAULT,
  )

export const glassOpacity = (transparency: number) =>
  0.94 - (transparency / 100) * 0.22
