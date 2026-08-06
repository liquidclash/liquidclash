/**
 * Tono node presentation metadata: user-facing display names, flag emoji, and
 * the protocol line, derived from the catalog's wire names. The server
 * address itself is never shown — that is Tono's idea of redaction.
 */

const NODE_DISPLAY_NAMES: Record<string, string> = {
  'US-VLESS-Reality': 'Los Angeles · Sunset',
  'JP-VLESS-Reality': 'Tokyo · Dawn',
}

export const nodeDisplayName = (wireName: string) =>
  NODE_DISPLAY_NAMES[wireName] ?? wireName

export const nodeFlag = (wireName: string) => {
  const upper = wireName.toUpperCase()
  if (/\bUS\b|^US[-_ ]/.test(upper)) return '🇺🇸'
  if (/\bJP\b|^JP[-_ ]/.test(upper)) return '🇯🇵'
  return '🌐'
}

export const nodeProtocol = (wireName: string) =>
  /vless/i.test(wireName) ? 'VLESS · Reality' : 'Tono Cloud'

export type NodeRegion = 'us' | 'jp' | 'other'

/** Keep the UI's groups aligned with the backend's whole-token region ranking. */
export const nodeRegion = (wireName: string): NodeRegion => {
  const tokens = wireName.split(/[^\p{L}\p{N}]+/u).filter(Boolean)
  if (tokens.some((token) => token.toLowerCase() === 'us')) return 'us'
  if (tokens.some((token) => token.toLowerCase() === 'jp')) return 'jp'
  return 'other'
}
