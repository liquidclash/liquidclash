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
