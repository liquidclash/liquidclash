/**
 * Shared Windows packaging allowlist for Test 6+.
 *
 * Test 5 shipped dual Mihomo (stable + alpha) and ~4.8 MB of Unix helpers because:
 *   - externalBin historically listed alpha
 *   - bundle.resources was the whole "resources" directory
 *   - portable scripts re-zipped that whole directory after build
 *
 * Keep this module as the single source of truth for config preflight, portable zips,
 * and NSIS payload inspection.
 */

export const WINDOWS_RESOURCE_ALLOWLIST = Object.freeze([
  'Country.mmdb',
  'geoip.dat',
  'geosite.dat',
  'enableLoopback.exe',
  'tono-service.exe',
  'tono-service-install.exe',
  'tono-service-uninstall.exe',
])

export const WINDOWS_RESOURCE_BUNDLE_ENTRIES = Object.freeze(
  WINDOWS_RESOURCE_ALLOWLIST.map((name) => `resources/${name}`),
)

export const STABLE_EXTERNAL_BIN = 'sidecar/verge-mihomo'

export const FORBIDDEN_PAYLOAD_NAME_PATTERNS = Object.freeze([
  /verge-mihomo-alpha/i,
  /clash-verge-service/i,
  /^set_dns\.sh$/i,
  /^unset_dns\.sh$/i,
])

/**
 * @param {unknown} externalBin
 * @returns {string | null} error message, or null when valid
 */
export function validateExternalBin(externalBin) {
  if (!Array.isArray(externalBin) || externalBin.length !== 1) {
    return `bundle.externalBin must be exactly one stable sidecar entry, got: ${JSON.stringify(externalBin)}`
  }
  if (externalBin.some((entry) => String(entry).includes('alpha'))) {
    return 'release config still bundles the unaudited alpha Mihomo sidecar'
  }
  if (externalBin[0] !== STABLE_EXTERNAL_BIN) {
    return `bundle.externalBin[0] must be "${STABLE_EXTERNAL_BIN}", got: ${externalBin[0]}`
  }
  return null
}

/**
 * @param {unknown} resources
 * @returns {string | null}
 */
export function validateResourcesWhitelist(resources) {
  if (!Array.isArray(resources)) {
    return 'bundle.resources must be an explicit array (Windows whitelist)'
  }
  if (resources.some((entry) => entry === 'resources' || entry === 'resources/')) {
    return 'bundle.resources still packages the whole resources/ directory; use an explicit Windows file whitelist'
  }
  const expected = [...WINDOWS_RESOURCE_BUNDLE_ENTRIES].sort()
  const actual = [...resources].map(String).sort()
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    return `bundle.resources whitelist mismatch.\n  expected: ${JSON.stringify(expected)}\n  actual:   ${JSON.stringify(actual)}`
  }
  return null
}

/**
 * @param {{ name: string, base?: string }[]} entries
 * @returns {string | null}
 */
export function validatePayloadEntries(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return 'payload listing is empty'
  }

  const normalized = entries.map((entry) => {
    const name = String(entry.name || '').replaceAll('\\', '/')
    const base = entry.base || name.split('/').pop() || name
    return { name, base, size: entry.size ?? 0 }
  })

  const bases = normalized.map((entry) => entry.base)
  const alpha = bases.filter((base) => /verge-mihomo-alpha/i.test(base))
  if (alpha.length) {
    return `installer payload still contains alpha Mihomo: ${[...new Set(alpha)].join(', ')}`
  }

  const mihomo = [
    ...new Set(
      bases.filter(
        (base) =>
          /^verge-mihomo(\.exe)?$/i.test(base) ||
          /^verge-mihomo-x86_64-pc-windows-msvc\.exe$/i.test(base),
      ),
    ),
  ]
  if (mihomo.length < 1) {
    return 'installer payload is missing stable Mihomo (looked for verge-mihomo*.exe)'
  }
  if (mihomo.length !== 1) {
    return `installer payload must contain exactly one stable Mihomo basename, found: ${mihomo.join(', ')}`
  }

  const forbidden = normalized.filter((entry) =>
    FORBIDDEN_PAYLOAD_NAME_PATTERNS.some(
      (pattern) => pattern.test(entry.base) || pattern.test(entry.name),
    ),
  )
  if (forbidden.length) {
    return `installer payload contains forbidden Windows junk: ${forbidden
      .map((entry) => entry.name)
      .join(', ')}`
  }

  for (const required of [
    'Tono.exe',
    'tono-service.exe',
    'tono-service-install.exe',
    'tono-service-uninstall.exe',
  ]) {
    if (!bases.some((base) => base.toLowerCase() === required.toLowerCase())) {
      return `installer payload is missing required file basename: ${required}`
    }
  }

  return null
}

/**
 * Pick only allowlisted files from a built release resources directory.
 * @param {string[]} basenames on-disk names under releaseDir/resources
 * @returns {{ allowed: string[], rejected: string[] }}
 */
export function partitionReleaseResources(basenames) {
  const allowed = []
  const rejected = []
  for (const name of basenames) {
    if (WINDOWS_RESOURCE_ALLOWLIST.includes(name)) {
      allowed.push(name)
    } else {
      rejected.push(name)
    }
  }
  return { allowed, rejected }
}
