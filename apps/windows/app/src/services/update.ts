import {
  check,
  type CheckOptions,
  type Update,
} from '@tauri-apps/plugin-updater'

import { version as appVersion } from '@root/package.json'

type VersionParts = {
  main: bigint[]
  pre: (bigint | string)[]
}

const SEMVER_FULL_REGEX =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/

const normalizeVersion = (input: string | null | undefined): string | null => {
  if (typeof input !== 'string') return null
  const trimmed = input.trim()
  if (!trimmed) return null
  return trimmed.replace(/^v/i, '')
}

const ensureSemver = (input: string | null | undefined): string | null => {
  const normalized = normalizeVersion(input)
  if (!normalized) return null
  return SEMVER_FULL_REGEX.test(normalized) ? normalized : null
}

const splitVersion = (version: string | null): VersionParts | null => {
  if (!version) return null
  const withoutBuildMetadata = version.split('+', 1)[0]
  const [mainPart, preRelease] = withoutBuildMetadata.split('-', 2)
  const main = mainPart.split('.').map((part) => BigInt(part))

  const pre =
    preRelease?.split('.').map((token) => {
      return /^\d+$/.test(token) ? BigInt(token) : token
    }) ?? []

  return { main, pre }
}

const compareVersionParts = (a: VersionParts, b: VersionParts): number => {
  const length = Math.max(a.main.length, b.main.length)
  for (let i = 0; i < length; i += 1) {
    const aPart = a.main[i] ?? 0n
    const bPart = b.main[i] ?? 0n
    if (aPart !== bPart) return aPart > bPart ? 1 : -1
  }

  if (a.pre.length === 0 && b.pre.length === 0) return 0
  if (a.pre.length === 0) return 1
  if (b.pre.length === 0) return -1

  const preLen = Math.max(a.pre.length, b.pre.length)
  for (let i = 0; i < preLen; i += 1) {
    const aToken = a.pre[i]
    const bToken = b.pre[i]
    if (aToken === undefined) return -1
    if (bToken === undefined) return 1

    if (typeof aToken === 'bigint' && typeof bToken === 'bigint') {
      if (aToken > bToken) return 1
      if (aToken < bToken) return -1
      continue
    }

    if (typeof aToken === 'bigint') return -1
    if (typeof bToken === 'bigint') return 1

    if (aToken > bToken) return 1
    if (aToken < bToken) return -1
  }

  return 0
}

export const compareVersions = (
  a: string | null,
  b: string | null,
): number | null => {
  const partsA = splitVersion(ensureSemver(a))
  const partsB = splitVersion(ensureSemver(b))
  if (!partsA || !partsB) return null
  return compareVersionParts(partsA, partsB)
}

const resolveRemoteVersion = (update: Update): string | null => {
  return ensureSemver(update.version)
}

const localVersionNormalized = ensureSemver(appVersion)
// Release builds set this only after prepare-updater-config.mjs has injected the Tono-owned
// endpoint and public key. Developer builds therefore never query any inherited channel.
export const TONO_UPDATES_CONFIGURED =
  import.meta.env.VITE_TONO_UPDATES_CONFIGURED === 'true'

export const checkUpdateSafe = async (
  options?: CheckOptions,
): Promise<Update | null> => {
  if (!TONO_UPDATES_CONFIGURED) return null
  const result = await check({ ...(options ?? {}), allowDowngrades: false })
  if (!result) return null

  const remoteVersion = resolveRemoteVersion(result)
  const comparison = compareVersions(remoteVersion, localVersionNormalized)

  // A signed feed is still required to name a strict SemVer newer than this App. Do not let a
  // malformed response bypass the downgrade check.
  if (comparison === null || comparison <= 0) {
    try {
      await result.close()
    } catch (err) {
      console.warn('[updater] failed to close stale update resource', err)
    }
    return null
  }

  return result
}

export type { CheckOptions }
