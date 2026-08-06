import { readFile, writeFile } from 'node:fs/promises'
import process from 'node:process'
import { pathToFileURL } from 'node:url'

import { verifyUpdaterSignature } from './prepare-updater-config.mjs'

const WINDOWS_PLATFORM = /^windows-(?:x86_64|i686|aarch64)(?:-(?:nsis|msi))?$/

export async function validateWindowsChannel(
  manifest,
  expectedVersion,
  publicKey,
  release,
  fetchAsset = fetch,
) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('latest.json must be an object')
  }
  const version = String(manifest.version ?? '').replace(/^v/, '')
  if (version !== expectedVersion) {
    throw new Error(
      `latest.json version ${manifest.version ?? 'missing'} does not match ${expectedVersion}`,
    )
  }

  const platforms = manifest.platforms
  const entries =
    platforms && typeof platforms === 'object' && !Array.isArray(platforms)
      ? Object.entries(platforms)
      : []
  if (entries.length === 0) {
    throw new Error('latest.json has no Windows platforms')
  }
  const releaseAssets = Array.isArray(release?.assets) ? release.assets : []
  if (releaseAssets.length === 0) {
    throw new Error('published Windows Release has no assets')
  }

  for (const [platform, update] of entries) {
    if (!WINDOWS_PLATFORM.test(platform)) {
      throw new Error(
        `non-Windows platform is forbidden in the Windows channel: ${platform}`,
      )
    }
    if (!update || typeof update !== 'object' || Array.isArray(update)) {
      throw new Error(`invalid update entry for ${platform}`)
    }

    const sourceUrl = String(update.url ?? '')
    const releaseAsset = releaseAssets.find(
      (asset) =>
        asset?.url === sourceUrl || asset?.browser_download_url === sourceUrl,
    )
    if (!releaseAsset) {
      throw new Error(
        `${platform} does not reference an asset owned by the selected Release`,
      )
    }
    const url = new URL(String(releaseAsset.browser_download_url ?? ''))
    const expectedPrefix = `/raydocs/tono/releases/download/v${expectedVersion}/`
    if (
      url.protocol !== 'https:' ||
      url.hostname !== 'github.com' ||
      !url.pathname.startsWith(expectedPrefix) ||
      url.search ||
      url.hash
    ) {
      throw new Error(
        `${platform} must reference an immutable raydocs/tono v${expectedVersion} release asset`,
      )
    }
    update.url = url.href
    if (typeof update.signature !== 'string' || !update.signature.trim()) {
      throw new Error(`${platform} has no updater signature`)
    }

    const response = await fetchAsset(url)
    if (!response.ok) {
      throw new Error(
        `${platform} artifact download failed: HTTP ${response.status}`,
      )
    }
    verifyUpdaterSignature(
      publicKey,
      update.signature,
      Buffer.from(await response.arrayBuffer()),
    )
  }

  return manifest
}

async function main() {
  const [, , manifestPath, releasePath, expectedVersion, outputPath] =
    process.argv
  if (!manifestPath || !releasePath || !expectedVersion || !outputPath) {
    throw new Error(
      'usage: validate-windows-channel.mjs <latest.json> <release.json> <version> <validated-output.json>',
    )
  }
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  const release = JSON.parse(await readFile(releasePath, 'utf8'))
  await validateWindowsChannel(
    manifest,
    expectedVersion,
    process.env.TONO_UPDATER_PUBLIC_KEY,
    release,
  )
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`)
  console.log(`validated Windows update channel candidate v${expectedVersion}`)
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    console.error(
      `[windows-channel] ${error instanceof Error ? error.message : error}`,
    )
    process.exit(1)
  })
}
