import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import {
  FORBIDDEN_PAYLOAD_NAME_PATTERNS,
  STABLE_EXTERNAL_BIN,
  WINDOWS_RESOURCE_ALLOWLIST,
  WINDOWS_RESOURCE_BUNDLE_ENTRIES,
  parseNsisListing,
  validateExternalBin,
  validateNsisLegacyCleanup,
  validatePayloadEntries,
  validateReleaseFeatureTree,
  validateResourcesWhitelist,
} from './windows-packaging.mjs'

/**
 * Test 6 / Windows release hard gates.
 *
 * Modes:
 *   pnpm release:preflight --config-only
 *     Validate packaging config + on-disk inputs before a long Windows build.
 *
 *   pnpm release:preflight --payload-only <installer.exe>
 *     Inspect a locally built installer without requiring a clean immutable release tag. This
 *     is the post-build gate for real-machine test packages; it does not grant release provenance.
 *
 *   pnpm release:preflight <immutable-tag> <installer.exe> [release-manifest.json]
 *     Full post-build gate: clean tree, tag, versions, hashes, and real NSIS
 *     payload inspection (stable-only Mihomo, no Unix helpers).
 */

const scriptDir = path.dirname(fileURLToPath(import.meta.url))
const appRoot = path.resolve(scriptDir, '..')
const windowsRoot = path.resolve(appRoot, '..')
const repositoryRoot = path.resolve(windowsRoot, '..', '..')
const tauriConfPath = path.resolve(appRoot, 'src-tauri/tauri.conf.json')
const cargoManifestPath = path.resolve(appRoot, 'src-tauri/Cargo.toml')
const nsisTemplatePath = path.resolve(
  appRoot,
  'src-tauri/packages/windows/installer.nsi',
)
const resourcesDir = path.resolve(appRoot, 'src-tauri/resources')
const sidecarDir = path.resolve(appRoot, 'src-tauri/sidecar')

const fail = (message) => {
  console.error(`[release-preflight] ${message}`)
  process.exit(1)
}

const run = (command, args, cwd = windowsRoot) =>
  execFileSync(command, args, { cwd, encoding: 'utf8' }).trim()

const sha256 = (file) => {
  const hash = createHash('sha256')
  hash.update(readFileSync(file))
  return hash.digest('hex')
}

const requireFile = (label, file) => {
  try {
    if (!statSync(file).isFile()) fail(`${label} is not a file: ${file}`)
  } catch {
    fail(`${label} is missing: ${file}`)
  }
}

const loadTauriConfig = () => JSON.parse(readFileSync(tauriConfPath, 'utf8'))

/**
 * Config-time gate: externalBin is stable-only, resources is an explicit Windows
 * whitelist, and on-disk inputs match. This catches Test 5 regressions before a
 * multi-hour NSIS build.
 */
export const assertPackagingConfig = () => {
  const tauriConfig = loadTauriConfig()

  const externalError = validateExternalBin(tauriConfig.bundle?.externalBin)
  if (externalError) fail(externalError)

  const resourcesError = validateResourcesWhitelist(tauriConfig.bundle?.resources)
  if (resourcesError) fail(resourcesError)

  const legacyCleanupError = validateNsisLegacyCleanup(
    readFileSync(nsisTemplatePath, 'utf8'),
  )
  if (legacyCleanupError) fail(legacyCleanupError)

  for (const name of WINDOWS_RESOURCE_ALLOWLIST) {
    requireFile(`resource ${name}`, path.join(resourcesDir, name))
  }

  // Source tree may still hold cross-platform leftovers; they must not be on the allowlist.
  const onDisk = readdirSync(resourcesDir)
  const unexpectedAllowed = onDisk.filter(
    (name) =>
      FORBIDDEN_PAYLOAD_NAME_PATTERNS.some((pattern) => pattern.test(name)) &&
      WINDOWS_RESOURCE_ALLOWLIST.includes(name),
  )
  if (unexpectedAllowed.length) {
    fail(`allowlist incorrectly includes forbidden names: ${unexpectedAllowed.join(', ')}`)
  }

  const leftovers = onDisk.filter(
    (name) =>
      !WINDOWS_RESOURCE_ALLOWLIST.includes(name) &&
      FORBIDDEN_PAYLOAD_NAME_PATTERNS.some((pattern) => pattern.test(name)),
  )
  if (leftovers.length) {
    // Informative only: source-tree leftovers are OK if the whitelist excludes them.
    console.error(
      `[release-preflight] note: source resources/ still has non-packaged leftovers (OK if whitelist holds): ${leftovers.join(', ')}`,
    )
  }

  const stableMihomo = path.join(
    sidecarDir,
    'verge-mihomo-x86_64-pc-windows-msvc.exe',
  )
  if (existsSync(stableMihomo) && !statSync(stableMihomo).isFile()) {
    fail(`stable Mihomo path exists but is not a file: ${stableMihomo}`)
  }

  return { tauriConfig, stableMihomo }
}

const assertReleaseFeatureIsolation = () => {
  let featureTree
  try {
    featureTree = run('cargo', [
      'tree',
      '--manifest-path',
      cargoManifestPath,
      '-e',
      'features',
      '-i',
      'tauri-runtime-wry',
    ])
  } catch (error) {
    fail(
      `failed to inspect the default Rust feature tree: ${error instanceof Error ? error.message : error}`,
    )
  }
  const featureError = validateReleaseFeatureTree(featureTree)
  if (featureError) fail(featureError)
}

const findSevenZip = () => {
  for (const candidate of ['7zz', '7z']) {
    try {
      run(candidate, ['--help'])
      return candidate
    } catch {
      // try next
    }
  }
  return null
}

/**
 * List NSIS payload paths. Tauri NSIS is a PE that 7-Zip can read as an archive.
 */
export const listNsisEntries = (sevenZip, installer) => {
  let listing
  try {
    listing = execFileSync(sevenZip, ['l', '-ba', installer], {
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
    })
  } catch (error) {
    fail(
      `failed to list NSIS payload with ${sevenZip}: ${error instanceof Error ? error.message : error}`,
    )
  }

  // Parsing lives in windows-packaging.mjs (parseNsisListing) so the unit
  // tests cover the real 7zz column variants (blank date/time, blank
  // compressed size) that the old inline regex rejected wholesale.
  const entries = parseNsisListing(listing)
  if (!entries.length) {
    fail(
      '7-Zip returned no file entries from the installer; install 7-Zip or inspect the package manually',
    )
  }
  return entries
}

const assertNsisPayload = (installer) => {
  const sevenZip = findSevenZip()
  if (!sevenZip) {
    fail(
      '7zz/7z is required to inspect the NSIS payload (install p7zip/7-Zip). Config gates alone are not enough for Test 6.',
    )
  }

  const entries = listNsisEntries(sevenZip, installer)
  const payloadError = validatePayloadEntries(entries)
  if (payloadError) {
    fail(
      `${payloadError}\nSample entries: ${entries
        .map((entry) => entry.name)
        .filter((name) => /mihomo|tono-service|resources|Tono\.exe|clash|dns/i.test(name))
        .slice(0, 40)
        .join(' | ')}`,
    )
  }

  return {
    sevenZip,
    entryCount: entries.length,
    mihomo: [
      ...new Set(
        entries
          .map((entry) => entry.base)
          .filter((base) => /verge-mihomo/i.test(base) && !/alpha/i.test(base)),
      ),
    ],
    sample: entries
      .map((entry) => entry.name)
      .filter((name) => /mihomo|tono-service|resources|Tono\.exe/i.test(name))
      .slice(0, 40),
  }
}

const args = process.argv.slice(2)
const configOnly = args.includes('--config-only')
const payloadOnly = args.includes('--payload-only')
const positional = args.filter(
  (arg) => arg !== '--config-only' && arg !== '--payload-only',
)

if (configOnly && payloadOnly) {
  fail('--config-only and --payload-only are mutually exclusive')
}

// Always enforce packaging config. This is the cheap Test 6 gate that was still open after
// the runtime P0–P4 work: Test 5 shipped dual Mihomo + Unix helpers because the bundle map
// was a whole directory and externalBin historically listed alpha.
const packaging = assertPackagingConfig()
assertReleaseFeatureIsolation()
console.error(
  `[release-preflight] packaging config OK (stable-only ${STABLE_EXTERNAL_BIN} + Windows resource whitelist + async release WebView dispatch)`,
)

if (configOnly) {
  console.log(
    JSON.stringify(
      {
        mode: 'config-only',
        externalBin: packaging.tauriConfig.bundle.externalBin,
        resources: packaging.tauriConfig.bundle.resources,
        resourceAllowlist: WINDOWS_RESOURCE_ALLOWLIST,
        resourceBundleEntries: WINDOWS_RESOURCE_BUNDLE_ENTRIES,
      },
      null,
      2,
    ),
  )
  process.exit(0)
}

if (payloadOnly) {
  const [installerArgument, ...unexpected] = positional
  if (!installerArgument || unexpected.length) {
    fail('usage: pnpm release:preflight --payload-only <installer.exe>')
  }

  const installer = path.resolve(process.cwd(), installerArgument)
  const service = path.resolve(appRoot, 'src-tauri/resources/tono-service.exe')
  const mihomo = path.resolve(
    appRoot,
    'src-tauri/sidecar/verge-mihomo-x86_64-pc-windows-msvc.exe',
  )
  for (const [label, file] of [
    ['installer', installer],
    ['service', service],
    ['mihomo', mihomo],
  ]) {
    requireFile(label, file)
  }

  const payload = assertNsisPayload(installer)
  console.error(
    '[release-preflight] local NSIS payload OK (no alpha, no Unix helpers, required binaries present)',
  )
  console.log(
    JSON.stringify(
      {
        mode: 'payload-only',
        provenance: 'local-test-package-only',
        payload,
        artifacts: {
          installer: {
            path: installer,
            size: statSync(installer).size,
            sha256: sha256(installer),
          },
          service: {
            path: service,
            size: statSync(service).size,
            sha256: sha256(service),
          },
          mihomo: {
            path: mihomo,
            size: statSync(mihomo).size,
            sha256: sha256(mihomo),
          },
        },
      },
      null,
      2,
    ),
  )
  process.exit(0)
}

const [tag, installerArgument, manifestArgument] = positional
if (!tag || !installerArgument) {
  fail(
    'usage: pnpm release:preflight --config-only\n' +
      '       pnpm release:preflight --payload-only <installer.exe>\n' +
      '       pnpm release:preflight <immutable-tag> <installer.exe> [release-manifest.json]',
  )
}

const installer = path.resolve(process.cwd(), installerArgument)
const manifestPath = manifestArgument
  ? path.resolve(process.cwd(), manifestArgument)
  : path.resolve(
      repositoryRoot,
      'services/control-plane/public/releases/manifest.json',
    )
const service = path.resolve(appRoot, 'src-tauri/resources/tono-service.exe')
const mihomo = path.resolve(
  appRoot,
  'src-tauri/sidecar/verge-mihomo-x86_64-pc-windows-msvc.exe',
)

for (const [label, file] of [
  ['installer', installer],
  ['service', service],
  ['mihomo', mihomo],
  ['manifest', manifestPath],
]) {
  requireFile(label, file)
}

// A source tarball from a dirty tree is not reproducible provenance. The release tag must resolve
// to the exact clean commit from which the installer is built.
const dirty = run('git', [
  'status',
  '--porcelain=v1',
  '--untracked-files=all',
  '--',
  '.',
])
if (dirty) fail(`Tono-win worktree is dirty:\n${dirty}`)

const commit = run('git', ['rev-parse', 'HEAD'])
let taggedCommit
try {
  taggedCommit = run('git', ['rev-list', '-n', '1', tag])
} catch {
  fail(`tag does not exist: ${tag}`)
}
if (taggedCommit !== commit) {
  fail(`tag ${tag} points to ${taggedCommit}, not current commit ${commit}`)
}

const packageJson = JSON.parse(
  readFileSync(path.resolve(appRoot, 'package.json'), 'utf8'),
)
const tauriConfig = packaging.tauriConfig
const cargoManifest = readFileSync(
  path.resolve(appRoot, 'src-tauri/Cargo.toml'),
  'utf8',
)
const cargoVersion = cargoManifest.match(/^version\s*=\s*"([^"]+)"/m)?.[1]
const versions = new Set([
  packageJson.version,
  tauriConfig.version,
  cargoVersion,
])
if (versions.size !== 1 || versions.has(undefined)) {
  fail(
    `App versions disagree: package=${packageJson.version}, tauri=${tauriConfig.version}, cargo=${cargoVersion}`,
  )
}

const payload = assertNsisPayload(installer)
console.error(
  '[release-preflight] NSIS payload OK (no alpha, no Unix helpers, required binaries present)',
)

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
const windowsRelease = manifest?.platforms?.windows?.current
if (!windowsRelease) fail('manifest has no platforms.windows.current entry')
if (windowsRelease.version !== packageJson.version) {
  fail(
    `manifest version ${windowsRelease.version} does not match App ${packageJson.version}`,
  )
}
if (!windowsRelease.releaseURL?.endsWith(`/tag/${tag}`)) {
  fail(`manifest releaseURL does not reference immutable tag ${tag}`)
}

const installerHash = sha256(installer)
const mihomoHash = sha256(mihomo)
const serviceHash = sha256(service)
if (windowsRelease.artifact?.sha256 !== installerHash) {
  fail(
    `manifest installer SHA differs: manifest=${windowsRelease.artifact?.sha256}, actual=${installerHash}`,
  )
}
if (windowsRelease.mihomo?.sha256 !== mihomoHash) {
  fail(
    `manifest Mihomo SHA differs: manifest=${windowsRelease.mihomo?.sha256}, actual=${mihomoHash}`,
  )
}
// Service SHA is required for Test 6 provenance when the field is present; if omitted, warn hard.
// Test 6 provenance is hard-required. Escape hatch only for local dry-runs:
//   TONO_RELEASE_ALLOW_INCOMPLETE_MANIFEST=1
const allowIncompleteManifest =
  process.env.TONO_RELEASE_ALLOW_INCOMPLETE_MANIFEST === '1'
if (!windowsRelease.commit) {
  const message =
    'manifest platforms.windows.current.commit is required (git SHA of the clean release commit)'
  if (allowIncompleteManifest) {
    console.error(`[release-preflight] warning: ${message}`)
  } else {
    fail(message)
  }
} else if (windowsRelease.commit !== commit) {
  fail(
    `manifest source commit ${windowsRelease.commit} does not match worktree ${commit}`,
  )
}
if (!windowsRelease.service?.sha256) {
  const message =
    'manifest platforms.windows.current.service.sha256 is required (tono-service.exe hash)'
  if (allowIncompleteManifest) {
    console.error(`[release-preflight] warning: ${message}`)
  } else {
    fail(message)
  }
} else if (windowsRelease.service.sha256 !== serviceHash) {
  fail(
    `manifest Service SHA differs: manifest=${windowsRelease.service.sha256}, actual=${serviceHash}`,
  )
}

console.log(
  JSON.stringify(
    {
      tag,
      commit,
      appVersion: packageJson.version,
      toolchain: {
        rustc: run('rustc', ['--version'], appRoot),
        cargo: run('cargo', ['--version'], appRoot),
        node: process.version,
      },
      packaging: {
        externalBin: tauriConfig.bundle.externalBin,
        resources: tauriConfig.bundle.resources,
      },
      payload,
      artifacts: {
        installer: {
          path: installer,
          size: statSync(installer).size,
          sha256: installerHash,
        },
        service: {
          path: service,
          size: statSync(service).size,
          sha256: serviceHash,
        },
        mihomo: {
          path: mihomo,
          size: statSync(mihomo).size,
          sha256: mihomoHash,
        },
      },
    },
    null,
    2,
  ),
)
