import fs from 'fs'
import fsp from 'fs/promises'
import { createRequire } from 'module'
import path from 'path'

import AdmZip from 'adm-zip'

import {
  WINDOWS_RESOURCE_ALLOWLIST,
  partitionReleaseResources,
} from './windows-packaging.mjs'

const target = process.argv.slice(2)[0]
const ARCH_MAP = {
  'x86_64-pc-windows-msvc': 'x64',
  'aarch64-pc-windows-msvc': 'arm64',
}

const PROCESS_MAP = {
  x64: 'x64',
  arm64: 'arm64',
}
const arch = target ? ARCH_MAP[target] : PROCESS_MAP[process.arch]
/// Script for ci
/// 打包绿色版/便携版 (only Windows)
async function resolvePortable() {
  if (process.platform !== 'win32') return

  const releaseDir = target
    ? `./src-tauri/target/${target}/release`
    : `./src-tauri/target/release`
  const configDir = path.join(releaseDir, '.config')
  const resourcesDir = path.join(releaseDir, 'resources')

  if (!fs.existsSync(releaseDir)) {
    throw new Error('could not found the release dir')
  }

  await fsp.mkdir(configDir, { recursive: true })
  if (!fs.existsSync(path.join(configDir, 'PORTABLE'))) {
    await fsp.writeFile(path.join(configDir, 'PORTABLE'), '')
  }
  const zip = new AdmZip()

  zip.addLocalFile(path.join(releaseDir, 'Tono.exe'))
  // Stable-only: never zip verge-mihomo-alpha even if a leftover sits in releaseDir.
  const stableMihomo = path.join(releaseDir, 'verge-mihomo.exe')
  if (!fs.existsSync(stableMihomo)) {
    throw new Error(`missing stable Mihomo at ${stableMihomo}`)
  }
  if (fs.existsSync(path.join(releaseDir, 'verge-mihomo-alpha.exe'))) {
    throw new Error(
      'refuse to build portable zip while verge-mihomo-alpha.exe is present in the release dir',
    )
  }
  zip.addLocalFile(stableMihomo)

  // Do not addLocalFolder(resources): that reintroduced Unix helpers in Test 5 when the
  // build tree still held source leftovers. Only the Windows allowlist ships.
  if (!fs.existsSync(resourcesDir)) {
    throw new Error(`missing resources dir: ${resourcesDir}`)
  }
  const onDisk = await fsp.readdir(resourcesDir)
  const { allowed, rejected } = partitionReleaseResources(onDisk)
  if (rejected.length) {
    console.warn(
      `[portable] ignoring non-allowlisted resources (not packaged): ${rejected.join(', ')}`,
    )
  }
  for (const name of WINDOWS_RESOURCE_ALLOWLIST) {
    if (!allowed.includes(name)) {
      throw new Error(`portable resources missing required file: ${name}`)
    }
    zip.addLocalFile(path.join(resourcesDir, name), 'resources')
  }

  zip.addLocalFolder(configDir, '.config')

  const require = createRequire(import.meta.url)
  const packageJson = require('../package.json')
  const { version } = packageJson
  const zipFile = `Tono_${version}_${arch}_portable.zip`
  zip.writeZip(zipFile)
  console.log('[INFO]: create portable zip successfully')
}

resolvePortable().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
