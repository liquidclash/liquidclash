import { createPublicKey, verify } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const TONO_UPDATER_ENDPOINT =
  'https://github.com/raydocs/tono/releases/latest/download/latest.json'

export function validateUpdaterPublicKey(value) {
  const publicKey = String(value ?? '').trim()
  if (!publicKey) {
    throw new Error('TONO_UPDATER_PUBLIC_KEY is required')
  }
  if (/placeholder|clash[- ]?verge/i.test(publicKey)) {
    throw new Error(
      'TONO_UPDATER_PUBLIC_KEY must be a Tono-owned key, not a placeholder or legacy key',
    )
  }

  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(publicKey)) {
    throw new Error('TONO_UPDATER_PUBLIC_KEY is not valid Base64')
  }

  const decodedPublicKey = Buffer.from(publicKey, 'base64').toString('utf8')
  const encodedKey = decodedPublicKey
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line.startsWith('RW'))
  if (!encodedKey || !/^RW[A-Za-z0-9+/]+={0,2}$/.test(encodedKey)) {
    throw new Error(
      'TONO_UPDATER_PUBLIC_KEY is not a Tauri/minisign public key',
    )
  }
  if (Buffer.from(encodedKey, 'base64').byteLength !== 42) {
    throw new Error(
      'TONO_UPDATER_PUBLIC_KEY does not contain a 42-byte minisign public key',
    )
  }

  return publicKey
}

export function verifyUpdaterSignature(publicKey, encodedSignature, payload) {
  validateUpdaterPublicKey(publicKey)
  const publicKeyText = Buffer.from(publicKey, 'base64').toString('utf8')
  const signatureText = Buffer.from(
    String(encodedSignature).trim(),
    'base64',
  ).toString('utf8')
  const publicKeyBytes = Buffer.from(
    publicKeyText.split(/\r?\n/).find((line) => line.startsWith('RW')) ?? '',
    'base64',
  )
  const signatureBytes = Buffer.from(
    signatureText.split(/\r?\n/).find((line) => /^R[A-Za-z0-9+/]/.test(line)) ??
      '',
    'base64',
  )
  if (signatureBytes.byteLength !== 74) {
    throw new Error('updater signature is not a minisign signature')
  }
  if (!publicKeyBytes.subarray(2, 10).equals(signatureBytes.subarray(2, 10))) {
    throw new Error(
      'updater private key does not match TONO_UPDATER_PUBLIC_KEY',
    )
  }

  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex')
  const verificationKey = createPublicKey({
    key: Buffer.concat([spkiPrefix, publicKeyBytes.subarray(10)]),
    format: 'der',
    type: 'spki',
  })
  if (!verify(null, payload, verificationKey, signatureBytes.subarray(10))) {
    throw new Error(
      'updater private key does not match TONO_UPDATER_PUBLIC_KEY',
    )
  }
}

export function createUpdaterConfig(publicKey) {
  return {
    bundle: { createUpdaterArtifacts: true },
    plugins: {
      updater: {
        endpoints: [TONO_UPDATER_ENDPOINT],
        pubkey: validateUpdaterPublicKey(publicKey),
        windows: { installMode: 'passive' },
      },
    },
  }
}

export async function writeUpdaterConfig(publicKey, outputPath) {
  const resolved = path.resolve(outputPath)
  await mkdir(path.dirname(resolved), { recursive: true })
  await writeFile(
    resolved,
    `${JSON.stringify(createUpdaterConfig(publicKey), null, 2)}\n`,
    {
      mode: 0o600,
    },
  )
  return resolved
}

async function main() {
  if (process.argv[2] === '--verify') {
    const [, , , payloadPath, signaturePath] = process.argv
    if (!payloadPath || !signaturePath) {
      throw new Error(
        'usage: prepare-updater-config.mjs --verify <payload> <signature>',
      )
    }
    verifyUpdaterSignature(
      process.env.TONO_UPDATER_PUBLIC_KEY,
      await readFile(signaturePath, 'utf8'),
      await readFile(payloadPath),
    )
    console.log('updater signing key pair verified')
    return
  }

  const appRoot = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
  )
  const outputPath =
    process.argv[2] ??
    path.join(appRoot, 'src-tauri', 'tauri.updater.conf.json')
  const resolved = await writeUpdaterConfig(
    process.env.TONO_UPDATER_PUBLIC_KEY,
    outputPath,
  )
  console.log(resolved)
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    console.error(
      `[updater-config] ${error instanceof Error ? error.message : error}`,
    )
    process.exit(1)
  })
}
