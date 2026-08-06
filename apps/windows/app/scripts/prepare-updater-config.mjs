import { createHash, createPublicKey, verify } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const TONO_UPDATER_ENDPOINT =
  'https://raw.githubusercontent.com/raydocs/tono/windows-updates/latest.json'

function decodeBase64(value, label) {
  const encoded = String(value)
  if (
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      encoded,
    )
  ) {
    throw new Error(`${label} is not valid Base64`)
  }
  const decoded = Buffer.from(encoded, 'base64')
  if (decoded.toString('base64') !== encoded) {
    throw new Error(`${label} is not canonical Base64`)
  }
  return decoded
}

function decodeUtf8(value, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(value)
  } catch {
    throw new Error(`${label} is not valid UTF-8`)
  }
}

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

  const decodedPublicKey = decodeUtf8(
    decodeBase64(publicKey, 'TONO_UPDATER_PUBLIC_KEY'),
    'TONO_UPDATER_PUBLIC_KEY',
  )
  const publicKeyLines = decodedPublicKey.split(/\r?\n/)
  if (publicKeyLines.at(-1) === '') publicKeyLines.pop()
  if (publicKeyLines.length !== 2 || !publicKeyLines[1].startsWith('RW')) {
    throw new Error(
      'TONO_UPDATER_PUBLIC_KEY is not a Tauri/minisign public key',
    )
  }
  if (
    decodeBase64(publicKeyLines[1], 'minisign public key').byteLength !== 42
  ) {
    throw new Error(
      'TONO_UPDATER_PUBLIC_KEY does not contain a 42-byte minisign public key',
    )
  }

  return publicKey
}

export function verifyUpdaterSignature(publicKey, encodedSignature, payload) {
  const normalizedPublicKey = validateUpdaterPublicKey(publicKey)
  const publicKeyText = decodeUtf8(
    decodeBase64(normalizedPublicKey, 'TONO_UPDATER_PUBLIC_KEY'),
    'TONO_UPDATER_PUBLIC_KEY',
  )
  const signatureText = decodeUtf8(
    decodeBase64(encodedSignature, 'updater signature'),
    'updater signature',
  )
  const signatureLines = signatureText.split(/\r?\n/)
  if (signatureLines.at(-1) === '') signatureLines.pop()
  if (
    signatureLines.length !== 4 ||
    !signatureLines[0].startsWith('untrusted comment: ') ||
    !signatureLines[2].startsWith('trusted comment: ')
  ) {
    throw new Error(
      'updater signature is not a complete minisign signature box',
    )
  }
  const publicKeyBytes = decodeBase64(
    publicKeyText.split(/\r?\n/)[1],
    'minisign public key',
  )
  const signatureBytes = decodeBase64(signatureLines[1], 'minisign signature')
  const globalSignature = decodeBase64(
    signatureLines[3],
    'minisign global signature',
  )
  if (signatureBytes.byteLength !== 74 || globalSignature.byteLength !== 64) {
    throw new Error('updater signature is not a minisign signature')
  }
  const publicKeyAlgorithm = publicKeyBytes.subarray(0, 2).toString('ascii')
  if (publicKeyAlgorithm !== 'ED' && publicKeyAlgorithm !== 'Ed') {
    throw new Error('updater public key uses an unsupported minisign algorithm')
  }
  const algorithm = signatureBytes.subarray(0, 2).toString('ascii')
  if (algorithm !== 'ED' && algorithm !== 'Ed') {
    throw new Error('updater signature uses an unsupported minisign algorithm')
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
  const signedPayload =
    algorithm === 'ED'
      ? createHash('blake2b512').update(payload).digest()
      : payload
  if (
    !verify(null, signedPayload, verificationKey, signatureBytes.subarray(10))
  ) {
    throw new Error(
      'updater private key does not match TONO_UPDATER_PUBLIC_KEY',
    )
  }

  const trustedComment = Buffer.from(signatureLines[2].slice(17))
  const globalPayload = Buffer.concat([
    signatureBytes.subarray(10),
    trustedComment,
  ])
  if (!verify(null, globalPayload, verificationKey, globalSignature)) {
    throw new Error('updater signature trusted comment authentication failed')
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
