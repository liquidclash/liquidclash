import assert from 'node:assert/strict'
import test from 'node:test'

import {
  TONO_UPDATER_ENDPOINT,
  createUpdaterConfig,
  validateUpdaterPublicKey,
  verifyUpdaterSignature,
} from './prepare-updater-config.mjs'

const TEST_PUBLIC_KEY_TEXT = `untrusted comment: minisign public key E7620F1842B4E81F
RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3`
const TEST_PUBLIC_KEY = Buffer.from(TEST_PUBLIC_KEY_TEXT).toString('base64')
const TEST_SIGNATURE_TEXT = `untrusted comment: signature from minisign secret key
RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=
trusted comment: timestamp:1556193335\tfile:test
y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==`
const TEST_SIGNATURE = Buffer.from(TEST_SIGNATURE_TEXT).toString('base64')

test('creates a Tono-only signed Windows updater configuration', () => {
  const config = createUpdaterConfig(TEST_PUBLIC_KEY)
  assert.deepEqual(config.bundle, { createUpdaterArtifacts: true })
  assert.deepEqual(config.plugins.updater.endpoints, [TONO_UPDATER_ENDPOINT])
  assert.equal(config.plugins.updater.pubkey, TEST_PUBLIC_KEY)
  assert.deepEqual(config.plugins.updater.windows, { installMode: 'passive' })
  assert.doesNotMatch(JSON.stringify(config), /clash-verge-rev/i)
})

test('rejects missing, malformed, placeholder, and legacy public keys', () => {
  for (const value of ['', 'RWabc', 'PLACEHOLDER', 'Clash Verge RWabc']) {
    assert.throws(() => validateUpdaterPublicKey(value))
  }
})

test('verifies that an updater signature belongs to the configured public key', () => {
  assert.doesNotThrow(() =>
    verifyUpdaterSignature(
      TEST_PUBLIC_KEY,
      TEST_SIGNATURE,
      Buffer.from('test'),
    ),
  )
  assert.throws(() =>
    verifyUpdaterSignature(
      TEST_PUBLIC_KEY,
      TEST_SIGNATURE,
      Buffer.from('changed'),
    ),
  )

  for (const line of [2, 3]) {
    const tampered = TEST_SIGNATURE_TEXT.split('\n')
    tampered[line] =
      line === 2 ? `${tampered[line]}x` : `A${tampered[line].slice(1)}`
    assert.throws(() =>
      verifyUpdaterSignature(
        TEST_PUBLIC_KEY,
        Buffer.from(tampered.join('\n')).toString('base64'),
        Buffer.from('test'),
      ),
    )
  }
})

test('rejects updater encodings that Tauri cannot decode canonically', () => {
  assert.throws(() =>
    verifyUpdaterSignature(
      TEST_PUBLIC_KEY,
      ` ${TEST_SIGNATURE}`,
      Buffer.from('test'),
    ),
  )

  const noncanonicalLines = TEST_SIGNATURE_TEXT.split('\n')
  const canonicalInnerSignature = noncanonicalLines[1]
  noncanonicalLines[1] = `${canonicalInnerSignature.slice(0, -2)}p=`
  assert.equal(
    Buffer.from(noncanonicalLines[1], 'base64').toString('base64'),
    canonicalInnerSignature,
  )
  const noncanonicalSignature = Buffer.from(
    noncanonicalLines.join('\n'),
  ).toString('base64')
  assert.throws(() =>
    verifyUpdaterSignature(
      TEST_PUBLIC_KEY,
      noncanonicalSignature,
      Buffer.from('test'),
    ),
  )

  const invalidUtf8Signature = Buffer.concat([
    Buffer.from(TEST_SIGNATURE_TEXT),
    Buffer.from([0xff]),
  ]).toString('base64')
  assert.throws(() =>
    verifyUpdaterSignature(
      TEST_PUBLIC_KEY,
      invalidUtf8Signature,
      Buffer.from('test'),
    ),
  )
})
