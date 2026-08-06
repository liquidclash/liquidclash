import assert from 'node:assert/strict'
import test from 'node:test'

import {
  TONO_UPDATER_ENDPOINT,
  createUpdaterConfig,
  validateUpdaterPublicKey,
  verifyUpdaterSignature,
} from './prepare-updater-config.mjs'

const TEST_PUBLIC_KEY_TEXT = `untrusted comment: minisign public key for updater tests
RWQBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB`
const TEST_PUBLIC_KEY = Buffer.from(TEST_PUBLIC_KEY_TEXT).toString('base64')

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
  // RFC 8032 Ed25519 test vector 1 (empty payload); no private key is stored or generated here.
  const keyId = Buffer.from('0102030405060708', 'hex')
  const publicKey = Buffer.from(
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    'hex',
  )
  const signature = Buffer.from(
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' +
      '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    'hex',
  )
  const publicKeyText = `untrusted comment: RFC 8032 test key\n${Buffer.concat([Buffer.from('Ed'), keyId, publicKey]).toString('base64')}`
  const signatureText = `untrusted comment: RFC 8032 test signature\n${Buffer.concat([Buffer.from('Ed'), keyId, signature]).toString('base64')}`
  const encodedPublicKey = Buffer.from(publicKeyText).toString('base64')
  const encodedSignature = Buffer.from(signatureText).toString('base64')

  assert.doesNotThrow(() =>
    verifyUpdaterSignature(encodedPublicKey, encodedSignature, Buffer.alloc(0)),
  )
  assert.throws(() =>
    verifyUpdaterSignature(
      encodedPublicKey,
      encodedSignature,
      Buffer.from('changed'),
    ),
  )
})
