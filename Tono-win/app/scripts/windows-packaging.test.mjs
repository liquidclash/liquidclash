import assert from 'node:assert/strict'
import test from 'node:test'

import {
  STABLE_EXTERNAL_BIN,
  WINDOWS_RESOURCE_ALLOWLIST,
  WINDOWS_RESOURCE_BUNDLE_ENTRIES,
  partitionReleaseResources,
  validateExternalBin,
  validatePayloadEntries,
  validateResourcesWhitelist,
} from './windows-packaging.mjs'

test('externalBin accepts only the stable sidecar', () => {
  assert.equal(validateExternalBin([STABLE_EXTERNAL_BIN]), null)
  assert.match(validateExternalBin(['sidecar/verge-mihomo-alpha']), /alpha/)
  assert.match(
    validateExternalBin(['sidecar/verge-mihomo', 'sidecar/verge-mihomo-alpha']),
    /exactly one/,
  )
  assert.match(validateExternalBin([]), /exactly one/)
})

test('resources whitelist rejects whole-directory packaging', () => {
  assert.equal(
    validateResourcesWhitelist([...WINDOWS_RESOURCE_BUNDLE_ENTRIES]),
    null,
  )
  assert.match(validateResourcesWhitelist(['resources']), /whole resources/)
  assert.match(
    validateResourcesWhitelist([
      ...WINDOWS_RESOURCE_BUNDLE_ENTRIES,
      'resources/set_dns.sh',
    ]),
    /mismatch/,
  )
  assert.match(
    validateResourcesWhitelist(['resources/Country.mmdb']),
    /mismatch/,
  )
})

test('payload validator rejects alpha and Unix helpers', () => {
  const good = [
    { name: 'Tono.exe' },
    { name: 'verge-mihomo.exe' },
    { name: 'resources/tono-service.exe' },
    { name: 'resources/tono-service-install.exe' },
    { name: 'resources/tono-service-uninstall.exe' },
    { name: 'resources/Country.mmdb' },
  ]
  assert.equal(validatePayloadEntries(good), null)

  assert.match(
    validatePayloadEntries([
      ...good,
      { name: 'verge-mihomo-alpha.exe' },
    ]),
    /alpha Mihomo/,
  )
  assert.match(
    validatePayloadEntries([
      ...good,
      { name: 'resources/clash-verge-service' },
    ]),
    /forbidden Windows junk/,
  )
  assert.match(
    validatePayloadEntries([
      ...good,
      { name: 'resources/set_dns.sh' },
    ]),
    /forbidden Windows junk/,
  )
  assert.match(
    validatePayloadEntries(good.filter((entry) => entry.name !== 'verge-mihomo.exe')),
    /missing stable Mihomo/,
  )
  assert.match(
    validatePayloadEntries(good.filter((entry) => entry.name !== 'Tono.exe')),
    /missing required file basename: Tono\.exe/,
  )
})

test('portable partition keeps only the allowlist', () => {
  const { allowed, rejected } = partitionReleaseResources([
    ...WINDOWS_RESOURCE_ALLOWLIST,
    'clash-verge-service',
    'set_dns.sh',
    'unset_dns.sh',
  ])
  assert.deepEqual(allowed.sort(), [...WINDOWS_RESOURCE_ALLOWLIST].sort())
  assert.deepEqual(rejected.sort(), [
    'clash-verge-service',
    'set_dns.sh',
    'unset_dns.sh',
  ])
})
