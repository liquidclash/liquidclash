import assert from 'node:assert/strict'
import test from 'node:test'

import {
  KNOWN_LEGACY_WINDOWS_PAYLOAD,
  parseNsisListing,
  STABLE_EXTERNAL_BIN,
  WINDOWS_RESOURCE_ALLOWLIST,
  WINDOWS_RESOURCE_BUNDLE_ENTRIES,
  partitionReleaseResources,
  validateExternalBin,
  validateNsisLegacyCleanup,
  validatePayloadEntries,
  validateReleaseFeatureTree,
  validateResourcesWhitelist,
} from './windows-packaging.mjs'

test('NSIS removes every known old payload on upgrade and uninstall', () => {
  const cleanup = KNOWN_LEGACY_WINDOWS_PAYLOAD.map(
    (entry) =>
      `Delete /REBOOTOK "$INSTDIR\\${entry.replaceAll('/', '\\')}"`,
  ).join('\n')
  const install = `Section Install\n!insertmacro RemoveVergeService\n!insertmacro StartVergeService\nSectionEnd`
  const template = `${cleanup}\n!insertmacro RemoveKnownLegacyPayload\n!insertmacro RemoveKnownLegacyPayload\nRMDir /REBOOTOK "$INSTDIR"\n${install}`
  assert.equal(validateNsisLegacyCleanup(template), null)
  assert.match(
    validateNsisLegacyCleanup(
      template.replace(
        'Delete /REBOOTOK "$INSTDIR\\resources\\set_dns.sh"',
        '',
      ),
    ),
    /set_dns\.sh/,
  )
  assert.match(
    validateNsisLegacyCleanup(
      `${cleanup}\n!insertmacro RemoveKnownLegacyPayload\nRMDir /REBOOTOK "$INSTDIR"`,
    ),
    /both upgrade\/install and uninstall/,
  )
  assert.match(
    validateNsisLegacyCleanup(template.replace('RMDir /REBOOTOK "$INSTDIR"', 'RMDir "$INSTDIR"')),
    /product root/,
  )
  assert.match(
    validateNsisLegacyCleanup(
      template.replace(
        '!insertmacro RemoveVergeService\n!insertmacro StartVergeService',
        '!insertmacro StartVergeService',
      ),
    ),
    /orphaned WFP/,
  )
})

test('release feature gate rejects synchronous traced WebView dispatch', () => {
  const safe = `tauri-runtime-wry v2.11.4\n└── tauri v2.11.5\n    └── clash-verge v0.0.5`
  assert.equal(validateReleaseFeatureTree(safe), null)
  assert.match(
    validateReleaseFeatureTree(
      `${safe}\n├── tauri-runtime-wry feature "tracing"\n│   └── tauri feature "tracing"`,
    ),
    /synchronous/,
  )
  assert.match(
    validateReleaseFeatureTree(`${safe}\n└── tauri-plugin-devtools v2.1.0`),
    /devtools/,
  )
})

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

test('NSIS listing parser accepts real 7zz column variants', () => {
  // Verbatim shapes from a real `7zz l -ba` of a Tauri NSIS installer:
  // blank date/time for entries without stored timestamps, blank compressed
  // size for solid-block members, backslash separators, directory attrs.
  const listing = [
    '                    .....        12288     30747870  $PLUGINSDIR/System.dll',
    '2026-04-19 14:41:36 .....        26494               $PLUGINSDIR/modern-wizard.bmp',
    '                    .....         9728               $PLUGINSDIR\\nsDialogs.dll',
    '2026-08-01 02:24:36 .....      1691856               $TEMP/MicrosoftEdgeWebview2Setup.exe',
    '2026-08-01 02:24:36 D....            0            0  resources',
    '                    .....      2895360               resources/tono-service.exe',
    'not a listing line',
    '',
  ].join('\n')
  const entries = parseNsisListing(listing)
  assert.deepEqual(
    entries.map((entry) => entry.name),
    [
      '$PLUGINSDIR/System.dll',
      '$PLUGINSDIR/modern-wizard.bmp',
      '$PLUGINSDIR/nsDialogs.dll',
      '$TEMP/MicrosoftEdgeWebview2Setup.exe',
      'resources/tono-service.exe',
    ],
  )
  assert.equal(entries[0].size, 12288)
  assert.equal(entries.at(-1).base, 'tono-service.exe')
  assert.deepEqual(parseNsisListing(''), [])
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
