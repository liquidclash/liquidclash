import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import { validateWindowsChannel } from './validate-windows-channel.mjs'

const publicKeyText = `untrusted comment: minisign public key E7620F1842B4E81F
RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3`
const signatureText = `untrusted comment: signature from minisign secret key
RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=
trusted comment: timestamp:1556193335\tfile:test
y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==`
const encodedPublicKey = Buffer.from(publicKeyText).toString('base64')
const encodedSignature = Buffer.from(signatureText).toString('base64')

const windowsManifest = () => ({
  version: '0.0.19',
  notes: 'Tono Windows',
  platforms: {
    'windows-x86_64': {
      url: 'https://github.com/raydocs/tono/releases/download/v0.0.19/Tono_0.0.19_x64-setup.nsis.zip',
      signature: encodedSignature,
    },
  },
})
const windowsRelease = () => ({
  assets: [
    {
      url: 'https://api.github.com/repos/raydocs/tono/releases/assets/190019',
      browser_download_url:
        'https://github.com/raydocs/tono/releases/download/v0.0.19/Tono_0.0.19_x64-setup.nsis.zip',
    },
  ],
})

const signedResponse = {
  ok: true,
  status: 200,
  arrayBuffer: async () => Buffer.from('test'),
}

test('accepts a signed artifact from the immutable Tono Windows release', async () => {
  await assert.doesNotReject(() =>
    validateWindowsChannel(
      windowsManifest(),
      '0.0.19',
      encodedPublicKey,
      windowsRelease(),
      async () => signedResponse,
    ),
  )
})

test('a macOS release can never enter or replace the Windows channel', async () => {
  const manifest = windowsManifest()
  manifest.platforms['darwin-aarch64'] = {
    url: 'https://github.com/raydocs/tono/releases/download/mac-build-40/Tono.app.tar.gz',
    signature: encodedSignature,
  }
  await assert.rejects(
    () =>
      validateWindowsChannel(
        manifest,
        '0.0.19',
        encodedPublicKey,
        windowsRelease(),
        async () => signedResponse,
      ),
    /non-Windows platform is forbidden/,
  )
})

test('rejects mutable, cross-version, and unsigned artifact references', async () => {
  for (const url of [
    'https://github.com/raydocs/tono/releases/latest/download/Tono.nsis.zip',
    'https://github.com/raydocs/tono/releases/download/v0.0.20/Tono.nsis.zip',
    'https://example.com/Tono.nsis.zip',
  ]) {
    const manifest = windowsManifest()
    manifest.platforms['windows-x86_64'].url = url
    await assert.rejects(() =>
      validateWindowsChannel(
        manifest,
        '0.0.19',
        encodedPublicKey,
        windowsRelease(),
        async () => signedResponse,
      ),
    )
  }

  const unsigned = windowsManifest()
  unsigned.platforms['windows-x86_64'].signature = ''
  await assert.rejects(() =>
    validateWindowsChannel(
      unsigned,
      '0.0.19',
      encodedPublicKey,
      windowsRelease(),
      async () => signedResponse,
    ),
  )
})

test('normalizes a Tauri action NSIS API asset to its immutable release URL', async () => {
  const manifest = windowsManifest()
  const update = manifest.platforms['windows-x86_64']
  delete manifest.platforms['windows-x86_64']
  manifest.platforms['windows-x86_64-nsis'] = {
    ...update,
    url: windowsRelease().assets[0].url,
  }

  await validateWindowsChannel(
    manifest,
    '0.0.19',
    encodedPublicKey,
    windowsRelease(),
    async () => signedResponse,
  )
  assert.equal(
    manifest.platforms['windows-x86_64-nsis'].url,
    windowsRelease().assets[0].browser_download_url,
  )
})

test('promotion validates before one non-forced atomic channel ref update', async () => {
  const workflow = await readFile(
    new URL(
      '../../../../.github/workflows/windows-update-promote.yml',
      import.meta.url,
    ),
    'utf8',
  )
  assert.doesNotMatch(workflow, /releases\/latest/)
  assert.doesNotMatch(workflow, /git push[^\n]*--force/)
  assert.match(workflow, /HEAD:refs\/heads\/windows-updates/)
  assert.ok(
    workflow.indexOf('validate-windows-channel.mjs') <
      workflow.indexOf('git push origin HEAD:refs/heads/windows-updates'),
  )
})

test('signing and channel write jobs require protected main-only environments', async () => {
  const [releaseWorkflow, promotionWorkflow] = await Promise.all([
    readFile(
      new URL(
        '../../../../.github/workflows/windows-release.yml',
        import.meta.url,
      ),
      'utf8',
    ),
    readFile(
      new URL(
        '../../../../.github/workflows/windows-update-promote.yml',
        import.meta.url,
      ),
      'utf8',
    ),
  ])

  assert.match(releaseWorkflow, /if: github\.ref == 'refs\/heads\/main'/)
  assert.match(releaseWorkflow, /environment: windows-release/)
  assert.match(promotionWorkflow, /if: github\.ref == 'refs\/heads\/main'/)
  assert.match(promotionWorkflow, /environment: windows-update-channel/)
})
