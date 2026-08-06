import { describe, expect, it } from 'vitest'

import { compareVersions } from '@/services/update'

describe('Tono updater version comparison', () => {
  it('orders stable and prerelease SemVer correctly', () => {
    expect(compareVersions('0.0.19', '0.0.18')).toBe(1)
    expect(compareVersions('0.0.19-rc.1', '0.0.19')).toBe(-1)
    expect(compareVersions('0.0.19', '0.0.19-rc.2')).toBe(1)
    expect(compareVersions('0.0.19-rc.10', '0.0.19-rc.2')).toBe(1)
    expect(compareVersions('1.0.0-2', '1.0.0-1a')).toBe(-1)
    expect(
      compareVersions('9007199254740993.0.0', '9007199254740992.0.0'),
    ).toBe(1)
  })

  it('ignores build metadata for precedence', () => {
    expect(compareVersions('0.0.19+windows.2', '0.0.19+windows.1')).toBe(0)
  })

  it('rejects malformed or incomplete versions', () => {
    expect(compareVersions('release-0.0.19', '0.0.18')).toBeNull()
    expect(compareVersions('0.0', '0.0.18')).toBeNull()
    expect(compareVersions('00.0.19', '0.0.18')).toBeNull()
  })
})
