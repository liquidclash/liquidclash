import { describe, expect, it } from 'vitest'

import { nodeRegion } from './node-meta'

describe('nodeRegion', () => {
  it('matches US and JP as whole tokens like the verified-catalog sorter', () => {
    expect(nodeRegion('🇺🇸 US Reality 01')).toBe('us')
    expect(nodeRegion('jp-west')).toBe('jp')
    expect(nodeRegion('JPN East')).toBe('other')
    expect(nodeRegion('Rust Server')).toBe('other')
  })
})
