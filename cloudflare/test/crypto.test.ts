import { describe, expect, it } from 'vitest';
import {
  decryptCatalog,
  decryptTrafficPolicy,
  encryptCatalog,
  encryptTrafficPolicy,
  hmacSha256,
  jwtSign,
  jwtVerify,
  sha256,
} from '../src/crypto';
describe('security primitives', () => {
  it('signs and rejects modified JWTs', async () => { const t=await jwtSign({sub:'u',exp:Math.floor(Date.now()/1000)+60},'secret'); expect((await jwtVerify(t,'secret')).sub).toBe('u'); expect(await jwtVerify(t+'x','secret')).toBeNull(); });
  it('hash is deterministic', async () => expect(await sha256('x')).toBe(await sha256('x')));
  it('keys challenge hashes with HMAC', async () => {
    expect(await hmacSha256('challenge', 'secret-one')).toBe(await hmacSha256('challenge', 'secret-one'));
    expect(await hmacSha256('challenge', 'secret-one')).not.toBe(await hmacSha256('challenge', 'secret-two'));
  });
  it('encrypts managed catalogs with authenticated AES-GCM', async () => {
    const key = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY';
    const encrypted = await encryptCatalog('proxies: []\n', key);
    expect(encrypted.ciphertext).not.toContain('proxies');
    expect(await decryptCatalog(encrypted.ciphertext, encrypted.nonce, key))
      .toBe('proxies: []\n');
    await expect(decryptCatalog(`${encrypted.ciphertext}A`, encrypted.nonce, key))
      .rejects.toBeTruthy();
  });
  it('uses distinct authenticated encryption context for traffic policies', async () => {
    const key = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY';
    const plaintext = '{"version":1,"domains":[],"mediaEndpoints":[]}';
    const encrypted = await encryptTrafficPolicy(plaintext, key);
    expect(await decryptTrafficPolicy(encrypted.ciphertext, encrypted.nonce, key)).toBe(plaintext);
    await expect(decryptCatalog(encrypted.ciphertext, encrypted.nonce, key)).rejects.toBeTruthy();
  });
});
