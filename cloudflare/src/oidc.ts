type JsonWebKeySet = { keys: JsonWebKey[] };
type SigningJWK = JsonWebKey & { kid: string };

export type OidcProvider = 'apple' | 'google';

export class OidcVerificationError extends Error {
  constructor(message: string, public readonly temporary = false) {
    super(message);
  }
}

export interface OidcIdentity {
  provider: OidcProvider;
  subject: string;
  email?: string;
  emailVerified: boolean;
  nonce: string;
}

interface ProviderConfiguration {
  audience: string;
  issuers: string[];
  jwksURL: string;
}

interface CachedKeys {
  expiresAt: number;
  fetchedAt: number;
  keys: SigningJWK[];
}

const keyCache = new Map<string, CachedKeys>();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

function decodeBase64URL(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length > 64_000) {
    throw new OidcVerificationError('Invalid base64url value');
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - value.length % 4) % 4);
  const decoded = atob(padded);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function decodeObject(value: string): Record<string, unknown> {
  const decoded = JSON.parse(textDecoder.decode(decodeBase64URL(value)));
  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) {
    throw new OidcVerificationError('Invalid JWT object');
  }
  return decoded as Record<string, unknown>;
}

function cacheSeconds(header: string | null): number {
  const match = header?.match(/(?:^|,)\s*max-age=(\d+)\b/i);
  const parsed = match ? Number(match[1]) : 300;
  return Number.isSafeInteger(parsed) ? Math.min(3_600, Math.max(60, parsed)) : 300;
}

function validJWK(value: unknown): value is SigningJWK {
  if (value === null || typeof value !== 'object') return false;
  const key = value as Record<string, unknown>;
  return key.kty === 'RSA' &&
    typeof key.kid === 'string' && key.kid.length >= 1 && key.kid.length <= 200 &&
    typeof key.n === 'string' && key.n.length >= 128 && key.n.length <= 4_096 &&
    typeof key.e === 'string' && key.e.length >= 2 && key.e.length <= 16 &&
    (key.use === undefined || key.use === 'sig') &&
    (key.alg === undefined || key.alg === 'RS256');
}

async function fetchKeys(url: string, force = false): Promise<SigningJWK[]> {
  const current = keyCache.get(url);
  const currentTime = Date.now();
  if (
    current &&
    current.expiresAt > currentTime &&
    (!force || current.fetchedAt > currentTime - 60_000)
  ) {
    return current.keys;
  }

  let response: Response;
  try {
    response = await fetch(url, {
      headers: { accept: 'application/json' },
      redirect: 'manual',
    });
  } catch {
    throw new OidcVerificationError('OIDC key service failed', true);
  }
  if (!response.ok) throw new OidcVerificationError('OIDC key service failed', true);
  const declaredLength = Number(response.headers.get('content-length') ?? '0');
  if (Number.isFinite(declaredLength) && declaredLength > 256 * 1024) {
    throw new OidcVerificationError('OIDC key response too large', true);
  }
  const raw = await response.text();
  if (raw.length > 256 * 1024) {
    throw new OidcVerificationError('OIDC key response too large', true);
  }
  let parsed: JsonWebKeySet;
  try {
    parsed = JSON.parse(raw) as JsonWebKeySet;
  } catch {
    throw new OidcVerificationError('Invalid OIDC key set', true);
  }
  if (!Array.isArray(parsed?.keys) || parsed.keys.length < 1 || parsed.keys.length > 20) {
    throw new OidcVerificationError('Invalid OIDC key set', true);
  }
  const keys = parsed.keys.filter(validJWK);
  if (keys.length < 1) throw new OidcVerificationError('No usable OIDC signing keys', true);
  keyCache.set(url, {
    fetchedAt: currentTime,
    expiresAt: currentTime + cacheSeconds(response.headers.get('cache-control')) * 1_000,
    keys,
  });
  return keys;
}

async function signingKey(configuration: ProviderConfiguration, kid: string): Promise<SigningJWK> {
  let keys = await fetchKeys(configuration.jwksURL);
  let key = keys.find((candidate) => candidate.kid === kid);
  if (!key) {
    keys = await fetchKeys(configuration.jwksURL, true);
    key = keys.find((candidate) => candidate.kid === kid);
  }
  if (!key) throw new OidcVerificationError('Unknown OIDC signing key');
  return key;
}

function audienceMatches(value: unknown, expected: string, authorizedParty: unknown): boolean {
  if (typeof value === 'string') return value === expected;
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) return false;
  if (!value.includes(expected)) return false;
  return value.length === 1 || authorizedParty === expected;
}

function verifiedEmail(value: unknown): boolean {
  return value === true || value === 'true';
}

function normalizedEmail(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (
    normalized.length < 3 ||
    normalized.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)
  ) {
    return undefined;
  }
  return normalized;
}

export async function verifyOidcIdToken(
  provider: OidcProvider,
  token: string,
  audience: string,
  currentTime = Math.floor(Date.now() / 1_000),
): Promise<OidcIdentity> {
  if (token.length < 100 || token.length > 16_384 || audience.length < 1 || audience.length > 512) {
    throw new OidcVerificationError('Invalid OIDC token');
  }
  const configuration: ProviderConfiguration = provider === 'apple'
    ? {
      audience,
      issuers: ['https://appleid.apple.com'],
      jwksURL: 'https://appleid.apple.com/auth/keys',
    }
    : {
      audience,
      issuers: ['https://accounts.google.com', 'accounts.google.com'],
      jwksURL: 'https://www.googleapis.com/oauth2/v3/certs',
    };

  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new OidcVerificationError('Invalid OIDC token');
  }
  const header = decodeObject(parts[0]);
  const claims = decodeObject(parts[1]);
  if (
    header.alg !== 'RS256' ||
    typeof header.kid !== 'string' ||
    header.kid.length < 1 ||
    header.kid.length > 200
  ) {
    throw new OidcVerificationError('Unsupported OIDC signature');
  }

  const jwk = await signingKey(configuration, header.kid);
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
  } catch {
    throw new OidcVerificationError('OIDC signing key could not be imported', true);
  }
  const validSignature = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    decodeBase64URL(parts[2]).buffer as ArrayBuffer,
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!validSignature) throw new OidcVerificationError('Invalid OIDC signature');

  const expiresAt = claims.exp;
  const issuedAt = claims.iat;
  if (
    !configuration.issuers.includes(String(claims.iss ?? '')) ||
    !audienceMatches(claims.aud, configuration.audience, claims.azp) ||
    !Number.isSafeInteger(expiresAt) ||
    Number(expiresAt) <= currentTime ||
    !Number.isSafeInteger(issuedAt) ||
    Number(issuedAt) > currentTime + 300
  ) {
    throw new OidcVerificationError('Invalid OIDC claims');
  }
  if (
    typeof claims.sub !== 'string' ||
    claims.sub.length < 1 ||
    claims.sub.length > 255 ||
    /[\u0000-\u001f\u007f]/.test(claims.sub) ||
    typeof claims.nonce !== 'string' ||
    claims.nonce.length < 8 ||
    claims.nonce.length > 512
  ) {
    throw new OidcVerificationError('Invalid OIDC identity');
  }

  const email = normalizedEmail(claims.email);
  const emailVerified = email !== undefined && verifiedEmail(claims.email_verified);
  return {
    provider,
    subject: claims.sub,
    email,
    emailVerified,
    nonce: claims.nonce,
  };
}
