import {
  createExecutionContext,
  createScheduledController,
  env,
  waitOnExecutionContext,
} from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { jwtSign } from '../src/crypto';
import worker, { type Env } from '../src/index';

const ADMIN_TOKEN = 'admin-test-token-with-at-least-32-characters';
const HOME_TOKEN = 'home-test-token-with-at-least-32-characters';
const JWT_TEST_SECRET = 'test-jwt-secret-with-at-least-32-characters';

const api = async (path: string, init: RequestInit = {}) => {
  const context = createExecutionContext();
  const response = await worker.fetch(
    new Request(`https://test/api/v1/${path}`, init),
    env as unknown as Env,
    context,
  );
  await waitOnExecutionContext(context);
  return response;
};
const json = (value: unknown, token?: string): RequestInit => ({
  method: 'POST',
  headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: JSON.stringify(value),
});
const admin = (path: string, value?: unknown, method = 'POST') => api(`admin/${path}`, {
  ...(value === undefined ? {} : json(value)), method,
  headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
});

/** Deliberately distinct Tailscale identity values (production mismatch case). */
const MGMT_ID = 'mgmt-abc';
const API_NODE_ID = 'nodeid-xyz';
const STABLE_ID = 'stable-n123';
const PUBLIC_KEY = 'public-key-123';
const TS_IPS = ['100.64.0.10'];
const OIDC_KEY_ID = 'test-oidc-key';
const GOOGLE_AUDIENCE = 'test-google-client.apps.googleusercontent.com';
const APPLE_AUDIENCE = 'com.raydocs.tono';

let sequence = 0;
const tailscaleRequests: string[] = [];
const emailCodes = new Map<string, string>();
let oidcPrivateKey: CryptoKey;
let oidcPublicKey: JsonWebKey & { kid: string };

/** In-memory mock inventory; tags mutate after promotion. */
const mockInventory: Array<{
  id: string;
  nodeId: string;
  name: string;
  nodeKey: string;
  stableNodeId?: string;
  addresses: string[];
  tags: string[];
  description?: string;
}> = [];

function resetMockInventory(
  deviceIdForDesc?: string,
  enrollmentHostname = 'tono-00000000000000000000000000000000',
) {
  mockInventory.length = 0;
  mockInventory.push({
    id: MGMT_ID,
    nodeId: API_NODE_ID,
    name: enrollmentHostname,
    nodeKey: `nodekey:${PUBLIC_KEY}`,
    addresses: [...TS_IPS],
    tags: ['tag:pending-tunnel-client'],
    description: deviceIdForDesc ? `tono-device-${deviceIdForDesc}` : undefined,
  });
}

let failNextTagPromotion = false;
let failNextKeyIssue = false;
let failNextDelete = false;
let tagPromotionGate: Promise<void> | undefined;
let releaseTagPromotion: (() => void) | undefined;
let notifyTagPromotionStarted: (() => void) | undefined;

function pauseNextTagPromotion() {
  let startedResolve!: () => void;
  const started = new Promise<void>((resolve) => { startedResolve = resolve; });
  notifyTagPromotionStarted = startedResolve;
  tagPromotionGate = new Promise<void>((resolve) => { releaseTagPromotion = resolve; });
  return {
    started,
    release() {
      releaseTagPromotion?.();
      releaseTagPromotion = undefined;
    },
  };
}

async function createAccount(prefix: string) {
  const email = `${prefix}-${++sequence}@example.com`;
  const response = await emailSignIn({
    email,
    deviceName: 'Primary Mac',
    installationId: `${prefix}-installation-one`,
  });
  expect(response.status).toBe(200);
  return { email, ...(await response.json() as any) };
}

async function startEmailSignIn(body: {
  email: string;
  deviceName: string;
  installationId: string;
}) {
  const response = await api('auth/email/start', json(body));
  const payload = await response.json() as any;
  return {
    response,
    challengeId: payload.challengeId as string,
    code: emailCodes.get(payload.challengeId as string),
  };
}

async function emailSignIn(body: {
  email: string;
  deviceName: string;
  installationId: string;
}) {
  const started = await startEmailSignIn(body);
  if (started.response.status !== 202 || !started.code) return started.response;
  return api('auth/email/verify', json({
    challengeId: started.challengeId,
    code: started.code,
  }));
}

function base64URL(value: Uint8Array): string {
  let raw = '';
  for (const byte of value) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function oidcToken(
  provider: 'apple' | 'google',
  nonce: string,
  options: { subject?: string; email?: string; audience?: string } = {},
) {
  const timestamp = Math.floor(Date.now() / 1_000);
  const header = base64URL(new TextEncoder().encode(JSON.stringify({
    alg: 'RS256',
    kid: OIDC_KEY_ID,
    typ: 'JWT',
  })));
  const payload = base64URL(new TextEncoder().encode(JSON.stringify({
    iss: provider === 'apple' ? 'https://appleid.apple.com' : 'https://accounts.google.com',
    aud: options.audience ?? (provider === 'apple' ? APPLE_AUDIENCE : GOOGLE_AUDIENCE),
    sub: options.subject ?? `${provider}-subject-${sequence}`,
    email: options.email ?? `${provider}-${sequence}@example.com`,
    email_verified: true,
    nonce,
    iat: timestamp,
    exp: timestamp + 300,
  })));
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    oidcPrivateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  );
  return `${header}.${payload}.${base64URL(new Uint8Array(signature))}`;
}

async function confirm(
  auth: any,
  body: {
    stableNodeId?: string;
    nodeId?: string;
    publicKey?: string;
    tailscaleIPs?: string[];
  } = {},
) {
  const response = await api(`devices/${auth.device.id}/confirm`, json({
    stableNodeId: body.stableNodeId ?? STABLE_ID,
    ...(body.nodeId !== undefined ? { nodeId: body.nodeId } : {}),
    publicKey: body.publicKey ?? PUBLIC_KEY,
    tailscaleIPs: body.tailscaleIPs ?? TS_IPS,
  }, auth.accessToken));
  return response;
}

describe('Worker routes with D1 and mocked Tailscale', () => {
  beforeAll(async () => {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair;
    oidcPrivateKey = keyPair.privateKey;
    oidcPublicKey = {
      ...await crypto.subtle.exportKey('jwk', keyPair.publicKey),
      kid: OIDC_KEY_ID,
      use: 'sig',
      alg: 'RS256',
    };

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const request = input instanceof Request ? input : new Request(String(input), init);
      const url = request.url;
      const method = request.method;
      const requestBody = request.body
        ? new TextDecoder().decode(await request.arrayBuffer())
        : '';

      if (url === 'https://api.resend.com/emails' && method === 'POST') {
        const payload = JSON.parse(requestBody) as any;
        const code = String(payload.text ?? '').match(/\b(\d{6})\b/)?.[1];
        const challenge = request.headers.get('idempotency-key');
        if (!code || !challenge) return new Response('invalid email payload', { status: 400 });
        emailCodes.set(challenge, code);
        return Response.json({ id: `email-${challenge}` });
      }

      if (
        (url === 'https://www.googleapis.com/oauth2/v3/certs' ||
          url === 'https://appleid.apple.com/auth/keys') &&
        method === 'GET'
      ) {
        return Response.json(
          { keys: [oidcPublicKey] },
          { headers: { 'cache-control': 'public, max-age=300' } },
        );
      }

      tailscaleRequests.push(`${method} ${url} ${requestBody}`);

      if (url.endsWith('/oauth/token')) {
        return Response.json({ access_token: 'mock-oauth' });
      }

      if (url.includes('/keys') && method === 'POST') {
        if (failNextKeyIssue) {
          failNextKeyIssue = false;
          return new Response('key failure', { status: 500 });
        }
        return Response.json({ key: `tskey-mock-${++sequence}`, expires: '2099-01-01T00:00:00Z' });
      }

      // Inventory list — primary resolution path
      if (url.includes('/tailnet/') && url.includes('/devices') && method === 'GET') {
        return Response.json({ devices: mockInventory });
      }

      // Tag promotion / delete must use management id only
      if (url.includes(`/device/${encodeURIComponent(MGMT_ID)}/tags`) && method === 'POST') {
        if (failNextTagPromotion) {
          failNextTagPromotion = false;
          return new Response('tag failure', { status: 500 });
        }
        if (tagPromotionGate) {
          notifyTagPromotionStarted?.();
          const gate = tagPromotionGate;
          tagPromotionGate = undefined;
          notifyTagPromotionStarted = undefined;
          await gate;
        }
        const device = mockInventory.find((d) => d.id === MGMT_ID);
        if (device) device.tags = ['tag:tunnel-client'];
        return new Response(null, { status: 200 });
      }

      if (url.includes(`/device/${encodeURIComponent(MGMT_ID)}`) && method === 'DELETE') {
        if (failNextDelete) {
          failNextDelete = false;
          return new Response('delete failure', { status: 500 });
        }
        const idx = mockInventory.findIndex((d) => d.id === MGMT_ID);
        if (idx >= 0) mockInventory.splice(idx, 1);
        return new Response(null, { status: 204 });
      }

      // Reject legacy client-id GET path used with wrong identifiers
      if (url.includes('/device/') && method === 'GET') {
        return new Response(null, { status: 404 });
      }

      if (url.includes('/device/') && method === 'DELETE') {
        return new Response(null, { status: 204 });
      }

      if (url.includes('/device/') && url.includes('/tags') && method === 'POST') {
        return new Response(null, { status: 200 });
      }

      return new Response(null, { status: 404 });
    });
  });

  beforeEach(async () => {
    (env as unknown as Env).TAILSCALE_ENROLLMENT_ENABLED = 'true';
    releaseTagPromotion?.();
    tailscaleRequests.length = 0;
    emailCodes.clear();
    failNextTagPromotion = false;
    failNextKeyIssue = false;
    failNextDelete = false;
    tagPromotionGate = undefined;
    releaseTagPromotion = undefined;
    notifyTagPromotionStarted = undefined;
    resetMockInventory();
    // Rate-limit counters persist in D1 across tests; reset so limits stay isolated
    await env.DB.prepare('DELETE FROM rate_limits').run();
  });

  it('sets defensive response headers and rejects an empty bearer token', async () => {
    const health = await api('health');
    expect(health.status).toBe(200);
    expect(health.headers.get('cache-control')).toBe('no-store');
    expect(health.headers.get('content-security-policy')).toContain("default-src 'self'");
    expect(health.headers.get('x-content-type-options')).toBe('nosniff');

    const preflight = await api('health', {
      method: 'OPTIONS',
      headers: { origin: String((env as unknown as Env).ALLOWED_ORIGIN) },
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('access-control-allow-methods')).toContain('PUT');

    const empty = await api('admin/users', {
      headers: { authorization: 'Bearer ' },
    });
    expect(empty.status).toBe(401);
  });

  it('serves an isolated release archive on the release subdomain', async () => {
    const fetchRelease = async (path: string, init: RequestInit = {}) => {
      const context = createExecutionContext();
      const response = await worker.fetch(
        new Request(`https://releases.afk.ccwu.cc${path}`, init),
        env as unknown as Env,
        context,
      );
      await waitOnExecutionContext(context);
      return response;
    };

    const page = await fetchRelease('/');
    expect(page.status).toBe(200);
    expect(page.headers.get('location')).toBeNull();
    expect(page.headers.get('content-security-policy')).toContain("default-src 'self'");
    expect(await page.text()).toContain('Tono 发布档案');

    const canonicalPage = await fetchRelease('/releases/');
    expect(canonicalPage.status).toBe(200);
    expect(await canonicalPage.text()).toContain('Tono 发布档案');

    const manifest = await fetchRelease('/manifest.json');
    expect(manifest.status).toBe(200);
    expect(await manifest.json()).toMatchObject({
      schemaVersion: 1,
      channel: 'test',
      platforms: {
        macos: { current: { build: 37 } },
        windows: {
          current: {
            version: '2.5.4',
            build: 'test5',
            trafficPolicySchemas: [1, 2],
            artifact: {
              sha256: '0cfd68444aefded4ed9bc2d687f4ce9d481e980f08940b5e65249e0fd393bb88',
            },
          },
        },
      },
    });

    const appcast = await fetchRelease('/macos/appcast.xml');
    expect(appcast.status).toBe(200);
    expect(await appcast.text()).toContain('<sparkle:version>37</sparkle:version>');

    expect((await fetchRelease('/api/v1/health')).status).toBe(404);
    const rejected = await fetchRelease('/manifest.json', { method: 'POST' });
    expect(rejected.status).toBe(405);
    expect(rejected.headers.get('allow')).toBe('GET, HEAD');
  });

  it('does not report success when an admin patches a missing user', async () => {
    const response = await admin(`users/${crypto.randomUUID()}`, { status: 'disabled' }, 'PATCH');
    expect(response.status).toBe(404);
    expect((await response.json() as any).error.code).toBe('NOT_FOUND');
  });

  it('manages exact signup access without a Worker redeployment', async () => {
    const address = `managed-user-${++sequence}@outside.test`;
    const unauthorized = await api('admin/signup-allowlist');
    expect(unauthorized.status).toBe(401);

    const added = await admin('signup-allowlist', { email: address.toUpperCase() });
    expect(added.status).toBe(201);
    expect(await added.json()).toEqual({
      email: address,
      createdAt: expect.any(Number),
      created: true,
    });

    const duplicate = await admin('signup-allowlist', { email: address });
    expect(duplicate.status).toBe(200);
    expect((await duplicate.json() as any).created).toBe(false);

    const listed = await admin('signup-allowlist', undefined, 'GET');
    expect(listed.status).toBe(200);
    expect((await listed.json() as any).entries).toContainEqual({
      email: address,
      createdAt: expect.any(Number),
    });

    const login = await emailSignIn({
      email: address,
      deviceName: 'Managed user Mac',
      installationId: 'managed-user-installation-one',
    });
    expect(login.status).toBe(200);

    const removed = await admin('signup-allowlist', { email: address }, 'DELETE');
    expect(removed.status).toBe(204);
    const afterRemoval = await admin('signup-allowlist', undefined, 'GET');
    expect((await afterRemoval.json() as any).entries).not.toContainEqual(
      expect.objectContaining({ email: address }),
    );

    const blocked = await startEmailSignIn({
      email: `removed-user-${sequence}@outside.test`,
      deviceName: 'Removed user Mac',
      installationId: 'removed-user-installation-one',
    });
    expect(blocked.response.status).toBe(202);
    expect(blocked.code).toBeUndefined();
  });

  it('advertises configured passwordless methods and retires password routes', async () => {
    const methods = await api('auth/methods');
    expect(methods.status).toBe(200);
    expect(await methods.json()).toEqual({
      email: { enabled: true },
      apple: { enabled: true },
      google: { enabled: true, clientId: GOOGLE_AUDIENCE },
    });

    for (const route of ['auth/login', 'auth/redeem']) {
      const retired = await api(route, json({}));
      expect(retired.status).toBe(410);
      expect((await retired.json() as any).error.code).toBe('PASSWORD_AUTH_DISABLED');
    }
  });

  it('activates a VLESS-only device without contacting Tailscale', async () => {
    const cloudOnlyEnv = Object.create(env) as Env;
    cloudOnlyEnv.TAILSCALE_ENROLLMENT_ENABLED = 'false';
    const started = await startEmailSignIn({
      email: `cloud-only-${++sequence}@example.com`,
      deviceName: 'Reality Mac',
      installationId: 'cloud-only-installation-one',
    });
    expect(started.response.status).toBe(202);
    expect(started.code).toBeTruthy();

    const invoke = async (path: string, init: RequestInit) => {
      const context = createExecutionContext();
      const response = await worker.fetch(
        new Request(`https://test/api/v1/${path}`, init),
        cloudOnlyEnv,
        context,
      );
      await waitOnExecutionContext(context);
      return response;
    };
    const response = await invoke('auth/email/verify', json({
      challengeId: started.challengeId,
      code: started.code,
    }));
    expect(response.status).toBe(200);
    const account = await response.json() as any;
    expect(account.device.status).toBe('active');
    expect(account.device.pendingExpiresAt).toBeNull();
    expect(account.device.confirmedAt).toEqual(expect.any(Number));
    expect(account.enrollment).toBeUndefined();
    expect(tailscaleRequests).toEqual([]);

    const enrollment = await invoke(
      `devices/${account.device.id}/enrollment`,
      json({ installationId: 'cloud-only-installation-one' }, account.accessToken),
    );
    expect(enrollment.status).toBe(410);
    expect((await enrollment.json() as any).error.code).toBe('TAILSCALE_DISABLED');
    expect(tailscaleRequests).toEqual([]);
  });

  it('encrypts, versions, and serves the managed exit catalog only to authenticated users', async () => {
    const yaml = `proxies:
  - name: "Managed Test"
    type: vless
    server: 8.8.4.4
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
`;
    expect((await api('exit-catalog')).status).toBe(401);

    const created = await admin('exit-catalog', { yaml, expectedRevision: 0 }, 'PUT');
    expect(created.status).toBe(200);
    const createdBody = await created.json() as any;
    expect(createdBody.revision).toBe(1);

    const stored = await env.DB.prepare(
      'SELECT revision, ciphertext, nonce, content_sha256 FROM managed_exit_catalog WHERE singleton_id = 1',
    ).first<any>();
    expect(stored.revision).toBe(1);
    expect(stored.ciphertext).not.toContain('Managed Test');
    expect(stored.ciphertext).not.toContain('11111111-1111-4111-8111-111111111111');
    expect(stored.nonce).not.toBe('');

    const adminFetched = await admin('exit-catalog', undefined, 'GET');
    expect(adminFetched.status).toBe(200);
    expect(await adminFetched.json()).toEqual({
      revision: 1,
      yaml,
      sha256: stored.content_sha256,
      updatedAt: createdBody.updatedAt,
    });

    const account = await createAccount('managed-catalog');
    const fetched = await api('exit-catalog', {
      headers: { authorization: `Bearer ${account.accessToken}` },
    });
    expect(fetched.status).toBe(200);
    expect(await fetched.json()).toEqual({
      revision: 1,
      yaml,
      sha256: stored.content_sha256,
      updatedAt: createdBody.updatedAt,
    });

    const conflict = await admin(
      'exit-catalog',
      { yaml: 'proxies: []\n', expectedRevision: 0 },
      'PUT',
    );
    expect(conflict.status).toBe(409);
    expect((await conflict.json() as any).error.code).toBe('CATALOG_CONFLICT');

    const cleared = await admin(
      'exit-catalog',
      { yaml: 'proxies: []', expectedRevision: 1 },
      'PUT',
    );
    expect(cleared.status).toBe(200);
    expect((await cleared.json() as any).revision).toBe(2);

    const utf8Oversized = await admin(
      'exit-catalog',
      { yaml: `proxies:\n${'#界\n'.repeat(210_000)}`, expectedRevision: 2 },
      'PUT',
    );
    expect(utf8Oversized.status).toBe(400);
    expect((await utf8Oversized.json() as any).error.code).toBe('INVALID_CATALOG');
  });

  it('validates, encrypts, versions, and serves the managed traffic policy', async () => {
    expect((await api('traffic-policy')).status).toBe(401);
    const empty = await admin('traffic-policy', undefined, 'GET');
    expect(empty.status).toBe(200);
    expect((await empty.json() as any).revision).toBe(0);

    const policy = {
      mediaEndpoints: [{ ports: [8000, 443], address: '43.146.27.17' }],
      domains: [
        { ports: [443, 80], host: 'wx.qlogo.cn' },
        { host: 'res.wx.qq.com', ports: [443] },
      ],
      version: 1,
    };
    const created = await admin('traffic-policy', { policy, expectedRevision: 0 }, 'PUT');
    expect(created.status).toBe(200);
    const createdBody = await created.json() as any;
    expect(JSON.parse(createdBody.json)).toEqual({
      version: 1,
      domains: [
        { host: 'res.wx.qq.com', ports: [443] },
        { host: 'wx.qlogo.cn', ports: [80, 443] },
      ],
      mediaEndpoints: [{ address: '43.146.27.17', ports: [443, 8000] }],
    });
    const stored = await env.DB.prepare(
      'SELECT ciphertext, nonce, content_sha256 FROM managed_traffic_policy WHERE singleton_id = 1',
    ).first<any>();
    expect(stored.ciphertext).not.toContain('res.wx.qq.com');
    expect(stored.ciphertext).not.toContain('43.146.27.17');
    expect(stored.nonce).not.toBe('');
    expect(createdBody.sha256).toBe(stored.content_sha256);
    expect(await (await admin('traffic-policy', undefined, 'GET')).json()).toEqual(createdBody);

    const account = await createAccount('managed-traffic-policy');
    const fetched = await api('traffic-policy', {
      headers: { authorization: `Bearer ${account.accessToken}` },
    });
    expect(await fetched.json()).toEqual(createdBody);
    const conflict = await admin('traffic-policy', { policy, expectedRevision: 0 }, 'PUT');
    expect(conflict.status).toBe(409);

    const webPolicy = {
      ...policy,
      version: 2,
      webDomains: [
        { host: 'www.bilibili.com', ports: [443] },
        { host: 'ykimg.alicdn.com', ports: [443] },
      ],
    };
    const updated = await admin(
      'traffic-policy',
      { policy: webPolicy, expectedRevision: 1 },
      'PUT',
    );
    expect(updated.status).toBe(200);
    expect(JSON.parse((await updated.json() as any).json)).toEqual({
      version: 2,
      domains: [
        { host: 'res.wx.qq.com', ports: [443] },
        { host: 'wx.qlogo.cn', ports: [80, 443] },
      ],
      mediaEndpoints: [{ address: '43.146.27.17', ports: [443, 8000] }],
      webDomains: [
        { host: 'www.bilibili.com', ports: [443] },
        { host: 'ykimg.alicdn.com', ports: [443] },
      ],
    });

    const invalidPolicies = [
      { ...policy, version: 3 },
      { ...policy, version: 2 },
      { ...policy, domains: [{ host: '*.qq.com', ports: [443] }] },
      { ...policy, domains: [{ host: 'api.anthropic.com', ports: [443] }] },
      { ...policy, domains: [{ host: 'res.wx.qq.com', ports: [22] }] },
      { ...policy, mediaEndpoints: [{ address: '10.0.0.1', ports: [443] }] },
      { ...policy, mediaEndpoints: [{ address: '43.146.27.0/24', ports: [443] }] },
      { ...policy, mediaEndpoints: [{ address: '43.146.27.999', ports: [443] }] },
      { ...policy, mediaEndpoints: [{ address: '43.146.27.17', ports: [80] }] },
      { ...webPolicy, webDomains: [{ host: '*.bilibili.com', ports: [443] }] },
      { ...webPolicy, webDomains: [{ host: 'api.anthropic.com', ports: [443] }] },
      { ...webPolicy, webDomains: [{ host: 'www.bilibili.com', ports: [80] }] },
      {
        ...webPolicy,
        domains: [{ host: 'v.qq.com', ports: [443] }],
        webDomains: [{ host: 'v.qq.com', ports: [443] }],
      },
    ];
    for (const invalid of invalidPolicies) {
      const response = await admin('traffic-policy', { policy: invalid, expectedRevision: 2 }, 'PUT');
      expect(response.status).toBe(400);
      expect((await response.json() as any).error.code).toBe('VALIDATION_ERROR');
    }
  });

  it('creates an account directly from a verified email and consumes one code winner atomically', async () => {
    const email = `email-otp-${++sequence}@example.com`;
    const started = await startEmailSignIn({
      email,
      deviceName: 'Primary Mac',
      installationId: 'email-otp-installation',
    });
    expect(started.response.status).toBe(202);
    expect(started.code).toMatch(/^\d{6}$/);

    const stored = await env.DB.prepare(
      'SELECT secret_hash, consumed_at FROM auth_challenges WHERE id = ?',
    ).bind(started.challengeId).first<any>();
    expect(stored.secret_hash).not.toContain(started.code);
    expect(stored.consumed_at).toBeNull();

    const attempts = await Promise.all([
      api('auth/email/verify', json({ challengeId: started.challengeId, code: started.code })),
      api('auth/email/verify', json({ challengeId: started.challengeId, code: started.code })),
    ]);
    expect(attempts.map((response) => response.status).sort()).toEqual([200, 401]);
    expect((await api('auth/email/verify', json({
      challengeId: started.challengeId,
      code: started.code,
    }))).status).toBe(401);

    const identity = await env.DB.prepare(
      "SELECT provider, subject FROM auth_identities WHERE provider = 'email'",
    ).first<any>();
    expect(identity).toEqual({ provider: 'email', subject: email });

    const secondEmail = `direct-${sequence}@example.com`;
    const direct = await emailSignIn({
      email: secondEmail,
      deviceName: 'Direct Mac',
      installationId: 'direct-email-installation',
    });
    expect(direct.status).toBe(200);
    expect((await direct.json() as any).user.email).toBe(secondEmail);

    const outsideAllowlist = await startEmailSignIn({
      email: `outside-${sequence}@unauthorized.invalid`,
      deviceName: 'Unknown Mac',
      installationId: 'outside-allowlist-installation',
    });
    expect(outsideAllowlist.response.status).toBe(202);
    expect(outsideAllowlist.code).toBeUndefined();
  });

  it('verifies Google OIDC signature, audience, nonce, direct signup, and replay protection', async () => {
    const email = `google-${++sequence}@example.com`;
    const challengeResponse = await api('auth/oidc/challenge', json({
      provider: 'google',
      deviceName: 'Google Mac',
      installationId: 'google-installation',
    }));
    expect(challengeResponse.status).toBe(200);
    const challenge = await challengeResponse.json() as any;
    const stored = await env.DB.prepare(
      'SELECT secret_hash FROM auth_challenges WHERE id = ?',
    ).bind(challenge.challengeId).first<any>();
    expect(stored.secret_hash).not.toBe(challenge.nonce);

    const wrongAudience = await oidcToken('google', challenge.nonce, {
      subject: 'google-user-1',
      email,
      audience: 'attacker-client.example',
    });
    expect((await api('auth/oidc/verify', json({
      provider: 'google',
      challengeId: challenge.challengeId,
      idToken: wrongAudience,
    }))).status).toBe(401);

    const validToken = await oidcToken('google', challenge.nonce, {
      subject: 'google-user-1',
      email,
    });
    const verified = await api('auth/oidc/verify', json({
      provider: 'google',
      challengeId: challenge.challengeId,
      idToken: validToken,
    }));
    expect(verified.status).toBe(200);
    expect((await verified.json() as any).user.email).toBe(email);
    expect((await api('auth/oidc/verify', json({
      provider: 'google',
      challengeId: challenge.challengeId,
      idToken: validToken,
    }))).status).toBe(401);

    const identity = await env.DB.prepare(
      "SELECT user_id, email FROM auth_identities WHERE provider = 'google' AND subject = ?",
    ).bind('google-user-1').first<any>();
    expect(identity.email).toBe(email);
  });

  it('links a verified Apple identity to the matching existing account', async () => {
    const account = await createAccount('apple-link');
    const challengeResponse = await api('auth/oidc/challenge', json({
      provider: 'apple',
      deviceName: 'Apple Mac',
      installationId: 'apple-link-installation-two',
    }));
    const challenge = await challengeResponse.json() as any;
    const token = await oidcToken('apple', challenge.nonce, {
      subject: 'apple-linked-subject',
      email: account.email,
    });
    const linked = await api('auth/oidc/verify', json({
      provider: 'apple',
      challengeId: challenge.challengeId,
      idToken: token,
    }));
    expect(linked.status).toBe(200);
    expect((await linked.json() as any).user.id).toBe(account.user.id);
    const identity = await env.DB.prepare(
      "SELECT user_id FROM auth_identities WHERE provider = 'apple' AND subject = ?",
    ).bind('apple-linked-subject').first<any>();
    expect(identity.user_id).toBe(account.user.id);
  });

  it('redeems, confirms, logs in without duplicating an installation, rotates refresh, and limits devices', async () => {
    const first = await createAccount('lifecycle');
    resetMockInventory(first.device.id, first.enrollment.hostname);
    const refresh = await api('auth/refresh', json({ refreshToken: first.refreshToken }));
    expect(refresh.status).toBe(200);
    const rotated = await refresh.json() as any;
    expect((await api('auth/refresh', json({ refreshToken: first.refreshToken }))).status).toBe(401);

    const conf = await confirm({ ...first, accessToken: rotated.accessToken });
    expect(conf.status).toBe(200);
    expect(tailscaleRequests.some((r) => r.includes('/tailnet/') && r.includes('/devices'))).toBe(true);
    expect(tailscaleRequests.some((r) =>
      r.includes(`/device/${encodeURIComponent(MGMT_ID)}/tags`) && r.includes('tag:tunnel-client'),
    )).toBe(true);
    // Must not resolve via GET /device/{clientSubmittedStableId}
    expect(tailscaleRequests.some((r) => r.startsWith('GET ') && r.includes(`/device/${STABLE_ID}`))).toBe(false);

    const login = (installationId: string) => emailSignIn({
      email: first.email,
      deviceName: installationId,
      installationId,
    });
    expect((await login('lifecycle-installation-one')).status).toBe(200);
    expect((await login('lifecycle-installation-two')).status).toBe(200);
    expect((await login('lifecycle-installation-three')).status).toBe(409);
    const count = await env.DB.prepare("SELECT count(*) n FROM devices WHERE installation_id='lifecycle-installation-one'").first<any>();
    expect(count.n).toBe(1);
  });

  it('supports an explicit per-user device allowance without changing the default', async () => {
    const account = await createAccount('expanded-device-limit');
    expect(account.user.deviceLimit).toBe(2);

    const expanded = await admin(
      `users/${account.user.id}`,
      { deviceLimit: 5 },
      'PATCH',
    );
    expect(expanded.status).toBe(200);

    const me = await api('me', {
      headers: { authorization: `Bearer ${account.accessToken}` },
    });
    expect(me.status).toBe(200);
    expect((await me.json() as any).user.deviceLimit).toBe(5);

    const login = (suffix: string) => emailSignIn({
      email: account.email,
      deviceName: `Expanded ${suffix}`,
      installationId: `expanded-device-limit-installation-${suffix}`,
    });
    for (const suffix of ['two', 'three', 'four', 'five']) {
      expect((await login(suffix)).status).toBe(200);
    }
    expect((await login('six')).status).toBe(409);

    const stored = await env.DB.prepare(
      'SELECT device_limit FROM users WHERE id = ?',
    ).bind(account.user.id).first<any>();
    expect(stored.device_limit).toBe(5);
  });

  it('confirm resolves via inventory with distinct IDs and stores management id', async () => {
    const account = await createAccount('three-id');
    resetMockInventory(account.device.id, account.enrollment.hostname);

    const tokenRequest = tailscaleRequests.find((request) => request.includes('/oauth/token'));
    expect(tokenRequest).toContain('scope=auth_keys+devices%3Acore');
    expect(tokenRequest).toContain('tags=tag%3Atono-controller');

    const conf = await confirm(account, { stableNodeId: STABLE_ID, nodeId: API_NODE_ID });
    expect(conf.status).toBe(200);
    const body = await conf.json() as any;
    expect(body.device.status).toBe('active');
    expect(body.device.tailscaleNodeId).toBe(MGMT_ID);
    expect(body.device.stableNodeId).toBe(STABLE_ID);
    expect(body.device.tailscaleApiNodeId).toBe(API_NODE_ID);
    expect(body.device.tailscaleIPs).toEqual(TS_IPS);
    expect(account.enrollment.hostname).toMatch(/^tono-[a-f0-9]{32}$/);

    const row = await env.DB.prepare(
      'SELECT tailscale_node_id, tailscale_stable_id, tailscale_api_node_id FROM devices WHERE id = ?',
    ).bind(account.device.id).first<any>();
    expect(row.tailscale_node_id).toBe(MGMT_ID);
    expect(row.tailscale_stable_id).toBe(STABLE_ID);
    expect(row.tailscale_api_node_id).toBe(API_NODE_ID);

    // Tags + delete paths use management id only
    expect(tailscaleRequests.some((r) => r.includes(`/device/${MGMT_ID}/tags`))).toBe(true);
    expect(tailscaleRequests.some((r) => r.includes(`/device/${API_NODE_ID}`) || r.includes(`/device/${STABLE_ID}`))).toBe(false);
  });

  it('derives device and installation identity from D1, not mutable JWT claims', async () => {
    const account = await createAccount('jwt-device-context');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    const session = await env.DB.prepare(
      'SELECT id FROM sessions WHERE user_id = ? AND device_id = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1',
    ).bind(account.user.id, account.device.id).first<any>();
    const forgedClaims = await jwtSign({
      sub: account.user.id,
      sid: session.id,
      did: 'attacker-controlled-device-id',
      iid: 'attacker-controlled-installation-id',
      exp: Math.floor(Date.now() / 1000) + 60,
      }, JWT_TEST_SECRET);

    const devices = await api('devices', {
      headers: { authorization: `Bearer ${forgedClaims}` },
    });
    expect(devices.status).toBe(200);
    const listed = await devices.json() as any;
    expect(listed.devices.find((device: any) => device.id === account.device.id)?.current).toBe(true);

    const wrongDevice = await api('devices/attacker-controlled-device-id/enrollment', json({
      installationId: 'attacker-controlled-installation-id',
    }, forgedClaims));
    expect(wrongDevice.status).toBe(404);

    const confirmed = await confirm({ ...account, accessToken: forgedClaims });
    expect(confirmed.status).toBe(200);
  });

  it('concurrent confirm race: second confirm of same device gets 409; winner stays active', async () => {
    const account = await createAccount('race');
    resetMockInventory(account.device.id, account.enrollment.hostname);

    // Hold the first request at the external tag call, after its D1 claim and
    // durable guard have been written. The second request is truly concurrent.
    const gate = pauseNextTagPromotion();
    const firstRequest = confirm(account);
    await gate.started;
    const second = await confirm(account);
    expect(second.status).toBe(409);
    gate.release();
    const first = await firstRequest;
    expect(first.status).toBe(200);

    const row = await env.DB.prepare(
      'SELECT status, tailscale_node_id FROM devices WHERE id = ?',
    ).bind(account.device.id).first<any>();
    expect(row.status).toBe('active');
    expect(row.tailscale_node_id).toBe(MGMT_ID);

    // Winner's node must not have been wrongfully deleted
    expect(mockInventory.some((d) => d.id === MGMT_ID)).toBe(true);
    const deleteOfWinner = tailscaleRequests.filter(
      (r) => r.startsWith('DELETE ') && r.includes(`/device/${MGMT_ID}`),
    );
    expect(deleteOfWinner.length).toBe(0);
  });

  it('does not rotate enrollment while a confirm claim is live', async () => {
    const account = await createAccount('enrollment-claim-race');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    await env.DB.prepare(
      'UPDATE devices SET enrollment_issued_at = ? WHERE id = ?',
    ).bind(Math.floor(Date.now() / 1000) - 61, account.device.id).run();
    const gate = pauseNextTagPromotion();
    const confirming = confirm(account);
    await gate.started;
    try {
      const enrollment = await api(`devices/${account.device.id}/enrollment`, json({
        installationId: 'enrollment-claim-race-installation-one',
      }, account.accessToken));
      expect(enrollment.status).toBe(429);
      const row = await env.DB.prepare(
        'SELECT enrollment_hostname FROM devices WHERE id = ?',
      ).bind(account.device.id).first<any>();
      expect(row.enrollment_hostname).toBe(account.enrollment.hostname);
    } finally {
      gate.release();
    }
    expect((await confirming).status).toBe(200);
  });

  it('second sequential claim while first holds claim returns 409 without deleting', async () => {
    const account = await createAccount('claim-race');
    resetMockInventory(account.device.id, account.enrollment.hostname);

    // Simulate an in-flight claim held by another worker
    const t = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      "UPDATE devices SET claim_token = 'held-by-other', claim_expires_at = ? WHERE id = ?",
    ).bind(t + 30, account.device.id).run();

    const conf = await confirm(account);
    expect(conf.status).toBe(409);

    // Still pending, management id not stolen/deleted
    const row = await env.DB.prepare('SELECT status, tailscale_node_id FROM devices WHERE id = ?')
      .bind(account.device.id).first<any>();
    expect(row.status).toBe('pending');
    expect(tailscaleRequests.filter((r) => r.startsWith('DELETE ')).length).toBe(0);
  });

  it('email-code verification rate limit returns 429 after threshold', async () => {
    const account = await createAccount('ratelimit');
    const started = await startEmailSignIn({
      email: account.email,
      deviceName: 'Mac',
      installationId: 'ratelimit-installation-one',
    });
    const wrongCode = started.code === '000000' ? '000001' : '000000';
    const attempt = () => api('auth/email/verify', json({
      challengeId: started.challengeId,
      code: wrongCode,
    }));

    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const r = await attempt();
      statuses.push(r.status);
      if (r.status === 429) {
        const body = await r.json() as any;
        expect(body.error.code).toBe('RATE_LIMITED');
      }
    }
    expect(statuses).toContain(429);
    // First attempts are rejected as invalid codes before the limiter closes.
    expect(statuses.filter((s) => s === 401).length).toBeGreaterThanOrEqual(1);
  });

  it('atomically limits parallel email-code attempts', async () => {
    const account = await createAccount('parallel-ratelimit');
    const started = await startEmailSignIn({
      email: account.email,
      deviceName: 'Mac',
      installationId: 'parallel-rate-install',
    });
    const wrongCode = started.code === '000000' ? '000001' : '000000';
    const attempts = await Promise.all(Array.from({ length: 12 }, () =>
      api('auth/email/verify', json({
        challengeId: started.challengeId,
        code: wrongCode,
      })),
    ));
    const statuses = attempts.map((response) => response.status);
    expect(statuses.filter((status) => status === 401)).toHaveLength(3);
    expect(statuses.filter((status) => status === 429)).toHaveLength(9);
  });

  it('bounds request bodies before JSON parsing', async () => {
    const response = await api('auth/email/start', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ padding: 'x'.repeat(20 * 1024) }),
    });
    expect(response.status).toBe(413);
    expect((await response.json() as any).error.code).toBe('PAYLOAD_TOO_LARGE');
  });

  it('rejects a mismatched public key instead of falling back to the sole IP candidate', async () => {
    const account = await createAccount('identity-mismatch');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    const response = await confirm(account, { publicKey: 'not-the-inventory-key' });
    expect(response.status).toBe(400);
    expect(tailscaleRequests.some((request) => request.includes('/tags'))).toBe(false);
    const row = await env.DB.prepare(
      'SELECT status, tailscale_node_id FROM devices WHERE id = ?',
    ).bind(account.device.id).first<any>();
    expect(row.status).toBe('pending');
    expect(row.tailscale_node_id).toBeNull();
  });

  it('binds confirm to the server-issued enrollment hostname', async () => {
    const account = await createAccount('hostname-binding');
    resetMockInventory(account.device.id, 'tono-ffffffffffffffffffffffffffffffff');
    const response = await confirm(account);
    expect(response.status).toBe(400);
    expect(tailscaleRequests.some((request) => request.includes('/tags'))).toBe(false);
    const row = await env.DB.prepare(
      'SELECT status, tailscale_node_id FROM devices WHERE id = ?',
    ).bind(account.device.id).first<any>();
    expect(row.status).toBe('pending');
    expect(row.tailscale_node_id).toBeNull();
  });

  it('rejects a mismatched stable id when inventory exposes one', async () => {
    const account = await createAccount('stable-id-mismatch');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    mockInventory[0].stableNodeId = 'server-stable-id';
    const response = await confirm(account, { stableNodeId: 'different-client-stable-id' });
    expect(response.status).toBe(400);
    expect(tailscaleRequests.some((request) => request.includes('/tags'))).toBe(false);
    const row = await env.DB.prepare(
      'SELECT status, tailscale_node_id FROM devices WHERE id = ?',
    ).bind(account.device.id).first<any>();
    expect(row.status).toBe('pending');
    expect(row.tailscale_node_id).toBeNull();
  });

  it('failed promotion compensation enqueues revocation job', async () => {
    const account = await createAccount('promo-fail');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    failNextTagPromotion = true;

    const conf = await confirm(account);
    expect(conf.status).toBe(502);

    const job = await env.DB.prepare(
      'SELECT * FROM revocation_jobs WHERE tailscale_node_id = ?',
    ).bind(MGMT_ID).first<any>();
    expect(job).toBeTruthy();
    expect(job.device_id).toBe(account.device.id);
    // Best-effort process should complete the delete in mock
    expect(job.completed_at).toBeTypeOf('number');

    const device = await env.DB.prepare(
      'SELECT status, claim_token, tailscale_node_id FROM devices WHERE id = ?',
    ).bind(account.device.id).first<any>();
    expect(device.status).toBe('pending');
    expect(device.claim_token).toBeNull();
    expect(device.tailscale_node_id).toBeNull();
  });

  it('keeps a durable deletion guard when D1 activation throws after promotion', async () => {
    const account = await createAccount('activate-fail');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    await env.DB.prepare(
      `CREATE TRIGGER test_fail_activation
       BEFORE UPDATE OF status ON devices
       WHEN NEW.status = 'active'
       BEGIN
         SELECT RAISE(ABORT, 'TEST_ACTIVATION_FAILURE');
       END`,
    ).run();
    try {
      const response = await confirm(account);
      expect(response.status).toBe(503);
      const job = await env.DB.prepare(
        'SELECT completed_at, reason FROM revocation_jobs WHERE tailscale_node_id = ?',
      ).bind(MGMT_ID).first<any>();
      expect(job).toBeTruthy();
      expect(job.reason).toBe('confirm_guard');
      expect(job.completed_at).toBeTypeOf('number');
      expect(mockInventory.some((device) => device.id === MGMT_ID)).toBe(false);
      const device = await env.DB.prepare(
        'SELECT status, tailscale_node_id, claim_token FROM devices WHERE id = ?',
      ).bind(account.device.id).first<any>();
      expect(device.status).toBe('pending');
      expect(device.tailscale_node_id).toBeNull();
      expect(device.claim_token).toBeNull();
    } finally {
      await env.DB.prepare('DROP TRIGGER IF EXISTS test_fail_activation').run();
    }
  });

  it('fences re-enrollment until an expired in-flight identity is deleted', async () => {
    const account = await createAccount('expiry-race');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    const gate = pauseNextTagPromotion();
    const confirmRequest = confirm(account);
    await gate.started;

    // The claim is in flight with its guard persisted. Expire the pending row
    // and reopen the installation through the normal login path.
    await env.DB.prepare(
      'UPDATE devices SET pending_expires_at = ? WHERE id = ?',
    ).bind(Math.floor(Date.now() / 1000) - 1, account.device.id).run();
    const login = await emailSignIn({
      email: account.email,
      deviceName: 'Primary Mac',
      installationId: 'expiry-race-installation-one',
    });
    expect(login.status).toBe(409);
    expect((await login.json() as any).error.code).toBe('REVOCATION_PENDING');

    gate.release();
    const staleConfirm = await confirmRequest;
    expect(staleConfirm.status).toBe(409);
    const retry = await emailSignIn({
      email: account.email,
      deviceName: 'Primary Mac',
      installationId: 'expiry-race-installation-one',
    });
    expect(retry.status).toBe(200);
    const device = await env.DB.prepare(
      'SELECT status, claim_generation, tailscale_node_id FROM devices WHERE id = ?',
    ).bind(account.device.id).first<any>();
    expect(device.status).toBe('pending');
    expect(device.tailscale_node_id).toBeNull();
    expect(mockInventory.some((candidate) => candidate.id === MGMT_ID)).toBe(false);
  });

  it('pending expire enqueues revocation when management id present', async () => {
    const account = await createAccount('expire-rev');
    const t = Math.floor(Date.now() / 1000);
    // Simulate mid-confirm: management id stored on still-pending device that is now expired
    await env.DB.prepare(
      `UPDATE devices SET tailscale_node_id = ?, pending_expires_at = ?, status = 'pending' WHERE id = ?`,
    ).bind(MGMT_ID, t - 10, account.device.id).run();

    // Login runs ensureDevice → expirePending (auth for expired pending session would 401)
    const login = await emailSignIn({
      email: account.email,
      deviceName: 'Primary Mac',
      installationId: 'expire-rev-installation-one',
    });
    expect(login.status).toBe(409);
    expect((await login.json() as any).error.code).toBe('REVOCATION_PENDING');

    const device = await env.DB.prepare('SELECT status FROM devices WHERE id = ?')
      .bind(account.device.id).first<any>();
    // expirePending revokes; ensureDevice then re-opens a pending row on the same device id
    expect(['revoked', 'pending']).toContain(device.status);

    const job = await env.DB.prepare(
      'SELECT * FROM revocation_jobs WHERE device_id = ? AND tailscale_node_id = ?',
    ).bind(account.device.id, MGMT_ID).first<any>();
    expect(job).toBeTruthy();

    const context = createExecutionContext();
    await worker.scheduled(createScheduledController(), env as unknown as Env, context);
    await waitOnExecutionContext(context);
    const retry = await emailSignIn({
      email: account.email,
      deviceName: 'Primary Mac',
      installationId: 'expire-rev-installation-one',
    });
    expect(retry.status).toBe(200);
  });

  it('scheduled cleanup revokes superseded pending enrollment hostnames', async () => {
    const account = await createAccount('stale-enrollment');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    mockInventory.push({
      id: 'mgmt-superseded',
      nodeId: 'nodeid-superseded',
      name: 'tono-ffffffffffffffffffffffffffffffff',
      nodeKey: 'nodekey:public-key-superseded',
      addresses: ['100.64.0.99'],
      tags: ['tag:pending-tunnel-client'],
      description: `tono-device-${account.device.id}`,
    });

    const context = createExecutionContext();
    await worker.scheduled(createScheduledController(), env as unknown as Env, context);
    await waitOnExecutionContext(context);

    expect(tailscaleRequests.some((request) =>
      request.startsWith('DELETE ') && request.includes('/device/mgmt-superseded'),
    )).toBe(true);
    expect(tailscaleRequests.some((request) =>
      request.startsWith('DELETE ') && request.includes(`/device/${MGMT_ID}`),
    )).toBe(false);
  });

  it('disables access and revokes the active tailnet device', async () => {
    const account = await createAccount('disabled');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    expect((await confirm(account)).status).toBe(200);
    const response = await admin(`users/${account.user.id}`, { status: 'disabled' }, 'PATCH');
    expect(response.status).toBe(200);
    expect((await api('me', { headers: { authorization: `Bearer ${account.accessToken}` } })).status).toBe(401);
    expect((await api('auth/refresh', json({ refreshToken: account.refreshToken }))).status).toBe(401);
    const device = await env.DB.prepare('SELECT status FROM devices WHERE id=?').bind(account.device.id).first<any>();
    expect(device.status).toBe('revoked');
    const job = await env.DB.prepare('SELECT completed_at FROM revocation_jobs WHERE device_id=?').bind(account.device.id).first<any>();
    expect(job.completed_at).toBeTypeOf('number');
  });

  it('refuses to re-enable a user if a prior disable left a live device without an outbox job', async () => {
    const account = await createAccount('reenable-invariant');
    // Simulate an invocation ending immediately after the user status write,
    // before enforceUser could transition the pending device and create jobs.
    await env.DB.prepare("UPDATE users SET status = 'disabled' WHERE id = ?")
      .bind(account.user.id).run();
    const response = await admin(`users/${account.user.id}`, { status: 'active' }, 'PATCH');
    expect(response.status).toBe(409);
    expect((await response.json() as any).error.code).toBe('REVOCATION_PENDING');
    const user = await env.DB.prepare('SELECT status FROM users WHERE id = ?')
      .bind(account.user.id).first<any>();
    expect(user.status).toBe('disabled');
  });

  it('only lets the bound installation re-enroll its active device', async () => {
    const account = await createAccount('reenroll');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    expect((await confirm(account)).status).toBe(200);
    // Re-enroll needs inventory for any subsequent confirm; enrollment issues a key
    const own = await api(`devices/${account.device.id}/enrollment`, json({
      installationId: 'reenroll-installation-one',
    }, account.accessToken));
    expect(own.status).toBe(200);
    expect((await own.json() as any).enrollment.authKey).toMatch(/^tskey-mock-/);

    const other = await emailSignIn({
      email: account.email,
      deviceName: 'Other Mac',
      installationId: 'reenroll-installation-two',
    });
    expect(other.status).toBe(200);
    const otherAuth = await other.json() as any;
    expect((await api(`devices/${account.device.id}/enrollment`, json({}, otherAuth.accessToken))).status).toBe(404);
  });

  it('does not issue a replacement enrollment while the prior identity revocation is pending', async () => {
    const account = await createAccount('reenroll-revoke-failure');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    expect((await confirm(account)).status).toBe(200);
    const keyRequestsBefore = tailscaleRequests.filter(
      (request) => request.startsWith('POST ') && request.includes('/keys'),
    ).length;

    failNextDelete = true;
    const blocked = await api(`devices/${account.device.id}/enrollment`, json({
      installationId: 'reenroll-revoke-failure-installation-one',
    }, account.accessToken));
    expect(blocked.status).toBe(409);
    expect((await blocked.json() as any).error.code).toBe('REVOCATION_PENDING');
    expect(tailscaleRequests.filter(
      (request) => request.startsWith('POST ') && request.includes('/keys'),
    )).toHaveLength(keyRequestsBefore);

    const pendingJob = await env.DB.prepare(
      'SELECT completed_at FROM revocation_jobs WHERE device_id = ? AND tailscale_node_id = ?',
    ).bind(account.device.id, MGMT_ID).first<any>();
    expect(pendingJob).toBeTruthy();
    expect(pendingJob.completed_at).toBeNull();

    const context = createExecutionContext();
    await worker.scheduled(createScheduledController(), env as unknown as Env, context);
    await waitOnExecutionContext(context);

    const retry = await api(`devices/${account.device.id}/enrollment`, json({
      installationId: 'reenroll-revoke-failure-installation-one',
    }, account.accessToken));
    expect(retry.status).toBe(200);
    expect((await retry.json() as any).enrollment.authKey).toMatch(/^tskey-mock-/);
  });

  it('releases the enrollment lease after a transient key-issuance failure', async () => {
    const email = `key-retry-${++sequence}@example.com`;
    failNextKeyIssue = true;
    const redeem = await emailSignIn({
      email,
      deviceName: 'Primary Mac',
      installationId: 'key-retry-installation-one',
    });
    expect(redeem.status).toBe(502);

    const login = await emailSignIn({
      email,
      deviceName: 'Primary Mac',
      installationId: 'key-retry-installation-one',
    });
    expect(login.status).toBe(200);
    expect((await login.json() as any).enrollment.authKey).toMatch(/^tskey-mock-/);
  });

  it('revokes sessions and devices as soon as a usage report reaches quota', async () => {
    const account = await createAccount('quota');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    expect((await confirm(account)).status).toBe(200);
    expect((await admin(`users/${account.user.id}`, { quotaBytes: 100 }, 'PATCH')).status).toBe(200);
    const usage = await api('home/usage', json({ reports: [{
      reportId: `report-${sequence}`,
      userId: account.user.id,
      totalBytes: 100,
      observedAt: Math.floor(Date.now() / 1000),
    }] }, HOME_TOKEN));
    expect(usage.status).toBe(200);
    expect((await api('me', { headers: { authorization: `Bearer ${account.accessToken}` } })).status).toBe(401);
    const device = await env.DB.prepare('SELECT status FROM devices WHERE id=?').bind(account.device.id).first<any>();
    expect(device.status).toBe('revoked');
  });

  it('exposes only verified peer usage mappings to the authenticated home agent', async () => {
    const account = await createAccount('home-inventory');
    resetMockInventory(account.device.id, account.enrollment.hostname);
    expect((await confirm(account)).status).toBe(200);

    const unauthorized = await api('home/inventory');
    expect(unauthorized.status).toBe(401);

    const response = await api('home/inventory', {
      headers: { authorization: `Bearer ${HOME_TOKEN}` },
    });
    expect(response.status).toBe(200);
    const payload = await response.json() as any;
    expect(payload.devices).toEqual([{
      stableNodeId: STABLE_ID,
      publicKey: PUBLIC_KEY.replace(/^nodekey:/, ''),
      userId: account.user.id,
      status: 'active',
      usageBytes: 0,
    }]);
    expect(JSON.stringify(payload)).not.toContain(account.email);
    expect(JSON.stringify(payload)).not.toContain(account.device.installationId);
    expect(JSON.stringify(payload)).not.toContain(MGMT_ID);
    expect(JSON.stringify(payload)).not.toContain(API_NODE_ID);
  });

  it('treats reportId as an immutable idempotency key', async () => {
    const account = await createAccount('usage-idempotency');
    const observedAt = Math.floor(Date.now() / 1000);
    const reportId = `immutable-report-${sequence}`;
    const original = {
      reportId,
      userId: account.user.id,
      totalBytes: 25,
      observedAt,
    };
    expect((await api('home/usage', json({ reports: [original] }, HOME_TOKEN))).status).toBe(200);
    expect((await api('home/usage', json({ reports: [original] }, HOME_TOKEN))).status).toBe(200);

    const conflict = await api('home/usage', json({ reports: [{
      ...original,
      totalBytes: 50,
    }] }, HOME_TOKEN));
    expect(conflict.status).toBe(409);
    expect((await conflict.json() as any).error.code).toBe('USAGE_REPORT_CONFLICT');

    const user = await env.DB.prepare('SELECT usage_bytes FROM users WHERE id = ?')
      .bind(account.user.id).first<any>();
    expect(user.usage_bytes).toBe(25);
    const stored = await env.DB.prepare('SELECT total_bytes FROM usage_reports WHERE report_id = ?')
      .bind(reportId).first<any>();
    expect(stored.total_bytes).toBe(25);
  });

  it('rejects non-object usage report entries as validation errors', async () => {
    const response = await api('home/usage', json({ reports: [null] }, HOME_TOKEN));
    expect(response.status).toBe(400);
    expect((await response.json() as any).error.code).toBe('VALIDATION_ERROR');
  });

  it('isolates allowlisted device actions and safely replays bounded canonical results', async () => {
    const owner = await createAccount('action-owner');
    const other = await createAccount('action-other');
    expect((await admin('device-actions', {
      deviceId: owner.device.id, action: 'run_shell', code: 'id',
    })).status).toBe(400);
    expect((await admin('device-actions', {
      deviceId: owner.device.id, action: 'diagnostic_snapshot', parameters: {},
    })).status).toBe(400);
    expect((await admin('device-actions', {
      deviceId: owner.device.id, action: 'diagnostic_snapshot', code: 'id',
    })).status).toBe(400);
    expect((await admin('device-actions', null)).status).toBe(400);

    const queued = await admin('device-actions', {
      deviceId: owner.device.id, action: 'diagnostic_snapshot', ttlSeconds: 300,
    });
    expect(queued.status).toBe(201);
    const command = (await queued.json() as any).action;
    const otherPoll = await api('device-actions', {
      headers: { authorization: `Bearer ${other.accessToken}` },
    });
    expect((await otherPoll.json() as any).actions).toEqual([]);

    const first = await api('device-actions', {
      headers: { authorization: `Bearer ${owner.accessToken}` },
    });
    expect((await first.json() as any).actions[0].status).toBe('delivered');
    const replay = await api('device-actions', {
      headers: { authorization: `Bearer ${owner.accessToken}` },
    });
    expect((await replay.json() as any).actions[0].id).toBe(command.id);
    expect((await api(`device-actions/${command.id}/result`, json({
      outcome: 'succeeded', snapshot: { connected: true, shell: '/bin/sh' },
    }, owner.accessToken))).status).toBe(400);
    expect((await api(`device-actions/${command.id}/result`, json({
      outcome: 'succeeded', message: 'x'.repeat(201),
    }, owner.accessToken))).status).toBe(400);
    expect((await api(`device-actions/${command.id}/result`, json({
      outcome: 'succeeded', snapshot: { lastErrorCategory: '/Users/customer/private' },
    }, owner.accessToken))).status).toBe(400);
    expect((await api(`device-actions/${command.id}/result`, json(null, owner.accessToken))).status).toBe(400);
    expect((await api(`device-actions/${command.id}/result`, json({
      outcome: 'succeeded', snapshot: { connected: true, reconnectAttempt: 2 },
    }, other.accessToken))).status).toBe(404);

    const result = {
      outcome: 'succeeded',
      snapshot: { connected: true, reconnectAttempt: 2, lastErrorCategory: 'data_plane' },
    };
    expect((await api(`device-actions/${command.id}/result`, json(result, owner.accessToken))).status).toBe(200);
    expect((await api(`device-actions/${command.id}/result`, json(result, owner.accessToken))).status).toBe(200);
    expect((await api(`device-actions/${command.id}/result`, json({ outcome: 'failed' }, owner.accessToken))).status).toBe(409);
    const stored = await env.DB.prepare('SELECT status, result_json FROM device_actions WHERE id = ?')
      .bind(command.id).first<any>();
    expect(stored.status).toBe('succeeded');
    expect(JSON.parse(stored.result_json)).toEqual(result);

    const trafficQueued = await admin('device-actions', {
      deviceId: owner.device.id, action: 'claude_traffic_snapshot', ttlSeconds: 300,
    });
    expect(trafficQueued.status).toBe(201);
    const trafficCommand = (await trafficQueued.json() as any).action;
    const trafficPoll = await api('device-actions', {
      headers: { authorization: `Bearer ${owner.accessToken}` },
    });
    expect((await trafficPoll.json() as any).actions[0].id).toBe(trafficCommand.id);
    const trafficSummary = {
      observedSince: Math.floor(Date.now() / 1000) - 60,
      droppedEndpointCount: 0,
      observedConnectionCount: 8,
      identifiedProcessConnectionCount: 3,
      proxiedConnectionCount: 7,
      directConnectionCount: 0,
      blockedConnectionCount: 1,
      directRouteAttemptCount: 0,
      managedDirectRouteCount: 2,
      unclassifiedRouteCount: 0,
      unsafeProtectionObservationCount: 0,
      webManagedDirectConnectionCount: 0,
      weChatConnectionCount: 2,
      weChatManagedDirectConnectionCount: 0,
      weChatProxiedConnectionCount: 2,
      weChatBlockedConnectionCount: 0,
      weChatEndpointUnknownProcessConnectionCount: 1,
      unknownManagedDirectConnectionCount: 0,
      otherManagedDirectConnectionCount: 0,
      protectedDirectConnectionCount: 0,
      connectionLimitReached: false,
      connected: true,
      killSwitchArmed: true,
      tunPresent: true,
      protectedDNSConfigured: true,
      exitIdentityConsistency: 'MATCHED',
      physicalBypassProbe: 'BLOCKED',
    };
    expect((await api(`device-actions/${trafficCommand.id}/result`, json({
      outcome: 'succeeded',
      trafficResearch: {
        ...trafficSummary,
        entries: [{
          service: 'claude', client: 'web', host: 'www.reclaude.ai',
          network: 'TCP', port: 443, route: 'PROXIED', connections: 1,
          upBytes: 10, downBytes: 20,
        }],
      },
    }, owner.accessToken))).status).toBe(400);
    expect((await api(`device-actions/${trafficCommand.id}/result`, json({
      outcome: 'succeeded',
      trafficResearch: {
        ...trafficSummary,
        entries: [{
          service: 'anthropic', client: 'code', host: 'api.anthropic.com',
          network: 'TCP', port: 443, route: 'PROXIED', connections: 2,
          upBytes: 100, downBytes: 200, processPath: '/Users/customer/bin/claude',
        }],
      },
    }, owner.accessToken))).status).toBe(400);
    expect((await api(`device-actions/${trafficCommand.id}/result`, json({
      outcome: 'succeeded',
      trafficResearch: {
        ...trafficSummary,
        protectedDirectConnectionCount: 1,
        entries: [],
      },
    }, owner.accessToken))).status).toBe(400);
    expect((await api(`device-actions/${trafficCommand.id}/result`, json({
      outcome: 'succeeded',
      trafficResearch: {
        ...trafficSummary,
        physicalBypassProbe: 'IGNORED',
        entries: [],
      },
    }, owner.accessToken))).status).toBe(400);
    const trafficResult = {
      outcome: 'succeeded',
      trafficResearch: {
        ...trafficSummary,
        entries: [
          {
            service: 'anthropic', client: 'code', host: 'api.anthropic.com',
            network: 'TCP', port: 443, route: 'PROXIED', connections: 2,
            upBytes: 100, downBytes: 200,
          },
          {
            service: 'claude', client: 'unknown', host: 'claude.ai',
            network: 'UDP', port: 443, route: 'PROXIED', connections: 3,
            upBytes: 300, downBytes: 400,
          },
          {
            service: 'other', client: 'code', host: 'example.com',
            network: 'TCP', port: 443, route: 'PROXIED', connections: 1,
            upBytes: 50, downBytes: 60,
          },
        ],
      },
    };
    expect((await api(`device-actions/${trafficCommand.id}/result`, json(
      trafficResult, owner.accessToken,
    ))).status).toBe(200);
    const storedTraffic = await env.DB.prepare('SELECT status, result_json FROM device_actions WHERE id = ?')
      .bind(trafficCommand.id).first<any>();
    expect(storedTraffic.status).toBe('succeeded');
    expect(JSON.parse(storedTraffic.result_json)).toEqual(trafficResult);

    const expiring = await admin('device-actions', {
      deviceId: owner.device.id, action: 'refresh_catalog', ttlSeconds: 1,
    });
    const expiringID = (await expiring.json() as any).action.id;
    await env.DB.prepare('UPDATE device_actions SET expires_at = ? WHERE id = ?')
      .bind(Math.floor(Date.now() / 1000) - 1, expiringID).run();
    const afterExpiry = await api('device-actions', {
      headers: { authorization: `Bearer ${owner.accessToken}` },
    });
    expect((await afterExpiry.json() as any).actions).toEqual([]);
    expect((await env.DB.prepare('SELECT status FROM device_actions WHERE id = ?').bind(expiringID).first<any>()).status).toBe('expired');
    expect((await api(`device-actions/${expiringID}/result`, json({
      outcome: 'succeeded',
    }, owner.accessToken))).status).toBe(409);

    await env.DB.prepare("UPDATE devices SET status = 'revoked' WHERE id = ?").bind(owner.device.id).run();
    expect((await admin('device-actions', {
      deviceId: owner.device.id, action: 'refresh_catalog',
    })).status).toBe(404);
    expect((await api('device-actions', {
      headers: { authorization: `Bearer ${owner.accessToken}` },
    })).status).toBe(401);
  });

  // Pinned verbatim from the client's single definition of the wire contract
  // (`crates/tono-core/src/auth.rs`, `DiagnosticsReport`), which is already
  // shipped. Do NOT edit this object to make the server pass: if the two ever
  // drift, this fixture is the alarm and the server is what moves.
  const shippedClientReport = {
    schemaVersion: 1,
    reportedAtMs: 1712345678901,
    appVersion: '0.0.3',
    osVersion: 'Windows 11 Pro 23H2',
    osArch: 'x86_64',
    serviceProtocol: '2.9',
    serviceBuild: '2.6.2',
    uiState: 'protectedOffline',
    accountState: 'ready',
    selectedServer: 'US West 1',
    catalogRevision: 12,
    killSwitchMode: 'blocked',
    killSwitchWanted: true,
    killSwitchLive: false,
    killSwitchLastError: 'WFP filter add failed (0x80320013)',
    dnsEnabled: true,
    dnsLastError: 'resolver handshake timed out',
    failedStage: 'securingDNS',
    error: 'connect failed after 2 retries',
    retryAttempt: 2,
    totalElapsedMs: 4600,
    steps: [{ key: 'preparing', state: 'completed', elapsedMs: 1200 }],
    virtualAdapters: ['hyperV', 'wsl'],
    auditLogPath: '%USERPROFILE%\\AppData\\Roaming\\Tono\\traffic-audit.jsonl',
    serviceLogPath: 'C:\\ProgramData\\Tono\\logs\\tono-service.log',
  };

  // Overrides patch the report, not the envelope: the envelope is `{report}`.
  const diagnosticsPayload = (overrides: Record<string, unknown> = {}) => ({
    report: { ...shippedClientReport, ...overrides },
  });

  it('accepts the exact payload the shipped client sends, verbatim', async () => {
    const account = await createAccount('diagnostics-contract');
    // The literal body from `auth.rs`, envelope included, byte for byte.
    const response = await api('diagnostics/reports', json(
      { report: shippedClientReport },
      account.accessToken,
    ));
    expect(response.status).toBe(201);
    const body = await response.json() as any;
    // The client requires a non-empty referenceCode and tolerates receivedAt.
    expect(body.referenceCode).toMatch(/^[2-9A-HJ-NP-Z]{8}$/);
    expect(typeof body.receivedAt).toBe('number');

    const stored = await env.DB.prepare(
      'SELECT * FROM diagnostics_reports WHERE reference_code = ?',
    ).bind(body.referenceCode).first<any>();
    // Every field survives, unchanged and in the contract's own key order:
    // a drift on either side breaks this equality loudly.
    expect(stored.report_json).toBe(JSON.stringify(shippedClientReport));
    // The columns come from inside the report; there is no second copy on the
    // envelope any more.
    expect(stored.client_version).toBe('0.0.3');
    expect(stored.os_version).toBe('Windows 11 Pro 23H2');
    expect((await api('diagnostics/reports', json({
      clientVersion: '0.0.3', osVersion: 'Windows 11 Pro 23H2', report: shippedClientReport,
    }, account.accessToken))).status).toBe(400);
  });

  it('accepts a user-initiated diagnostics upload and returns only a spoken reference code', async () => {
    const account = await createAccount('diagnostics-happy');
    const payload = diagnosticsPayload();
    const response = await api('diagnostics/reports', json(payload, account.accessToken));
    expect(response.status).toBe(201);
    const body = await response.json() as any;
    // The code plus a display-only receipt time is the entire response: no
    // payload is echoed back to the client.
    expect(Object.keys(body).sort()).toEqual(['receivedAt', 'referenceCode']);
    expect(body.referenceCode).toMatch(/^[2-9A-HJ-NP-Z]{8}$/);
    expect(Math.abs(body.receivedAt - Math.floor(Date.now() / 1000))).toBeLessThan(60);

    const stored = await env.DB.prepare(
      'SELECT * FROM diagnostics_reports WHERE reference_code = ?',
    ).bind(body.referenceCode).first<any>();
    expect(stored.user_id).toBe(account.user.id);
    expect(stored.client_version).toBe('0.0.3');
    expect(stored.os_version).toBe('Windows 11 Pro 23H2');
    expect(JSON.parse(stored.report_json)).toEqual(payload.report);

    // An accepted report is immutable evidence; retention deletes, nothing rewrites.
    await expect(env.DB.prepare(
      'UPDATE diagnostics_reports SET client_version = ? WHERE reference_code = ?',
    ).bind('0.0.0', body.referenceCode).run()).rejects.toThrow(/DIAGNOSTICS_REPORT_IMMUTABLE/);

    // Only whitelisted fields survive; anything else is refused, not dropped.
    const extra = await api('diagnostics/reports', json(
      diagnosticsPayload({ wifiSSID: 'home-network' }),
      account.accessToken,
    ));
    expect(extra.status).toBe(400);
    expect((await extra.json() as any).error.code).toBe('VALIDATION_ERROR');

    // A required field is required; the nullable ones may be null or absent.
    const { appVersion, ...missingAppVersion } = shippedClientReport;
    expect((await api('diagnostics/reports', json(
      { report: missingAppVersion }, account.accessToken,
    ))).status).toBe(400);

    const nulled = await api('diagnostics/reports', json(diagnosticsPayload({
      serviceProtocol: null, serviceBuild: null, selectedServer: null,
      catalogRevision: null, killSwitchMode: null, killSwitchWanted: null,
      killSwitchLive: null, killSwitchLastError: null, dnsEnabled: null,
      dnsLastError: null, failedStage: null, error: null, totalElapsedMs: null,
      steps: [{ key: 'preparing', state: 'current', elapsedMs: null }],
      virtualAdapters: [],
    }), account.accessToken));
    expect(nulled.status).toBe(201);
    const nulledStored = await env.DB.prepare(
      'SELECT report_json FROM diagnostics_reports WHERE reference_code = ?',
    ).bind((await nulled.json() as any).referenceCode).first<any>();
    // Null and absent mean the same thing: neither is stored.
    expect(JSON.parse(nulledStored.report_json)).toEqual({
      schemaVersion: 1,
      reportedAtMs: 1712345678901,
      appVersion: '0.0.3',
      osVersion: 'Windows 11 Pro 23H2',
      osArch: 'x86_64',
      uiState: 'protectedOffline',
      accountState: 'ready',
      retryAttempt: 2,
      steps: [{ key: 'preparing', state: 'current' }],
      virtualAdapters: [],
      auditLogPath: shippedClientReport.auditLogPath,
      serviceLogPath: shippedClientReport.serviceLogPath,
    });

    expect((await api('diagnostics/reports', json(payload))).status).toBe(401);
  });

  it('rejects an oversized diagnostics upload instead of truncating it', async () => {
    const account = await createAccount('diagnostics-oversized');
    const overBodyCap = await api('diagnostics/reports', json(
      diagnosticsPayload({ serviceLogPath: 'y'.repeat(40 * 1024) }),
      account.accessToken,
    ));
    expect(overBodyCap.status).toBe(413);
    expect((await overBodyCap.json() as any).error.code).toBe('PAYLOAD_TOO_LARGE');

    // Within the body cap, the per-field bounds refuse rather than truncate.
    const tooManySteps = await api('diagnostics/reports', json(
      diagnosticsPayload({
        steps: Array.from({ length: 33 }, (_, index) => ({
          key: `step-${index}`, state: 'completed', elapsedMs: 10,
        })),
      }),
      account.accessToken,
    ));
    expect(tooManySteps.status).toBe(400);

    const badStepState = await api('diagnostics/reports', json(
      diagnosticsPayload({ steps: [{ key: 'preparing', state: 'skipped', elapsedMs: 1 }] }),
      account.accessToken,
    ));
    expect(badStepState.status).toBe(400);

    const longStepKey = await api('diagnostics/reports', json(
      diagnosticsPayload({ steps: [{ key: 'k'.repeat(61), state: 'failed', elapsedMs: 1 }] }),
      account.accessToken,
    ));
    expect(longStepKey.status).toBe(400);

    const longError = await api('diagnostics/reports', json(
      diagnosticsPayload({ error: 'w'.repeat(501) }),
      account.accessToken,
    ));
    expect(longError.status).toBe(400);

    const longOsVersion = await api('diagnostics/reports', json(
      diagnosticsPayload({ osVersion: 'w'.repeat(81) }),
      account.accessToken,
    ));
    expect(longOsVersion.status).toBe(400);

    // The adapter vocabulary is fixed: unknown classes and repeats are refused.
    const unknownAdapter = await api('diagnostics/reports', json(
      diagnosticsPayload({ virtualAdapters: ['hyperV', 'parallels'] }),
      account.accessToken,
    ));
    expect(unknownAdapter.status).toBe(400);

    const repeatedAdapter = await api('diagnostics/reports', json(
      diagnosticsPayload({ virtualAdapters: ['wsl', 'wsl'] }),
      account.accessToken,
    ));
    expect(repeatedAdapter.status).toBe(400);

    const wildRetry = await api('diagnostics/reports', json(
      diagnosticsPayload({ retryAttempt: 1001 }),
      account.accessToken,
    ));
    expect(wildRetry.status).toBe(400);

    const wildElapsed = await api('diagnostics/reports', json(
      diagnosticsPayload({ totalElapsedMs: 24 * 60 * 60 * 1000 + 1 }),
      account.accessToken,
    ));
    expect(wildElapsed.status).toBe(400);

    const rows = await env.DB.prepare(
      'SELECT COUNT(*) AS total FROM diagnostics_reports WHERE user_id = ?',
    ).bind(account.user.id).first<any>();
    expect(Number(rows.total)).toBeLessThanOrEqual(1);
  });

  it('caps diagnostics uploads per user per hour', async () => {
    const account = await createAccount('diagnostics-ratelimit');
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 7; attempt++) {
      const response = await api('diagnostics/reports', json(diagnosticsPayload(), account.accessToken));
      statuses.push(response.status);
      if (response.status === 429) {
        expect((await response.json() as any).error.code).toBe('RATE_LIMITED');
      }
    }
    expect(statuses.filter((status) => status === 201)).toHaveLength(5);
    expect(statuses.filter((status) => status === 429)).toHaveLength(2);
    const rows = await env.DB.prepare(
      'SELECT COUNT(*) AS total FROM diagnostics_reports WHERE user_id = ?',
    ).bind(account.user.id).first<any>();
    expect(Number(rows.total)).toBe(5);
  });

  it('lets only an admin look a diagnostics report up by reference code', async () => {
    const account = await createAccount('diagnostics-lookup');
    const upload = await api('diagnostics/reports', json(diagnosticsPayload(), account.accessToken));
    expect(upload.status).toBe(201);
    const { referenceCode } = await upload.json() as any;

    expect((await api(`admin/diagnostics/reports/${referenceCode}`)).status).toBe(401);
    expect((await api(`admin/diagnostics/reports/${referenceCode}`, {
      headers: { authorization: `Bearer ${account.accessToken}` },
    })).status).toBe(401);

    const found = await admin(`diagnostics/reports/${referenceCode}`, undefined, 'GET');
    expect(found.status).toBe(200);
    expect((await found.json() as any).report).toMatchObject({
      referenceCode,
      userId: account.user.id,
      clientVersion: '0.0.3',
      osVersion: 'Windows 11 Pro 23H2',
      report: { failedStage: 'securingDNS', virtualAdapters: ['hyperV', 'wsl'] },
    });

    // Support types the code back in however they heard it.
    const typedBack = await admin(
      `diagnostics/reports/${referenceCode.slice(0, 4).toLowerCase()}-${referenceCode.slice(4)}`,
      undefined,
      'GET',
    );
    expect(typedBack.status).toBe(200);

    const unknown = await admin('diagnostics/reports/ZZZZZZZZ', undefined, 'GET');
    expect(unknown.status).toBe(404);
    expect((await unknown.json() as any).error.code).toBe('NOT_FOUND');

    // 0/O/1/I are not in the alphabet, so a misheard code fails validation.
    expect((await admin('diagnostics/reports/O0O0O0O0', undefined, 'GET')).status).toBe(400);
  });

  it('deletes diagnostics reports once they pass retention', async () => {
    const account = await createAccount('diagnostics-retention');
    const upload = await api('diagnostics/reports', json(diagnosticsPayload(), account.accessToken));
    const { referenceCode } = await upload.json() as any;

    const context = createExecutionContext();
    await worker.scheduled(createScheduledController(), env as unknown as Env, context);
    await waitOnExecutionContext(context);
    // Still inside retention.
    expect((await admin(`diagnostics/reports/${referenceCode}`, undefined, 'GET')).status).toBe(200);

    await env.DB.prepare(
      'DELETE FROM diagnostics_reports WHERE reference_code = ?',
    ).bind(referenceCode).run();
    await env.DB.prepare(
      `INSERT INTO diagnostics_reports(
         id, reference_code, user_id, received_at, client_version, os_version, report_json
       ) VALUES(?, ?, ?, ?, '2.5.4', 'Windows 11', '{}')`,
    ).bind(
      crypto.randomUUID(),
      referenceCode,
      account.user.id,
      Math.floor(Date.now() / 1000) - 31 * 86_400,
    ).run();

    const later = createExecutionContext();
    await worker.scheduled(createScheduledController(), env as unknown as Env, later);
    await waitOnExecutionContext(later);
    expect((await admin(`diagnostics/reports/${referenceCode}`, undefined, 'GET')).status).toBe(404);
  });
});
