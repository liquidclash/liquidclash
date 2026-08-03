import {
  decryptCatalog,
  decryptTrafficPolicy,
  encryptCatalog,
  encryptTrafficPolicy,
  hmacSha256,
  jwtSign,
  jwtVerify,
  randomToken,
  sha256,
} from './crypto';
import {
  OidcVerificationError,
  verifyOidcIdToken,
  type OidcProvider,
} from './oidc';

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  JWT_SECRET: string;
  ADMIN_API_TOKEN: string;
  HOME_AGENT_TOKEN: string;
  TAILSCALE_OAUTH_CLIENT_ID: string;
  TAILSCALE_OAUTH_CLIENT_SECRET: string;
  TAILSCALE_TAILNET: string;
  TAILSCALE_ENROLLMENT_ENABLED?: string;
  ALLOWED_ORIGIN: string;
  ACCESS_TOKEN_TTL_SECONDS: string;
  REFRESH_TOKEN_TTL_SECONDS: string;
  PENDING_DEVICE_TTL_SECONDS: string;
  RATE_LIMIT_WINDOW_SECONDS?: string;
  RATE_LIMIT_EMAIL_START_IP?: string;
  RATE_LIMIT_EMAIL_START_EMAIL?: string;
  RATE_LIMIT_EMAIL_VERIFY_IP?: string;
  RATE_LIMIT_EMAIL_VERIFY_CHALLENGE?: string;
  RATE_LIMIT_OIDC_START_IP?: string;
  RATE_LIMIT_OIDC_START_INSTALLATION?: string;
  RATE_LIMIT_OIDC_VERIFY_IP?: string;
  RATE_LIMIT_OIDC_VERIFY_CHALLENGE?: string;
  EMAIL_CODE_TTL_SECONDS?: string;
  OIDC_CHALLENGE_TTL_SECONDS?: string;
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
  APPLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_ID?: string;
  DIRECT_SIGNUP_ALLOWLIST?: string;
  CATALOG_ENCRYPTION_KEY?: string;
  CONFIRM_CLAIM_TTL_SECONDS?: string;
  RATE_LIMIT_DIAGNOSTICS_IP_HOUR?: string;
  RATE_LIMIT_DIAGNOSTICS_USER_HOUR?: string;
  RATE_LIMIT_DIAGNOSTICS_USER_DAY?: string;
  DIAGNOSTICS_RETENTION_SECONDS?: string;
}

type Row = Record<string, any>;

class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

const now = () => Math.floor(Date.now() / 1000);
const id = () => crypto.randomUUID();
const deviceActions = ['diagnostic_snapshot', 'claude_traffic_snapshot', 'refresh_catalog', 'retry_protection'] as const;
/** Failure vocabulary for device-action snapshots. (Diagnostics uploads carry
 *  the client's own free-text `error`/`failedStage` instead; see
 *  `canonicalDiagnosticsReport`.) */
const errorCategories = ['preparation', 'helper', 'kill_switch', 'tunnel', 'policy', 'dns', 'exit_check', 'data_plane', 'other'];

function fixedAction(value: unknown) {
  if (typeof value !== 'string' || !deviceActions.includes(value as typeof deviceActions[number])) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Unknown device action');
  }
  return value;
}

function rejectUnexpectedKeys(value: unknown, allowed: string[]): asserts value is Row {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Expected an object');
  }
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Unexpected field');
  }
}

function canonicalClaudeTrafficResearch(value: unknown) {
  const countKeys = [
    'observedConnectionCount', 'identifiedProcessConnectionCount',
    'proxiedConnectionCount', 'directConnectionCount', 'blockedConnectionCount',
    'directRouteAttemptCount', 'managedDirectRouteCount', 'unclassifiedRouteCount',
    'unsafeProtectionObservationCount',
    'webManagedDirectConnectionCount',
    'weChatConnectionCount', 'weChatManagedDirectConnectionCount',
    'weChatProxiedConnectionCount', 'weChatBlockedConnectionCount',
    'weChatEndpointUnknownProcessConnectionCount',
    'unknownManagedDirectConnectionCount', 'otherManagedDirectConnectionCount',
    'protectedDirectConnectionCount',
  ];
  const booleanKeys = [
    'connectionLimitReached', 'connected', 'killSwitchArmed', 'tunPresent',
    'protectedDNSConfigured',
  ];
  const expectedKeys = [
    'observedSince', 'droppedEndpointCount', ...countKeys, ...booleanKeys,
    'exitIdentityConsistency', 'physicalBypassProbe', 'entries',
  ];
  rejectUnexpectedKeys(value, expectedKeys);
  if (!exactKeys(value, expectedKeys) ||
      !Number.isSafeInteger(value.observedSince) || value.observedSince < 0 || value.observedSince > now() + 300 ||
      !Number.isSafeInteger(value.droppedEndpointCount) || value.droppedEndpointCount < 0 || value.droppedEndpointCount > 64 ||
      !Array.isArray(value.entries) || value.entries.length > 10) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid Claude traffic research snapshot');
  }
  for (const key of countKeys) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 0 || value[key] > 1_000_000) {
      throw new ApiError(400, 'VALIDATION_ERROR', `Invalid ${key}`);
    }
  }
  for (const key of booleanKeys) {
    if (typeof value[key] !== 'boolean') {
      throw new ApiError(400, 'VALIDATION_ERROR', `Invalid ${key}`);
    }
  }
  if (value.identifiedProcessConnectionCount > value.observedConnectionCount ||
      value.proxiedConnectionCount + value.directConnectionCount + value.blockedConnectionCount !== value.observedConnectionCount ||
      value.weChatConnectionCount > value.observedConnectionCount ||
      value.weChatManagedDirectConnectionCount + value.weChatProxiedConnectionCount + value.weChatBlockedConnectionCount !== value.weChatConnectionCount ||
      value.webManagedDirectConnectionCount + value.weChatManagedDirectConnectionCount + value.unknownManagedDirectConnectionCount + value.otherManagedDirectConnectionCount > value.directConnectionCount ||
      value.protectedDirectConnectionCount > value.directConnectionCount ||
      value.weChatEndpointUnknownProcessConnectionCount > value.observedConnectionCount) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Inconsistent Claude traffic research counts');
  }
  const exitIdentityConsistency = str(value.exitIdentityConsistency, 'exitIdentityConsistency', 1, 20);
  const physicalBypassProbe = str(value.physicalBypassProbe, 'physicalBypassProbe', 1, 20);
  if (!['MATCHED', 'MISMATCHED', 'INCONCLUSIVE'].includes(exitIdentityConsistency) ||
      !['BLOCKED', 'REACHABLE', 'INCONCLUSIVE'].includes(physicalBypassProbe)) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid Claude leak probe verdict');
  }
  const seen = new Set<string>();
  const entries = value.entries.map((raw: unknown) => {
    rejectUnexpectedKeys(raw, ['service', 'client', 'host', 'network', 'port', 'route', 'connections', 'upBytes', 'downBytes']);
    if (!exactKeys(raw, ['service', 'client', 'host', 'network', 'port', 'route', 'connections', 'upBytes', 'downBytes'])) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid Claude traffic research entry');
    }
    const service = str(raw.service, 'service', 1, 20);
    const client = str(raw.client, 'client', 1, 20);
    const host = str(raw.host, 'host', 1, 100);
    const network = str(raw.network, 'network', 1, 3);
    const route = str(raw.route, 'route', 1, 10);
    const officialHost = service === 'claude'
      ? host === 'claude.ai' || host.endsWith('.claude.ai')
      : service === 'anthropic' && (host === 'anthropic.com' || host.endsWith('.anthropic.com'));
    const labels = host.split('.');
    const validHostname = host.length <= 100 && labels.length >= 2 && labels.every((label) =>
      label.length >= 1 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) &&
      /^[a-z]{2,}$/.test(labels[labels.length - 1]) &&
      !['local', 'internal', 'localhost', 'home', 'lan'].includes(labels[labels.length - 1]);
    const attributedOther = service === 'other' && ['app', 'code'].includes(client);
    if ((!officialHost && !attributedOther) || !validHostname ||
        !['app', 'code', 'web', 'unknown'].includes(client) ||
        !['TCP', 'UDP'].includes(network) || !['PROXIED', 'DIRECT', 'BLOCKED'].includes(route) ||
        !Number.isSafeInteger(raw.port) || raw.port < 1 || raw.port > 65535 ||
        !Number.isSafeInteger(raw.connections) || raw.connections < 1 || raw.connections > 1_000_000 ||
        !Number.isSafeInteger(raw.upBytes) || raw.upBytes < 0 || raw.upBytes > 1_000_000_000_000_000 ||
        !Number.isSafeInteger(raw.downBytes) || raw.downBytes < 0 || raw.downBytes > 1_000_000_000_000_000) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid Claude traffic research entry');
    }
    const key = `${service}\n${client}\n${host}\n${network}\n${raw.port}\n${route}`;
    if (seen.has(key)) throw new ApiError(400, 'VALIDATION_ERROR', 'Duplicate Claude traffic research entry');
    seen.add(key);
    return {
      service, client, host, network, port: raw.port, route,
      connections: raw.connections, upBytes: raw.upBytes, downBytes: raw.downBytes,
    };
  }).sort((a, b) => {
    const left = `${a.service}\n${a.client}\n${a.host}\n${a.network}\n${String(a.port).padStart(5, '0')}\n${a.route}`;
    const right = `${b.service}\n${b.client}\n${b.host}\n${b.network}\n${String(b.port).padStart(5, '0')}\n${b.route}`;
    return left < right ? -1 : left > right ? 1 : 0;
  });
  return {
    observedSince: value.observedSince,
    droppedEndpointCount: value.droppedEndpointCount,
    ...Object.fromEntries(countKeys.map((key) => [key, value[key]])),
    ...Object.fromEntries(booleanKeys.map((key) => [key, value[key]])),
    exitIdentityConsistency,
    physicalBypassProbe,
    entries,
  };
}

function canonicalActionResult(value: unknown) {
  rejectUnexpectedKeys(value, ['outcome', 'message', 'snapshot', 'trafficResearch']);
  if (!['succeeded', 'failed'].includes(value.outcome)) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid outcome');
  }
  if (value.snapshot !== undefined && value.trafficResearch !== undefined) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Only one result snapshot is allowed');
  }
  const result: Row = { outcome: value.outcome };
  if (value.message !== undefined) result.message = str(value.message, 'message', 0, 200);
  if (value.snapshot !== undefined) {
    if (!value.snapshot || typeof value.snapshot !== 'object' || Array.isArray(value.snapshot)) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid snapshot');
    }
    const s = value.snapshot as Row;
    const bools = ['connected', 'connecting', 'disconnecting', 'protectionBlocked', 'killSwitchArmed', 'utunPresent', 'protectedDNSConfigured'];
    const strings = ['appVersion', 'build', 'selectedExit', 'connectionStage'];
    rejectUnexpectedKeys(s, [...bools, ...strings, 'reconnectAttempt', 'lastErrorCategory']);
    const snapshot: Row = {};
    for (const key of bools) {
      if (s[key] !== undefined && typeof s[key] !== 'boolean') throw new ApiError(400, 'VALIDATION_ERROR', `Invalid ${key}`);
      if (s[key] !== undefined) snapshot[key] = s[key];
    }
    for (const key of strings) {
      if (s[key] !== undefined) snapshot[key] = str(s[key], key, 0, 100);
    }
    if (s.lastErrorCategory !== undefined) {
      if (typeof s.lastErrorCategory !== 'string' || !errorCategories.includes(s.lastErrorCategory)) {
        throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid lastErrorCategory');
      }
      snapshot.lastErrorCategory = s.lastErrorCategory;
    }
    if (s.reconnectAttempt !== undefined) {
      if (!Number.isSafeInteger(s.reconnectAttempt) || s.reconnectAttempt < 0 || s.reconnectAttempt > 1000) throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid reconnectAttempt');
      snapshot.reconnectAttempt = s.reconnectAttempt;
    }
    result.snapshot = snapshot;
  }
  if (value.trafficResearch !== undefined) {
    result.trafficResearch = canonicalClaudeTrafficResearch(value.trafficResearch);
  }
  const json = JSON.stringify(result);
  if (new TextEncoder().encode(json).byteLength > 2048) throw new ApiError(400, 'VALIDATION_ERROR', 'Result is too large');
  return { result, json };
}

function publicAction(row: Row) {
  return {
    id: row.id, userId: row.user_id, deviceId: row.device_id, action: row.action,
    status: row.status, createdAt: Number(row.created_at), expiresAt: Number(row.expires_at),
    deliveredAt: row.delivered_at === null ? null : Number(row.delivered_at),
    completedAt: row.completed_at === null ? null : Number(row.completed_at),
    result: row.result_json ? JSON.parse(row.result_json) : null,
  };
}

const error = (e: unknown) => {
  const x = e instanceof ApiError ? e : new ApiError(500, 'INTERNAL_ERROR', 'Internal server error');
  return Response.json({ error: { code: x.code, message: x.message } }, { status: x.status });
};

async function body(req: Request, maxBytes = 1024 * 1024) {
  const declared = Number(req.headers.get('content-length') ?? '0');
  const declaredTooLarge = Number.isFinite(declared) && declared > maxBytes;
  try {
    const reader = req.body?.getReader();
    if (!reader && declaredTooLarge) {
      throw new ApiError(413, 'PAYLOAD_TOO_LARGE', 'Request body is too large');
    }
    if (!reader) throw new ApiError(400, 'INVALID_JSON', 'Expected a JSON body');
    const chunks: Uint8Array[] = [];
    let total = 0;
    let tooLarge = declaredTooLarge;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        // Drain an oversized stream before responding so neither workerd nor
        // an HTTP sender is left trying to feed an abandoned request body.
        if (tooLarge) continue;
        total += value.byteLength;
        if (total > maxBytes) {
          tooLarge = true;
          chunks.length = 0;
          continue;
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    if (tooLarge) {
      throw new ApiError(413, 'PAYLOAD_TOO_LARGE', 'Request body is too large');
    }
    const raw = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      raw.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw new ApiError(400, 'INVALID_JSON', 'Expected a JSON object');
    }
    return value as Row;
  } catch (x) {
    if (x instanceof ApiError) throw x;
    throw new ApiError(400, 'INVALID_JSON', 'Expected a JSON body');
  }
}

const str = (v: any, n: string, min = 1, max = 200) => {
  if (typeof v !== 'string' || v.length < min || v.length > max) {
    throw new ApiError(400, 'VALIDATION_ERROR', `Invalid ${n}`);
  }
  return v;
};

const email = (v: any) => {
  const x = str(v, 'email').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x)) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid email');
  }
  return x;
};

function bearer(req: Request) {
  const h = req.headers.get('authorization');
  if (!h?.startsWith('Bearer ')) throw new ApiError(401, 'UNAUTHORIZED', 'Bearer token required');
  const token = h.slice(7);
  if (!token || token.length > 4_096 || /\s/.test(token)) {
    throw new ApiError(401, 'UNAUTHORIZED', 'Invalid bearer token');
  }
  return token;
}

function clientIp(req: Request) {
  return req.headers.get('cf-connecting-ip') || '0.0.0.0';
}

function envInt(e: Env, key: keyof Env, fallback: number) {
  const raw = e[key];
  if (typeof raw !== 'string' || raw === '') return fallback;
  const n = Number(raw);
  return Number.isSafeInteger(n) && n > 0 ? n : fallback;
}

function tailscaleEnrollmentEnabled(e: Env) {
  return e.TAILSCALE_ENROLLMENT_ENABLED?.trim().toLowerCase() === 'true';
}

function requiredSecret(value: unknown) {
  if (typeof value !== 'string' || value.length < 32) {
    throw new ApiError(503, 'SERVICE_MISCONFIGURED', 'Service credentials are not configured');
  }
  return value;
}

function requiredCatalogKey(e: Env) {
  const value = requiredSecret(e.CATALOG_ENCRYPTION_KEY);
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new ApiError(503, 'SERVICE_MISCONFIGURED', 'Catalog encryption is not configured');
  }
  return value;
}

function managedCatalogYAML(value: unknown): string {
  const yaml = str(value, 'yaml', 11, 1024 * 1024);
  if (
    new TextEncoder().encode(yaml).byteLength > 1024 * 1024 ||
    yaml.includes('\0') ||
    yaml.split(/\r?\n/).some((line) => (
      line.length > 16 * 1024 ||
      [...line].some((character) => {
        const code = character.charCodeAt(0);
        return code < 0x09 || (code > 0x0D && code < 0x20) || code === 0x7F;
      })
    )) ||
    !/^proxies\s*:/m.test(yaml)
  ) {
    throw new ApiError(400, 'INVALID_CATALOG', 'Catalog must be bounded Clash YAML with a proxies section');
  }
  return yaml;
}

async function publicManagedCatalog(e: Env) {
  const row = await e.DB.prepare(
    'SELECT revision, ciphertext, nonce, content_sha256, updated_at FROM managed_exit_catalog WHERE singleton_id = 1',
  ).first<Row>();
  if (!row) {
    const yaml = 'proxies: []\n';
    return {
      revision: 0,
      yaml,
      sha256: await sha256(yaml),
      updatedAt: undefined,
    };
  }
  let yaml: string;
  try {
    yaml = await decryptCatalog(
      String(row.ciphertext),
      String(row.nonce),
      requiredCatalogKey(e),
    );
  } catch {
    throw new ApiError(503, 'CATALOG_UNAVAILABLE', 'Managed server catalog is unavailable');
  }
  const digest = await sha256(yaml);
  if (digest !== row.content_sha256) {
    throw new ApiError(503, 'CATALOG_UNAVAILABLE', 'Managed server catalog failed integrity validation');
  }
  return {
    revision: Number(row.revision),
    yaml,
    sha256: digest,
    updatedAt: Number(row.updated_at),
  };
}

type TrafficPolicy = {
  version: 1 | 2;
  domains: Array<{ host: string; ports: number[] }>;
  mediaEndpoints: Array<{ address: string; ports: number[] }>;
  webDomains?: Array<{ host: string; ports: number[] }>;
};

const emptyTrafficPolicy = (): TrafficPolicy => ({ version: 1, domains: [], mediaEndpoints: [] });

function exactKeys(value: Row, keys: string[]) {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function canonicalPorts(value: unknown, allowed: number[], name: string) {
  if (!Array.isArray(value) || value.length === 0 || value.some((port) => !Number.isInteger(port) || !allowed.includes(port))) {
    throw new ApiError(400, 'VALIDATION_ERROR', `Invalid ${name}`);
  }
  if (new Set(value).size !== value.length) {
    throw new ApiError(400, 'VALIDATION_ERROR', `Duplicate ${name}`);
  }
  return [...value].sort((a, b) => a - b) as number[];
}

function isPublicIPv4(address: string) {
  if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(address)) return false;
  const octets = address.split('.').map(Number);
  if (octets.some((part) => part > 255)) return false;
  const [a, b, c] = octets;
  return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 192 && b === 0) || (a === 192 && b === 88 && c === 99) ||
    (a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) ||
    (a === 203 && b === 0 && c === 113));
}

function canonicalTrafficPolicy(value: unknown): TrafficPolicy {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid policy');
  }
  const policy = value as Row;
  const isVersion1 = policy.version === 1 &&
    exactKeys(policy, ['version', 'domains', 'mediaEndpoints']);
  const isVersion2 = policy.version === 2 &&
    exactKeys(policy, ['version', 'domains', 'mediaEndpoints', 'webDomains']);
  if ((!isVersion1 && !isVersion2) ||
      !Array.isArray(policy.domains) || policy.domains.length > 32 ||
      !Array.isArray(policy.mediaEndpoints) || policy.mediaEndpoints.length > 64 ||
      (isVersion2 && (!Array.isArray(policy.webDomains) || policy.webDomains.length > 16))) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid traffic policy version or shape');
  }
  const allowedWeChatSuffixes = ['qq.com', 'qq.com.cn', 'qpic.cn', 'qlogo.cn', 'gtimg.cn', 'gtimg.com', 'wechat.com', 'weixin.com', 'weixinbridge.com', 'wxs.qq.com'];
  const allowedWebSuffixes = ['bilibili.com', 'biliapi.net', 'bilivideo.com', 'hdslb.com', 'qq.com', 'gtimg.cn', 'gtimg.com', 'iqiyi.com', 'qiyi.com', 'qiyipic.com', 'iqiyipic.com', 'youku.com', 'ykimg.com'];
  const allowedWebExactHosts = ['ykimg.alicdn.com'];
  const protectedSuffixes = ['anthropic.com', 'claude.ai', 'tono.app', 'tono.com'];
  const seenHosts = new Set<string>();
  const canonicalDomains = (
    values: unknown[],
    allowedSuffixes: string[],
    allowedExactHosts: string[],
    web: boolean,
  ) => values.map((entry: unknown) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || !exactKeys(entry as Row, ['host', 'ports'])) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid domain entry');
    }
    const { host, ports } = entry as Row;
    if (typeof host !== 'string' || host.length > 253 || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(host) ||
        protectedSuffixes.some((suffix) => host === suffix || host.endsWith(`.${suffix}`)) ||
        !allowedExactHosts.includes(host) && !allowedSuffixes.some((suffix) => host === suffix || host.endsWith(`.${suffix}`)) || seenHosts.has(host)) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid or duplicate domain host');
    }
    seenHosts.add(host);
    const canonical = canonicalPorts(ports, web ? [443] : [80, 443], 'domain ports');
    if (web && (canonical.length !== 1 || canonical[0] !== 443)) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Web direct domains require TCP port 443');
    }
    return { host, ports: canonical };
  }).sort((a, b) => a.host < b.host ? -1 : a.host > b.host ? 1 : 0);
  const domains = canonicalDomains(
    policy.domains,
    allowedWeChatSuffixes,
    [],
    false,
  );
  const seenAddresses = new Set<string>();
  const mediaEndpoints = policy.mediaEndpoints.map((entry: unknown) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || !exactKeys(entry as Row, ['address', 'ports'])) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid media endpoint');
    }
    const { address, ports } = entry as Row;
    if (typeof address !== 'string' || !isPublicIPv4(address) || seenAddresses.has(address)) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid or duplicate media address');
    }
    seenAddresses.add(address);
    return { address, ports: canonicalPorts(ports, [443, 8000], 'media ports') };
  }).sort((a, b) => a.address < b.address ? -1 : a.address > b.address ? 1 : 0);
  if (isVersion1) return { version: 1, domains, mediaEndpoints };
  const webDomains = canonicalDomains(
    policy.webDomains as unknown[],
    allowedWebSuffixes,
    allowedWebExactHosts,
    true,
  );
  return { version: 2, domains, mediaEndpoints, webDomains };
}

async function publicTrafficPolicy(e: Env) {
  const row = await e.DB.prepare(
    'SELECT revision, ciphertext, nonce, content_sha256, updated_at FROM managed_traffic_policy WHERE singleton_id = 1',
  ).first<Row>();
  if (!row) {
    const json = JSON.stringify(emptyTrafficPolicy());
    return { revision: 0, json, sha256: await sha256(json), updatedAt: undefined };
  }
  try {
    const json = await decryptTrafficPolicy(String(row.ciphertext), String(row.nonce), requiredCatalogKey(e));
    const digest = await sha256(json);
    if (digest !== row.content_sha256) throw new Error('digest mismatch');
    canonicalTrafficPolicy(JSON.parse(json));
    return { revision: Number(row.revision), json, sha256: digest, updatedAt: Number(row.updated_at) };
  } catch {
    throw new ApiError(503, 'TRAFFIC_POLICY_UNAVAILABLE', 'Managed traffic policy is unavailable');
  }
}

async function auth(req: Request, e: Env) {
  const p = await jwtVerify(bearer(req), requiredSecret(e.JWT_SECRET));
  if (
    typeof p?.sub !== 'string' ||
    p.sub.length === 0 ||
    typeof p.sid !== 'string' ||
    p.sid.length === 0
  ) {
    throw new ApiError(401, 'UNAUTHORIZED', 'Invalid or expired access token');
  }
  const t = now();
  const s = await e.DB.prepare(
    `SELECT sessions.*, users.status user_status, users.quota_bytes, users.usage_bytes, users.expires_at user_expires_at,
            devices.status device_status, devices.pending_expires_at, devices.installation_id
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     JOIN devices ON devices.id = sessions.device_id
     WHERE sessions.id = ? AND sessions.user_id = ? AND sessions.revoked_at IS NULL AND sessions.expires_at > ?`,
  ).bind(p.sid, p.sub, t).first<Row>();
  if (
    !s ||
    s.user_status !== 'active' ||
    !['active', 'pending'].includes(s.device_status) ||
    (s.device_status === 'pending' && s.pending_expires_at <= t) ||
    (s.user_expires_at !== null && s.user_expires_at <= t) ||
    (s.quota_bytes !== null && s.usage_bytes >= s.quota_bytes)
  ) {
    throw new ApiError(401, 'UNAUTHORIZED', 'Session is no longer active');
  }
  return {
    userId: String(s.user_id),
    sessionId: String(s.id),
    deviceId: String(s.device_id),
    installationId: String(s.installation_id),
  };
}

async function userId(req: Request, e: Env) {
  return (await auth(req, e)).userId;
}

async function privileged(req: Request, expected: string) {
  const actualHash = await sha256(bearer(req));
  const expectedHash = await sha256(requiredSecret(expected));
  let difference = actualHash.length ^ expectedHash.length;
  for (let index = 0; index < Math.max(actualHash.length, expectedHash.length); index++) {
    difference |= (actualHash.charCodeAt(index) || 0) ^ (expectedHash.charCodeAt(index) || 0);
  }
  if (difference !== 0) {
    throw new ApiError(401, 'UNAUTHORIZED', 'Invalid token');
  }
}

const publicUser = (u: Row) => ({
  id: u.id,
  email: u.email,
  name: u.name ?? undefined,
  plan: u.plan ?? undefined,
  deviceLimit: Number(u.device_limit ?? 2),
  quotaBytes: u.quota_bytes,
  usageBytes: u.usage_bytes,
  expiresAt: u.expires_at ?? undefined,
  suspended: u.status !== 'active',
  status: u.status,
  createdAt: u.created_at,
});

const publicDevice = (d: Row, currentId?: string) => ({
  id: d.id,
  name: d.name,
  installationId: d.installation_id,
  current: d.id === currentId,
  status: d.status,
  pendingExpiresAt: d.pending_expires_at,
  tailscaleNodeId: d.tailscale_node_id,
  stableNodeId: d.tailscale_stable_id ?? undefined,
  tailscaleApiNodeId: d.tailscale_api_node_id ?? undefined,
  tailscaleIPs: d.tailscale_ips ? JSON.parse(d.tailscale_ips) : [],
  lastSeenAt: d.last_seen_at ?? undefined,
  confirmedAt: d.confirmed_at ?? undefined,
  createdAt: d.created_at,
});

/** Multiset equality for Tailscale addresses (order-independent). */
function sameAddressSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sa = [...a].map(String).sort();
  const sb = [...b].map(String).sort();
  return sa.every((x, i) => x === sb[i]);
}

// --- Rate limiting (D1) -------------------------------------------------------

async function consumeRateLimit(e: Env, key: string, limit: number, windowSeconds: number) {
  const t = now();
  const cutoff = t - windowSeconds;
  const row = await e.DB.prepare(
    `INSERT INTO rate_limits(key, count, window_start)
     VALUES(?, 1, ?)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN rate_limits.window_start <= ? THEN 1 ELSE rate_limits.count + 1 END,
       window_start = CASE WHEN rate_limits.window_start <= ? THEN excluded.window_start ELSE rate_limits.window_start END
     RETURNING count`,
  ).bind(key, t, cutoff, cutoff).first<Row>();
  if (!row || Number(row.count) > limit) {
    throw new ApiError(429, 'RATE_LIMITED', 'Too many attempts; try again later');
  }
}

async function rateLimitEmailStart(e: Env, req: Request, emailAddr: string) {
  const windowSeconds = envInt(e, 'RATE_LIMIT_WINDOW_SECONDS', 900);
  const ipLimit = envInt(e, 'RATE_LIMIT_EMAIL_START_IP', 20);
  const emailLimit = envInt(e, 'RATE_LIMIT_EMAIL_START_EMAIL', 5);
  const ip = clientIp(req);
  await consumeRateLimit(e, `rl:${await sha256(`email-start:ip:${ip}`)}`, ipLimit, windowSeconds);
  await consumeRateLimit(e, `rl:${await sha256(`email-start:email:${emailAddr}`)}`, emailLimit, windowSeconds);
}

async function rateLimitChallenge(
  e: Env,
  req: Request,
  kind: 'email-verify' | 'oidc-verify',
  challengeId: string,
) {
  const windowSeconds = envInt(e, 'RATE_LIMIT_WINDOW_SECONDS', 900);
  const ipLimit = envInt(
    e,
    kind === 'email-verify' ? 'RATE_LIMIT_EMAIL_VERIFY_IP' : 'RATE_LIMIT_OIDC_VERIFY_IP',
    30,
  );
  const challengeLimit = envInt(
    e,
    kind === 'email-verify'
      ? 'RATE_LIMIT_EMAIL_VERIFY_CHALLENGE'
      : 'RATE_LIMIT_OIDC_VERIFY_CHALLENGE',
    5,
  );
  await consumeRateLimit(
    e,
    `rl:${await sha256(`${kind}:ip:${clientIp(req)}`)}`,
    ipLimit,
    windowSeconds,
  );
  await consumeRateLimit(
    e,
    `rl:${await sha256(`${kind}:challenge:${challengeId}`)}`,
    challengeLimit,
    windowSeconds,
  );
}

async function rateLimitOidcStart(e: Env, req: Request, installationId: string) {
  const windowSeconds = envInt(e, 'RATE_LIMIT_WINDOW_SECONDS', 900);
  await consumeRateLimit(
    e,
    `rl:${await sha256(`oidc-start:ip:${clientIp(req)}`)}`,
    envInt(e, 'RATE_LIMIT_OIDC_START_IP', 20),
    windowSeconds,
  );
  await consumeRateLimit(
    e,
    `rl:${await sha256(`oidc-start:installation:${installationId}`)}`,
    envInt(e, 'RATE_LIMIT_OIDC_START_INSTALLATION', 10),
    windowSeconds,
  );
}

// --- Diagnostics reports ------------------------------------------------------

// A degraded client on the kill-switch recovery channel gets one bounded
// upload, never a log firehose. Anything larger is rejected, not truncated:
// a silently trimmed report is worse than none for support.
const DIAGNOSTICS_BODY_MAX_BYTES = 32 * 1024;
// Backstop matching the column CHECK. The per-field bounds below already keep a
// fully-populated report under 8 KiB, so this only catches a schema change that
// forgets to re-check the total.
const DIAGNOSTICS_REPORT_MAX_BYTES = 16 * 1024;
const DIAGNOSTICS_HOUR_SECONDS = 3_600;
const DIAGNOSTICS_DAY_SECONDS = 86_400;
const DIAGNOSTICS_RETENTION_DEFAULT_SECONDS = 30 * DIAGNOSTICS_DAY_SECONDS;
/** Crockford-style: no 0/O/1/I, so a code survives being read over the phone. */
const referenceAlphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
const referencePattern = /^[2-9A-HJ-NP-Z]{8}$/;

function referenceCode() {
  // The alphabet is exactly 32 symbols, so masking the low five bits of each
  // random byte is uniform without rejection sampling. 32^8 ≈ 1.1e12 codes.
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let code = '';
  for (const byte of bytes) code += referenceAlphabet[byte & 31];
  return code;
}

/** Accept what a support agent actually types: lowercase, spaced, hyphenated. */
function normalizedReferenceCode(value: unknown) {
  const parsed = str(value, 'referenceCode', 1, 40).toUpperCase().replace(/[\s-]/g, '');
  if (!referencePattern.test(parsed)) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid referenceCode');
  }
  return parsed;
}

// The wire contract is owned by the client, which is already shipped:
// `crates/tono-core/src/auth.rs` (`DiagnosticsReport`) is its single
// definition and this intake mirrors it field for field. Serde emits every
// field, writing `null` for an absent optional, so a nullable field arriving
// as `null` and not arriving at all mean the same thing here: both drop out
// of the canonical form. The non-nullable fields are required.
const diagnosticsStepStates = ['pending', 'current', 'completed', 'failed'];
/** Fixed vocabulary; an unknown adapter class is rejected, not stored. */
const diagnosticsVirtualAdapters = [
  'hyperV', 'wsl', 'vmware', 'virtualBox', 'docker', 'loopbackAdapter',
];
const DIAGNOSTICS_MAX_STEPS = 32;
/** A connect attempt that "took" more than a day is a broken clock, not data. */
const DIAGNOSTICS_MAX_ELAPSED_MS = 24 * 60 * 60 * 1000;
/** 2100-01-01 in epoch ms. `reportedAtMs` is the *client* clock, and a skewed
 *  clock is itself a failure this report exists to capture, so it is bounded
 *  for storage sanity rather than checked against the server's clock. */
const DIAGNOSTICS_MAX_REPORTED_AT_MS = 4_102_444_800_000;
/** Required strings: [key, minLength, maxLength]. Only the two that are
 *  promoted to columns must be non-empty (the column CHECKs say so); an empty
 *  state name from a degraded client should not cost the whole upload. */
const diagnosticsStrings: Array<[string, number, number]> = [
  ['appVersion', 1, 40],
  ['osVersion', 1, 80],
  ['osArch', 0, 32],
  ['uiState', 0, 40],
  ['accountState', 0, 40],
  ['auditLogPath', 0, 400],
  ['serviceLogPath', 0, 400],
];
/** Nullable strings: [key, maxLength]. The error texts are redacted client-side. */
const diagnosticsNullableStrings: Array<[string, number]> = [
  ['serviceProtocol', 20],
  ['serviceBuild', 40],
  ['selectedServer', 100],
  ['killSwitchMode', 40],
  ['killSwitchLastError', 500],
  ['dnsLastError', 500],
  ['failedStage', 60],
  ['error', 500],
];
const diagnosticsNullableBools = ['killSwitchWanted', 'killSwitchLive', 'dnsEnabled'];
/** Numbers: [key, min, max, nullable]. */
const diagnosticsNumbers: Array<[string, number, number, boolean]> = [
  // Recorded rather than pinned to 1: a newer client must still be able to
  // reach support, and support needs to tell payload generations apart.
  ['schemaVersion', 1, 1_000, false],
  ['reportedAtMs', 0, DIAGNOSTICS_MAX_REPORTED_AT_MS, false],
  ['retryAttempt', 0, 1_000, false],
  ['catalogRevision', 0, 1_000_000_000_000, true],
  ['totalElapsedMs', 0, DIAGNOSTICS_MAX_ELAPSED_MS, true],
];
const diagnosticsKeys = [
  'schemaVersion', 'reportedAtMs', 'appVersion', 'osVersion', 'osArch',
  'serviceProtocol', 'serviceBuild', 'uiState', 'accountState', 'selectedServer',
  'catalogRevision', 'killSwitchMode', 'killSwitchWanted', 'killSwitchLive',
  'killSwitchLastError', 'dnsEnabled', 'dnsLastError', 'failedStage', 'error',
  'retryAttempt', 'totalElapsedMs', 'steps', 'virtualAdapters',
  'auditLogPath', 'serviceLogPath',
];

function diagnosticsInt(source: Row, key: string, min: number, max: number, nullable: boolean) {
  const raw = source[key];
  if (nullable && (raw === undefined || raw === null)) return undefined;
  if (!Number.isSafeInteger(raw) || (raw as number) < min || (raw as number) > max) {
    throw new ApiError(400, 'VALIDATION_ERROR', `Invalid ${key}`);
  }
  return raw as number;
}

/**
 * Whitelist the structured report. Nothing outside the schema is stored, the
 * bounds refuse rather than truncate, and the payload is never echoed back to
 * the uploader. `appVersion`/`osVersion` are also lifted into their own
 * columns by the caller, so their bounds match the column CHECKs exactly.
 */
function canonicalDiagnosticsReport(value: unknown) {
  rejectUnexpectedKeys(value, diagnosticsKeys);
  const source = value as Row;
  const parsed: Row = {};
  for (const [key, min, max] of diagnosticsStrings) {
    parsed[key] = str(source[key], key, min, max);
  }
  for (const [key, max] of diagnosticsNullableStrings) {
    if (source[key] === undefined || source[key] === null) continue;
    parsed[key] = str(source[key], key, 0, max);
  }
  for (const key of diagnosticsNullableBools) {
    if (source[key] === undefined || source[key] === null) continue;
    if (typeof source[key] !== 'boolean') {
      throw new ApiError(400, 'VALIDATION_ERROR', `Invalid ${key}`);
    }
    parsed[key] = source[key];
  }
  for (const [key, min, max, nullable] of diagnosticsNumbers) {
    const parsedNumber = diagnosticsInt(source, key, min, max, nullable);
    if (parsedNumber !== undefined) parsed[key] = parsedNumber;
  }
  if (!Array.isArray(source.steps) || source.steps.length > DIAGNOSTICS_MAX_STEPS) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid steps');
  }
  parsed.steps = source.steps.map((raw: unknown) => {
    rejectUnexpectedKeys(raw, ['key', 'state', 'elapsedMs']);
    const entry = raw as Row;
    const key = str(entry.key, 'step key', 0, 60);
    const state = str(entry.state, 'step state', 0, 20);
    if (!diagnosticsStepStates.includes(state)) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid step state');
    }
    const step: Row = { key, state };
    const elapsedMs = diagnosticsInt(entry, 'elapsedMs', 0, DIAGNOSTICS_MAX_ELAPSED_MS, true);
    if (elapsedMs !== undefined) step.elapsedMs = elapsedMs;
    return step;
  });
  // Bounded by the vocabulary itself: repeating a class carries no information
  // and is the shape a buggy collector produces, so it is refused.
  if (!Array.isArray(source.virtualAdapters) ||
      source.virtualAdapters.length > diagnosticsVirtualAdapters.length) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid virtualAdapters');
  }
  const seenAdapters = new Set<string>();
  parsed.virtualAdapters = source.virtualAdapters.map((raw: unknown) => {
    if (typeof raw !== 'string' || !diagnosticsVirtualAdapters.includes(raw) || seenAdapters.has(raw)) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid virtualAdapters');
    }
    seenAdapters.add(raw);
    return raw;
  });
  // Re-emit in the contract's own key order so stored reports diff cleanly.
  const report: Row = {};
  for (const key of diagnosticsKeys) {
    if (parsed[key] !== undefined) report[key] = parsed[key];
  }
  const json = JSON.stringify(report);
  if (new TextEncoder().encode(json).byteLength > DIAGNOSTICS_REPORT_MAX_BYTES) {
    throw new ApiError(413, 'PAYLOAD_TOO_LARGE', 'Diagnostics report is too large');
  }
  return {
    json,
    appVersion: report.appVersion as string,
    osVersion: report.osVersion as string,
  };
}

async function rateLimitDiagnostics(e: Env, req: Request, uid: string) {
  await consumeRateLimit(
    e,
    `rl:${await sha256(`diagnostics:ip:${clientIp(req)}`)}`,
    envInt(e, 'RATE_LIMIT_DIAGNOSTICS_IP_HOUR', 30),
    DIAGNOSTICS_HOUR_SECONDS,
  );
  await consumeRateLimit(
    e,
    `rl:${await sha256(`diagnostics:user-hour:${uid}`)}`,
    envInt(e, 'RATE_LIMIT_DIAGNOSTICS_USER_HOUR', 5),
    DIAGNOSTICS_HOUR_SECONDS,
  );
  await consumeRateLimit(
    e,
    `rl:${await sha256(`diagnostics:user-day:${uid}`)}`,
    envInt(e, 'RATE_LIMIT_DIAGNOSTICS_USER_DAY', 20),
    DIAGNOSTICS_DAY_SECONDS,
  );
}

async function storeDiagnosticsReport(
  e: Env,
  uid: string,
  clientVersion: string,
  osVersion: string,
  reportJson: string,
) {
  const receivedAt = now();
  // The unique index is the arbiter; a collision only costs another draw.
  for (let attempt = 0; attempt < 5; attempt++) {
    const code = referenceCode();
    const inserted = await e.DB.prepare(
      `INSERT OR IGNORE INTO diagnostics_reports(
         id, reference_code, user_id, received_at, client_version, os_version, report_json
       ) VALUES(?, ?, ?, ?, ?, ?, ?)`,
    ).bind(id(), code, uid, receivedAt, clientVersion, osVersion, reportJson).run();
    if (inserted.meta.changes) return { referenceCode: code, receivedAt };
  }
  throw new ApiError(503, 'DIAGNOSTICS_UNAVAILABLE', 'Could not allocate a reference code; try again');
}

const publicDiagnosticsReport = (r: Row) => ({
  id: r.id,
  referenceCode: r.reference_code,
  userId: r.user_id,
  receivedAt: Number(r.received_at),
  clientVersion: r.client_version,
  osVersion: r.os_version,
  report: JSON.parse(r.report_json),
});

// --- Passwordless authentication ---------------------------------------------

function challengeID(value: unknown): string {
  const parsed = str(value, 'challengeId', 36, 36).toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(parsed)) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid challengeId');
  }
  return parsed;
}

function oidcProvider(value: unknown): OidcProvider {
  if (value !== 'apple' && value !== 'google') {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid provider');
  }
  return value;
}

function emailDeliveryConfigured(e: Env): boolean {
  return typeof e.RESEND_API_KEY === 'string' &&
    e.RESEND_API_KEY.length >= 20 &&
    typeof e.EMAIL_FROM === 'string' &&
    e.EMAIL_FROM.length >= 3 &&
    e.EMAIL_FROM.length <= 320 &&
    e.EMAIL_FROM.includes('@') &&
    !/[\r\n]/.test(e.EMAIL_FROM);
}

function providerAudience(e: Env, provider: OidcProvider): string | undefined {
  const value = provider === 'apple' ? e.APPLE_CLIENT_ID : e.GOOGLE_CLIENT_ID;
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length >= 3 && trimmed.length <= 512 ? trimmed : undefined;
}

async function directSignupAllowed(e: Env, emailAddr: string): Promise<boolean> {
  const managed = await e.DB.prepare(
    'SELECT 1 FROM signup_allowlist WHERE email = ?',
  ).bind(emailAddr).first<Row>();
  if (managed) return true;

  // Keep the configuration allowlist as a backwards-compatible bootstrap
  // path. New individual users should be managed through the authenticated
  // admin API so granting access does not require a Worker redeployment.
  const configured = e.DIRECT_SIGNUP_ALLOWLIST;
  if (typeof configured !== 'string' || configured.length > 4096) return false;
  const entries = configured
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0);
  if (entries.length === 0 || entries.length > 100) return false;
  return entries.some((entry) => (
    entry.startsWith('@')
      ? emailAddr.endsWith(entry) && emailAddr.length > entry.length
      : emailAddr === entry
  ));
}

function numericCode(): string {
  // Rejection sampling avoids modulo bias in the six-digit code.
  const range = 1_000_000;
  const maximum = 0x1_0000_0000 - (0x1_0000_0000 % range);
  const value = new Uint32Array(1);
  do {
    crypto.getRandomValues(value);
  } while (value[0] >= maximum);
  return (value[0] % range).toString().padStart(6, '0');
}

async function challengeSecret(e: Env, challenge: string, secret: string) {
  return hmacSha256(
    `auth-challenge\u0000${challenge}\u0000${secret}`,
    requiredSecret(e.JWT_SECRET),
  );
}

async function deliverEmailCode(
  e: Env,
  recipient: string,
  code: string,
  challenge: string,
  ttlSeconds: number,
) {
  if (!emailDeliveryConfigured(e)) return false;
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      redirect: 'manual',
      headers: {
        authorization: `Bearer ${e.RESEND_API_KEY}`,
        'content-type': 'application/json',
        'idempotency-key': challenge,
      },
      body: JSON.stringify({
        from: e.EMAIL_FROM,
        to: [recipient],
        subject: 'Your Tono sign-in code',
        text: `Your Tono sign-in code is ${code}. It expires in ${Math.ceil(ttlSeconds / 60)} minutes. If you did not request it, you can ignore this email.`,
      }),
    });
    await response.body?.cancel();
    return response.ok;
  } catch (deliveryError) {
    console.error(
      'email delivery failed',
      deliveryError instanceof Error ? deliveryError.message : String(deliveryError),
    );
    return false;
  }
}

async function ensureEmailIdentity(e: Env, user: Row, emailAddr: string, t = now()) {
  await e.DB.prepare(
    `INSERT INTO auth_identities(
       provider, subject, user_id, email, email_verified_at, created_at, updated_at
     ) VALUES('email', ?, ?, ?, ?, ?, ?)
     ON CONFLICT(provider, subject) DO UPDATE SET
       email = excluded.email,
       email_verified_at = excluded.email_verified_at,
       updated_at = excluded.updated_at
     WHERE auth_identities.user_id = excluded.user_id`,
  ).bind(emailAddr, user.id, emailAddr, t, t, t).run();
  const identity = await e.DB.prepare(
    "SELECT user_id FROM auth_identities WHERE provider = 'email' AND subject = ?",
  ).bind(emailAddr).first<Row>();
  if (!identity || identity.user_id !== user.id) {
    throw new ApiError(409, 'IDENTITY_CONFLICT', 'This sign-in identity is already linked');
  }
}

async function accountForVerifiedEmail(
  e: Env,
  emailAddr: string,
): Promise<Row> {
  let user = await e.DB.prepare('SELECT * FROM users WHERE email = ?').bind(emailAddr).first<Row>();
  if (user) {
    if (ineligible(user)) throw new ApiError(403, 'USER_DISABLED', 'User is disabled');
    await ensureEmailIdentity(e, user, emailAddr);
    return user;
  }

  if (!(await directSignupAllowed(e, emailAddr))) {
    throw new ApiError(401, 'AUTHENTICATION_FAILED', 'Authentication could not be completed');
  }
  const t = now();
  const userId = id();
  let creationError: unknown;
  try {
    // The verified email or OIDC claim is the account-creation authority.
    // INSERT OR IGNORE makes concurrent first sign-ins converge on the same
    // unique email without requiring an invitation/redemption transaction.
    await e.DB.prepare(
      `INSERT OR IGNORE INTO users(
         id, email, password_hash, password_salt, created_at, updated_at
       ) VALUES(?, ?, ?, ?, ?, ?)`,
    ).bind(
      userId,
      emailAddr,
      'PASSWORD_AUTH_DISABLED',
      'PASSWORD_AUTH_DISABLED',
      t,
      t,
    ).run();
  } catch (error) {
    // Resolve a concurrent first sign-in below. D1 uniqueness constraints
    // ensure that only the account for this verified email can be selected.
    creationError = error;
  }
  user = await e.DB.prepare('SELECT * FROM users WHERE email = ?').bind(emailAddr).first<Row>();
  if (!user) {
    if (creationError) {
      throw new ApiError(
        503,
        'ACCOUNT_CREATION_UNAVAILABLE',
        'Account activation is temporarily unavailable',
      );
    }
    throw new ApiError(401, 'AUTHENTICATION_FAILED', 'Authentication could not be completed');
  }
  if (ineligible(user)) throw new ApiError(403, 'USER_DISABLED', 'User is disabled');
  await ensureEmailIdentity(e, user, emailAddr, t);
  return user;
}

async function accountForOidcIdentity(
  e: Env,
  identity: Awaited<ReturnType<typeof verifyOidcIdToken>>,
): Promise<Row> {
  const linked = await e.DB.prepare(
    `SELECT users.*
     FROM auth_identities
     JOIN users ON users.id = auth_identities.user_id
     WHERE auth_identities.provider = ? AND auth_identities.subject = ?`,
  ).bind(identity.provider, identity.subject).first<Row>();
  if (linked) {
    if (ineligible(linked)) throw new ApiError(403, 'USER_DISABLED', 'User is disabled');
    return linked;
  }
  if (!identity.email || !identity.emailVerified) {
    throw new ApiError(
      401,
      'VERIFIED_EMAIL_REQUIRED',
      'The identity provider did not return a verified email address',
    );
  }

  const user = await accountForVerifiedEmail(e, identity.email);
  const t = now();
  try {
    await e.DB.prepare(
      `INSERT INTO auth_identities(
         provider, subject, user_id, email, email_verified_at, created_at, updated_at
       ) VALUES(?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      identity.provider,
      identity.subject,
      user.id,
      identity.email,
      t,
      t,
      t,
    ).run();
    return user;
  } catch {
    const raced = await e.DB.prepare(
      `SELECT users.*
       FROM auth_identities
       JOIN users ON users.id = auth_identities.user_id
       WHERE auth_identities.provider = ? AND auth_identities.subject = ?`,
    ).bind(identity.provider, identity.subject).first<Row>();
    if (!raced) {
      const existingProvider = await e.DB.prepare(
        `SELECT 1 FROM auth_identities
         WHERE provider = ? AND user_id = ?`,
      ).bind(identity.provider, user.id).first<Row>();
      if (existingProvider) {
        throw new ApiError(409, 'IDENTITY_CONFLICT', 'This sign-in identity is already linked');
      }
      throw new ApiError(
        503,
        'IDENTITY_LINK_UNAVAILABLE',
        'Identity linking is temporarily unavailable',
      );
    }
    if (ineligible(raced)) throw new ApiError(403, 'USER_DISABLED', 'User is disabled');
    return raced;
  }
}

async function completePasswordlessAuth(
  e: Env,
  user: Row,
  deviceName: string,
  installationId: string,
) {
  if (ineligible(user)) throw new ApiError(403, 'USER_DISABLED', 'User is disabled');
  return authResult(e, user, await ensureDevice(e, user.id, deviceName, installationId));
}

async function recordChallengeFailure(e: Env, challenge: string, kind: string) {
  await e.DB.prepare(
    `UPDATE auth_challenges
     SET attempts = attempts + 1
     WHERE id = ? AND kind = ? AND consumed_at IS NULL
       AND expires_at > ? AND attempts < max_attempts`,
  ).bind(challenge, kind, now()).run();
}

// --- Tokens / devices ---------------------------------------------------------

async function tokens(e: Env, user: string, device: string, installation: string) {
  const refresh = randomToken();
  const t = now();
  const sid = id();
  const accessTTL = envInt(e, 'ACCESS_TOKEN_TTL_SECONDS', 900);
  const refreshTTL = envInt(e, 'REFRESH_TOKEN_TTL_SECONDS', 2_592_000);
  await e.DB.prepare(
    'INSERT INTO sessions(id, user_id, refresh_hash, expires_at, created_at, device_id) VALUES(?, ?, ?, ?, ?, ?)',
  ).bind(sid, user, await sha256(refresh), t + refreshTTL, t, device).run();
  return {
    accessToken: await jwtSign(
      { sub: user, sid, did: device, iid: installation, iat: t, exp: t + accessTTL },
      requiredSecret(e.JWT_SECRET),
    ),
    refreshToken: refresh,
  };
}

async function authResult(e: Env, u: Row, d: Row) {
  const enrollment =
    tailscaleEnrollmentEnabled(e) && d.status === 'pending'
      ? await issueEnrollment(e, d)
      : undefined;
  return {
    ...await tokens(e, u.id, d.id, d.installation_id),
    user: publicUser(u),
    device: publicDevice(d, d.id),
    enrollment,
  };
}

async function enqueueRevocation(
  e: Env,
  deviceId: string,
  managementId: string,
  ownershipGeneration = -1,
  reason = 'orphan_cleanup',
  t = now(),
) {
  await e.DB.prepare(
    `INSERT INTO revocation_jobs(
       id, device_id, tailscale_node_id, created_at, ownership_generation, reason
     ) VALUES(?, ?, ?, ?, ?, ?)
     ON CONFLICT(tailscale_node_id) DO UPDATE SET
       completed_at = NULL,
       last_error = NULL,
       device_id = excluded.device_id,
       created_at = excluded.created_at,
       ownership_generation = excluded.ownership_generation,
       reason = excluded.reason`,
  ).bind(id(), deviceId, managementId, t, ownershipGeneration, reason).run();
}

/**
 * Expire pending devices for a user. When a management id is already stored
 * (e.g. mid-confirm claim), enqueue durable Tailscale deletion.
 */
async function expirePending(e: Env, user: string) {
  const t = now();
  const q = await e.DB.prepare(
    `SELECT id, tailscale_node_id, claim_generation
     FROM devices
     WHERE user_id = ? AND status = 'pending' AND pending_expires_at <= ?`,
  ).bind(user, t).all<Row>();
  for (const d of q.results) {
    const statements: D1PreparedStatement[] = [];
    if (d.tailscale_node_id) {
      statements.push(
        e.DB.prepare(
          `INSERT INTO revocation_jobs(
             id, device_id, tailscale_node_id, created_at, ownership_generation, reason
           )
           SELECT ?, id, tailscale_node_id, ?, claim_generation, 'pending_expired'
           FROM devices
           WHERE id = ? AND user_id = ? AND status = 'pending'
             AND pending_expires_at <= ? AND claim_generation = ?
             AND tailscale_node_id IS NOT NULL
           ON CONFLICT(tailscale_node_id) DO UPDATE SET
             completed_at = NULL,
             last_error = NULL,
             device_id = excluded.device_id,
             created_at = excluded.created_at,
             ownership_generation = excluded.ownership_generation,
             reason = excluded.reason`,
        ).bind(id(), t, d.id, user, t, d.claim_generation),
      );
    }
    statements.push(
      e.DB.prepare(
        `UPDATE devices SET
           status = 'revoked',
           claim_token = NULL,
           claim_expires_at = NULL,
           updated_at = ?
         WHERE id = ? AND user_id = ? AND status = 'pending'
           AND pending_expires_at <= ? AND claim_generation = ?`,
      ).bind(t, d.id, user, t, d.claim_generation),
      e.DB.prepare(
        `UPDATE sessions SET revoked_at = ?
         WHERE device_id = ? AND revoked_at IS NULL
           AND EXISTS (
             SELECT 1 FROM devices
             WHERE id = ? AND status = 'revoked' AND claim_generation = ?
           )`,
      ).bind(t, d.id, d.id, d.claim_generation),
    );
    await e.DB.batch(statements);
  }
}

async function ensureDevice(e: Env, user: string, name: string, installation: string) {
  await expirePending(e, user);
  let d = await e.DB.prepare('SELECT * FROM devices WHERE user_id = ? AND installation_id = ?').bind(user, installation).first<Row>();
  const enrollmentEnabled = tailscaleEnrollmentEnabled(e);
  if (d && d.status === 'active') return d;
  const t = now();
  if (d && d.status === 'pending' && !enrollmentEnabled) {
    await e.DB.prepare(
      `UPDATE devices SET
         name = ?,
         status = 'active',
         pending_expires_at = NULL,
         claim_token = NULL,
         claim_expires_at = NULL,
         enrollment_issued_at = NULL,
         enrollment_hostname = NULL,
         confirmed_at = ?,
         last_seen_at = ?,
         updated_at = ?
       WHERE id = ? AND status = 'pending'`,
    ).bind(name, t, t, t, d.id).run();
    return (await e.DB.prepare('SELECT * FROM devices WHERE id = ?').bind(d.id).first<Row>())!;
  }
  if (d && d.status === 'pending') return d;
  const pendingTTL = envInt(e, 'PENDING_DEVICE_TTL_SECONDS', 1_800);
  const did = d?.id || id();
  try {
    if (d) {
      if (enrollmentEnabled) {
        await e.DB.prepare(
          `UPDATE devices SET
             name = ?,
             status = 'pending',
             pending_expires_at = ?,
             updated_at = ?,
             tailscale_node_id = NULL,
             tailscale_stable_id = NULL,
             tailscale_api_node_id = NULL,
             tailscale_public_key = NULL,
             tailscale_ips = NULL,
             claim_token = NULL,
             claim_expires_at = NULL,
             claim_generation = claim_generation + 1,
             enrollment_issued_at = NULL,
             enrollment_hostname = NULL,
             confirmed_at = NULL
           WHERE id = ? AND status = 'revoked'`,
        ).bind(name, t + pendingTTL, t, did).run();
      } else {
        await e.DB.prepare(
          `UPDATE devices SET
             name = ?,
             status = 'active',
             pending_expires_at = NULL,
             updated_at = ?,
             tailscale_node_id = NULL,
             tailscale_stable_id = NULL,
             tailscale_api_node_id = NULL,
             tailscale_public_key = NULL,
             tailscale_ips = NULL,
             claim_token = NULL,
             claim_expires_at = NULL,
             claim_generation = claim_generation + 1,
             enrollment_issued_at = NULL,
             enrollment_hostname = NULL,
             confirmed_at = ?,
             last_seen_at = ?
           WHERE id = ? AND status = 'revoked'`,
        ).bind(name, t, t, t, did).run();
      }
    } else {
      if (enrollmentEnabled) {
        await e.DB.prepare(
          "INSERT INTO devices(id, user_id, installation_id, name, status, pending_expires_at, created_at, updated_at) VALUES(?, ?, ?, ?, 'pending', ?, ?, ?)",
        ).bind(did, user, installation, name, t + pendingTTL, t, t).run();
      } else {
        await e.DB.prepare(
          `INSERT INTO devices(
             id, user_id, installation_id, name, status,
             pending_expires_at, confirmed_at, last_seen_at, created_at, updated_at
           ) VALUES(?, ?, ?, ?, 'active', NULL, ?, ?, ?, ?)`,
        ).bind(did, user, installation, name, t, t, t, t).run();
      }
    }
  } catch (x) {
    if (String(x).includes('DEVICE_LIMIT')) {
      throw new ApiError(409, 'DEVICE_LIMIT', 'This account has reached its device allowance');
    }
    throw x;
  }
  return (await e.DB.prepare('SELECT * FROM devices WHERE id = ?').bind(did).first<Row>())!;
}

// --- Tailscale ----------------------------------------------------------------

async function tailscaleToken(e: Env) {
  const r = await fetch('https://api.tailscale.com/api/v2/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: e.TAILSCALE_OAUTH_CLIENT_ID,
      client_secret: requiredSecret(e.TAILSCALE_OAUTH_CLIENT_SECRET),
      grant_type: 'client_credentials',
      // Explicitly downscope every generated access token. The credential is
      // configured with a grantless controller tag that owns only the pending
      // and active client tags in the repository policy artifact.
      scope: 'auth_keys devices:core',
      tags: 'tag:tono-controller',
    }).toString(),
  });
  if (!r.ok) {
    await r.body?.cancel();
    throw new ApiError(502, 'TAILSCALE_ERROR', 'Tailscale authentication failed');
  }
  const accessToken = (await r.json() as Row).access_token;
  if (
    typeof accessToken !== 'string' ||
    accessToken.length < 8 ||
    accessToken.length > 4_096 ||
    /\s/.test(accessToken)
  ) {
    throw new ApiError(502, 'TAILSCALE_ERROR', 'Tailscale authentication failed');
  }
  return accessToken;
}

async function tailscale(
  e: Env,
  path: string,
  init: RequestInit = {},
  allowNotFound = false,
  accessToken?: string,
) {
  const r = await fetch(`https://api.tailscale.com/api/v2${path}`, {
    ...init,
    headers: { ...init.headers, authorization: `Bearer ${accessToken ?? await tailscaleToken(e)}` },
  });
  if (!r.ok && !(allowNotFound && r.status === 404)) {
    await r.body?.cancel();
    throw new ApiError(502, 'TAILSCALE_ERROR', 'Tailscale API request failed');
  }
  return r;
}

interface ResolvedTailscaleDevice {
  managementId: string;
  apiNodeId?: string;
  publicKey?: string;
  addresses: string[];
}

function normalizedNodeKey(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return trimmed.startsWith('nodekey:') ? trimmed.slice('nodekey:'.length) : trimmed;
}

/**
 * Resolve a pending Tailscale node from tailnet inventory.
 * NEVER use client-submitted IDs as GET /device/{id} path segments.
 * Management API `id` is used only for /device/{id}/tags and DELETE.
 */
async function resolveFromInventory(
  e: Env,
  opts: {
    stableNodeId: string;
    nodeId?: string;
    publicKey?: string;
    ips: string[];
    enrollmentHostname: string;
  },
): Promise<ResolvedTailscaleDevice> {
  const r = await tailscale(e, `/tailnet/${encodeURIComponent(e.TAILSCALE_TAILNET)}/devices`);
  if (!r.ok) throw new ApiError(502, 'TAILSCALE_ERROR', 'Failed to list tailnet devices');
  const data = await r.json() as Row;
  const inventory: Row[] = Array.isArray(data.devices) ? data.devices : [];

  const candidates = inventory.filter((td) => {
    const tags: string[] = Array.isArray(td.tags) ? td.tags.map(String) : [];
    const addresses: string[] = Array.isArray(td.addresses) ? td.addresses.map(String) : [];
    const hostnameLabels = [td.name, td.hostname, td.hostName, td.dnsName, td.DNSName]
      .filter((value) => typeof value === 'string')
      .map((value) => String(value).trim().toLowerCase().replace(/\.$/, '').split('.')[0]);
    return tags.includes('tag:pending-tunnel-client') &&
      hostnameLabels.includes(opts.enrollmentHostname) &&
      sameAddressSet(addresses, opts.ips);
  });

  if (candidates.length === 0) {
    throw new ApiError(
      400,
      'INVALID_TAILSCALE_NODE',
      'No pending Tailscale node matches this enrollment and the submitted addresses',
    );
  }

  let narrowed = candidates;
  let hasServerVerifiedIdentity = false;

  if (opts.nodeId) {
    narrowed = narrowed.filter((td) => String(td.nodeId ?? '') === opts.nodeId);
    if (narrowed.length === 0) {
      throw new ApiError(400, 'INVALID_TAILSCALE_NODE', 'Submitted nodeId does not match pending inventory');
    }
    hasServerVerifiedIdentity = true;
  }
  if (opts.publicKey) {
    const submittedKey = normalizedNodeKey(opts.publicKey);
    narrowed = narrowed.filter((td) => {
      const fields = [td.publicKey, td.key, td.nodeKey]
        .map(normalizedNodeKey)
        .filter((x): x is string => x !== undefined);
      return submittedKey !== undefined && fields.includes(submittedKey);
    });
    if (narrowed.length === 0) {
      throw new ApiError(400, 'INVALID_TAILSCALE_NODE', 'Submitted publicKey does not match pending inventory');
    }
    hasServerVerifiedIdentity = true;
  }

  // Some Device API versions expose StableNodeID explicitly. If present, it must
  // agree exactly; hostnames and management ids are never substitutes.
  const stableFields = (td: Row) =>
    [td.stableNodeId, td.stableNodeID, td.stableId]
      .filter((x) => x != null)
      .map(String);
  const serverExposesStableId = narrowed.some((td) => stableFields(td).length > 0);
  const stableMatches = narrowed.filter((td) => stableFields(td).includes(opts.stableNodeId));
  if (serverExposesStableId) {
    if (stableMatches.length === 0) {
      throw new ApiError(400, 'INVALID_TAILSCALE_NODE', 'Submitted stableNodeId does not match pending inventory');
    }
    narrowed = stableMatches;
    hasServerVerifiedIdentity = true;
  }

  if (!hasServerVerifiedIdentity) {
    throw new ApiError(
      400,
      'UNVERIFIABLE_TAILSCALE_IDENTITY',
      'A server-verifiable nodeId or publicKey is required',
    );
  }
  if (narrowed.length !== 1) {
    throw new ApiError(400, 'INVALID_TAILSCALE_NODE', 'Ambiguous Tailscale node for submitted identity');
  }

  const matched = narrowed[0];
  const managementId = str(matched.id, 'tailscaleDeviceId', 1, 200);
  const apiNodeId = matched.nodeId != null ? String(matched.nodeId) : undefined;
  const publicKey = [matched.publicKey, matched.key, matched.nodeKey]
    .map(normalizedNodeKey)
    .find((x): x is string => x !== undefined);
  const addresses: string[] = Array.isArray(matched.addresses) ? matched.addresses.map(String) : [];
  return { managementId, apiNodeId, publicKey, addresses };
}

function ineligible(u: Row, t = now()) {
  return u.status !== 'active' ||
    (u.expires_at !== null && u.expires_at <= t) ||
    (u.quota_bytes !== null && u.usage_bytes >= u.quota_bytes);
}

async function revokeDevice(e: Env, d: Row, requireIneligibleUser = false) {
  const t = now();
  const requireFlag = requireIneligibleUser ? 1 : 0;
  await e.DB.batch([
    // Resolve claim_generation inside this transaction. Reading it before the
    // batch creates a race where a concurrent confirm can advance generation
    // and make a successful-looking revoke update zero rows.
    e.DB.prepare(
      `INSERT INTO revocation_jobs(
         id, device_id, tailscale_node_id, created_at, ownership_generation, reason
       )
       SELECT ?, id, tailscale_node_id, ?, claim_generation, 'device_revoked'
       FROM devices
       WHERE id = ? AND status IN ('active', 'pending')
         AND tailscale_node_id IS NOT NULL
         AND (
           ? = 0 OR EXISTS (
             SELECT 1 FROM users
             WHERE users.id = devices.user_id
               AND (
                 users.status != 'active'
                 OR (users.expires_at IS NOT NULL AND users.expires_at <= ?)
                 OR (users.quota_bytes IS NOT NULL AND users.usage_bytes >= users.quota_bytes)
               )
           )
         )
       ON CONFLICT(tailscale_node_id) DO UPDATE SET
         completed_at = NULL,
         last_error = NULL,
         device_id = excluded.device_id,
         created_at = excluded.created_at,
         ownership_generation = excluded.ownership_generation,
         reason = excluded.reason`,
    ).bind(id(), t, d.id, requireFlag, t),
    e.DB.prepare(
      `UPDATE devices SET
         status = 'revoked',
         claim_token = NULL,
         claim_expires_at = NULL,
         updated_at = ?
       WHERE id = ? AND status IN ('active', 'pending')
         AND (
           ? = 0 OR EXISTS (
             SELECT 1 FROM users
             WHERE users.id = devices.user_id
               AND (
                 users.status != 'active'
                 OR (users.expires_at IS NOT NULL AND users.expires_at <= ?)
                 OR (users.quota_bytes IS NOT NULL AND users.usage_bytes >= users.quota_bytes)
               )
             )
           )`,
    ).bind(t, d.id, requireFlag, t),
    e.DB.prepare(
      `UPDATE sessions SET revoked_at = ?
       WHERE device_id = ? AND revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM devices
           WHERE devices.id = ? AND devices.status = 'revoked'
         )`,
    ).bind(t, d.id, d.id),
  ]);
}

/**
 * Clear only the exact failed claim generation. A durable guard job is written
 * before tag promotion, so this function never has to infer current ownership.
 */
async function compensateConfirmFailure(
  e: Env,
  deviceId: string,
  claimToken: string,
  claimGeneration: number,
) {
  const t = now();
  await e.DB.prepare(
    `UPDATE devices SET claim_token = NULL, claim_expires_at = NULL,
       tailscale_node_id = NULL, tailscale_stable_id = NULL,
       tailscale_api_node_id = NULL, tailscale_public_key = NULL,
       tailscale_ips = NULL, updated_at = ?
     WHERE id = ? AND status = 'pending' AND claim_token = ?
       AND claim_generation = ?`,
  ).bind(t, deviceId, claimToken, claimGeneration).run();
  try {
    await processRevocations(e);
  } catch (x) {
    console.error('compensation processRevocations failed', x instanceof Error ? x.message : String(x));
  }
}

async function clearClaim(e: Env, deviceId: string, claimToken: string, claimGeneration: number) {
  const t = now();
  await e.DB.prepare(
    `UPDATE devices SET claim_token = NULL, claim_expires_at = NULL, updated_at = ?
     WHERE id = ? AND claim_token = ? AND claim_generation = ?
       AND status = 'pending'`,
  ).bind(t, deviceId, claimToken, claimGeneration).run();
}

async function processRevocations(e: Env) {
  // Keep durable jobs queued while Home-US is paused, but do not contact
  // Tailscale from API requests or scheduled maintenance.
  if (!tailscaleEnrollmentEnabled(e)) return;
  const jobs = await e.DB.prepare(
    'SELECT * FROM revocation_jobs WHERE completed_at IS NULL ORDER BY created_at LIMIT 40',
  ).all<Row>();
  let oauthToken: string | undefined;
  for (const job of jobs.results) {
    try {
      const jobGeneration = Number(job.ownership_generation ?? -1);
      const t = now();

      // An active D1 owner is authoritative. This also retires a stale guard job
      // left behind after a successful activation acknowledgement failed.
      const owner = await e.DB.prepare(
        `SELECT id, status, claim_token, claim_expires_at, claim_generation
         FROM devices
         WHERE tailscale_node_id = ? AND status IN ('active', 'pending')
         ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END
         LIMIT 1`,
      ).bind(job.tailscale_node_id).first<Row>();
      if (owner?.status === 'active') {
        await e.DB.prepare(
          `UPDATE revocation_jobs SET completed_at = ?, last_error = ?
           WHERE id = ? AND device_id = ? AND ownership_generation = ?`,
        ).bind(t, 'skipped: node has a live active owner', job.id, job.device_id, jobGeneration).run();
        continue;
      }
      if (owner?.status === 'pending' && owner.claim_token && Number(owner.claim_expires_at ?? 0) > t) {
        await e.DB.prepare(
          `UPDATE revocation_jobs SET last_error = ?
           WHERE id = ? AND device_id = ? AND ownership_generation = ?`,
        ).bind('deferred: node has a live confirm claim', job.id, job.device_id, jobGeneration).run();
        continue;
      }

      // A newer claim for the same installation may not have stored its
      // management id yet. Defer until it either binds/activates or expires.
      const newerClaim = await e.DB.prepare(
        `SELECT id FROM devices
         WHERE id = ? AND status = 'pending' AND claim_generation > ?
           AND claim_token IS NOT NULL AND claim_expires_at > ?`,
      ).bind(job.device_id, jobGeneration, t).first<Row>();
      if (newerClaim) {
        await e.DB.prepare(
          `UPDATE revocation_jobs SET last_error = ?
           WHERE id = ? AND device_id = ? AND ownership_generation = ?`,
        ).bind('deferred: device has a newer confirm claim', job.id, job.device_id, jobGeneration).run();
        continue;
      }

      oauthToken ??= await tailscaleToken(e);
      const deletion = await tailscale(
        e,
        `/device/${encodeURIComponent(job.tailscale_node_id)}`,
        { method: 'DELETE' },
        true,
        oauthToken,
      );
      await deletion.body?.cancel();
      await e.DB.prepare(
        `UPDATE revocation_jobs SET completed_at = ?, last_error = NULL
         WHERE id = ? AND device_id = ? AND ownership_generation = ?`,
      ).bind(now(), job.id, job.device_id, jobGeneration).run();
    } catch (x) {
      await e.DB.prepare(
        `UPDATE revocation_jobs SET last_error = ?
         WHERE id = ? AND device_id = ? AND ownership_generation = ?`,
      ).bind(
        String(x instanceof Error ? x.message : x).slice(0, 500),
        job.id,
        job.device_id,
        Number(job.ownership_generation ?? -1),
      ).run();
    }
  }
}

/**
 * Pending nodes created with description `tono-device-{deviceId}` that no longer
 * have a live pending D1 row should be deleted via the durable outbox.
 */
async function cleanupOrphanPendingNodes(e: Env) {
  if (!tailscaleEnrollmentEnabled(e)) return;
  const r = await tailscale(e, `/tailnet/${encodeURIComponent(e.TAILSCALE_TAILNET)}/devices`);
  if (!r.ok) return;
  const data = await r.json() as Row;
  const inventory: Row[] = Array.isArray(data.devices) ? data.devices : [];
  const t = now();
  for (const td of inventory) {
    const tags: string[] = Array.isArray(td.tags) ? td.tags.map(String) : [];
    if (!tags.includes('tag:pending-tunnel-client')) continue;
    const desc = String(td.description ?? '');
    if (!desc.startsWith('tono-device-')) continue;
    const deviceId = desc.slice('tono-device-'.length);
    if (!deviceId || !td.id) continue;
    const d = await e.DB.prepare(
      'SELECT id, status, pending_expires_at, enrollment_hostname FROM devices WHERE id = ?',
    ).bind(deviceId).first<Row>();
    const inventoryLabels = [td.name, td.hostname, td.hostName, td.dnsName, td.DNSName]
      .filter((value) => typeof value === 'string')
      .map((value) => String(value).trim().toLowerCase().replace(/\.$/, '').split('.')[0]);
    const orphan =
      !d ||
      d.status === 'revoked' ||
      (d.status === 'pending' && (
        (d.pending_expires_at != null && d.pending_expires_at <= t) ||
        typeof d.enrollment_hostname !== 'string' ||
        !inventoryLabels.includes(d.enrollment_hostname)
      ));
    if (orphan) {
      await enqueueRevocation(e, deviceId, String(td.id), -1, 'orphan_pending_node', t);
    }
  }
}

async function enforceUser(e: Env, userId: string, processNow = true) {
  const u = await e.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first<Row>();
  if (!u || !ineligible(u)) return;
  const ds = await e.DB.prepare("SELECT * FROM devices WHERE user_id = ? AND status IN ('active', 'pending')").bind(userId).all<Row>();
  for (const d of ds.results) await revokeDevice(e, d, true);
  const t = now();
  await e.DB.prepare(
    `UPDATE sessions SET revoked_at = ?
     WHERE user_id = ? AND revoked_at IS NULL
       AND EXISTS (
         SELECT 1 FROM users
         WHERE users.id = ?
           AND (
             users.status != 'active'
             OR (users.expires_at IS NOT NULL AND users.expires_at <= ?)
             OR (users.quota_bytes IS NOT NULL AND users.usage_bytes >= users.quota_bytes)
           )
       )`,
  ).bind(t, userId, userId, t).run();
  if (processNow && tailscaleEnrollmentEnabled(e)) await processRevocations(e);
}

async function enforceAll(e: Env) {
  const t = now();
  const q = await e.DB.prepare(
    "SELECT id FROM users WHERE status != 'active' OR (expires_at IS NOT NULL AND expires_at <= ?) OR (quota_bytes IS NOT NULL AND usage_bytes >= quota_bytes)",
  ).bind(t).all<Row>();
  for (const u of q.results) {
    try {
      await enforceUser(e, u.id, false);
    } catch (x) {
      console.error('user enforcement failed', u.id, x instanceof Error ? x.message : String(x));
    }
  }
  // Also expire any globally-stale pending devices (revocation outbox when management id present)
  const stale = await e.DB.prepare(
    "SELECT DISTINCT user_id FROM devices WHERE status = 'pending' AND pending_expires_at <= ?",
  ).bind(t).all<Row>();
  for (const row of stale.results) {
    try {
      await expirePending(e, row.user_id);
    } catch (x) {
      console.error('expirePending failed', row.user_id, x instanceof Error ? x.message : String(x));
    }
  }
  const rateWindow = envInt(e, 'RATE_LIMIT_WINDOW_SECONDS', 900);
  // Diagnostics counters run on a day-long window, so pruning at twice the auth
  // window would silently reset the per-day cap every five minutes.
  const rateRetention = Math.max(rateWindow, DIAGNOSTICS_DAY_SECONDS) * 2;
  await e.DB.prepare('DELETE FROM rate_limits WHERE window_start <= ?').bind(t - rateRetention).run();
  await e.DB.prepare(
    `DELETE FROM auth_challenges
     WHERE expires_at <= ? OR (consumed_at IS NOT NULL AND consumed_at <= ?)`,
  ).bind(t - 86_400, t - 86_400).run();
  // Diagnostics uploads are troubleshooting artifacts, not account records.
  await e.DB.prepare('DELETE FROM diagnostics_reports WHERE received_at <= ?')
    .bind(t - envInt(e, 'DIAGNOSTICS_RETENTION_SECONDS', DIAGNOSTICS_RETENTION_DEFAULT_SECONDS))
    .run();
  if (tailscaleEnrollmentEnabled(e)) {
    try {
      await cleanupOrphanPendingNodes(e);
    } catch (x) {
      console.error('cleanupOrphanPendingNodes failed', x instanceof Error ? x.message : String(x));
    }
    await processRevocations(e);
  }
}

async function issueEnrollment(e: Env, d: Row) {
  if (!tailscaleEnrollmentEnabled(e)) {
    throw new ApiError(410, 'TAILSCALE_DISABLED', 'Tailscale enrollment is temporarily disabled');
  }
  const t = now();
  if (d.claim_token && Number(d.claim_expires_at ?? 0) > t) {
    throw new ApiError(429, 'ENROLLMENT_COOLDOWN', 'Wait before requesting another enrollment key');
  }
  const unfinishedRevocation = await e.DB.prepare(
    `SELECT 1
     FROM revocation_jobs
     WHERE device_id = ? AND completed_at IS NULL
     LIMIT 1`,
  ).bind(d.id).first<Row>();
  if (unfinishedRevocation) {
    throw new ApiError(
      409,
      'REVOCATION_PENDING',
      'Wait for the prior tailnet identity to be revoked before enrolling again',
    );
  }
  if (d.enrollment_issued_at && t - d.enrollment_issued_at < 60) {
    throw new ApiError(429, 'ENROLLMENT_COOLDOWN', 'Wait before requesting another enrollment key');
  }
  const enrollmentHostname = `tono-${id().replaceAll('-', '')}`;
  const claim = await e.DB.prepare(
    `UPDATE devices SET enrollment_issued_at = ?, enrollment_hostname = ?, updated_at = ?
     WHERE id = ? AND status = 'pending' AND pending_expires_at > ?
       AND (claim_token IS NULL OR claim_expires_at <= ?)
       AND (enrollment_issued_at IS NULL OR enrollment_issued_at <= ?)
       AND NOT EXISTS (
         SELECT 1
         FROM revocation_jobs
         WHERE device_id = devices.id AND completed_at IS NULL
       )`,
  ).bind(t, enrollmentHostname, t, d.id, t, t, t - 60).run();
  if (!claim.meta.changes) {
    const racedRevocation = await e.DB.prepare(
      `SELECT 1
       FROM revocation_jobs
       WHERE device_id = ? AND completed_at IS NULL
       LIMIT 1`,
    ).bind(d.id).first<Row>();
    if (racedRevocation) {
      throw new ApiError(
        409,
        'REVOCATION_PENDING',
        'Wait for the prior tailnet identity to be revoked before enrolling again',
      );
    }
    throw new ApiError(429, 'ENROLLMENT_COOLDOWN', 'Wait before requesting another enrollment key');
  }
  try {
    const r = await tailscale(e, `/tailnet/${encodeURIComponent(e.TAILSCALE_TAILNET)}/keys`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        capabilities: {
          devices: {
            create: {
              reusable: false,
              ephemeral: true,
              preauthorized: true,
              tags: ['tag:pending-tunnel-client'],
            },
          },
        },
        expirySeconds: 600,
        description: `tono-device-${d.id}`,
      }),
    });
    const x = await r.json() as Row;
    const authKey = str(x.key, 'tailscaleAuthKey', 1, 1000);
    const expiresAt = str(x.expires, 'tailscaleKeyExpiry', 1, 100);
    return { id: d.id, authKey, hostname: enrollmentHostname, expiresAt, state: 'pending' };
  } catch (x) {
    // Release only this issuance lease. A transient Tailscale failure must not
    // make every subsequent authentication attempt fail with the local
    // 60-second cooldown.
    await e.DB.prepare(
      `UPDATE devices SET enrollment_issued_at = NULL, enrollment_hostname = NULL, updated_at = ?
       WHERE id = ? AND status = 'pending' AND enrollment_issued_at = ?
         AND enrollment_hostname = ?`,
    ).bind(now(), d.id, t, enrollmentHostname).run();
    throw x;
  }
}

// --- Confirm state machine ----------------------------------------------------

async function confirmDevice(
  e: Env,
  a: { userId: string; deviceId?: string; installationId?: string },
  deviceRowId: string,
  b: Row,
) {
  if (!tailscaleEnrollmentEnabled(e)) {
    throw new ApiError(410, 'TAILSCALE_DISABLED', 'Tailscale enrollment is temporarily disabled');
  }
  const stableNodeId = str(b.stableNodeId, 'stableNodeId', 1, 200);
  const nodeId = b.nodeId !== undefined && b.nodeId !== null ? str(b.nodeId, 'nodeId', 1, 200) : undefined;
  const publicKey = str(b.publicKey, 'publicKey', 1, 500);
  const ips = b.tailscaleIPs;
  if (!Array.isArray(ips) || ips.length < 1 || ips.length > 10 || ips.some((x) => typeof x !== 'string' || x.length > 64)) {
    throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid tailscaleIPs');
  }
  const ipsList = ips as string[];

  // 1) Atomic claim. Each successful claim advances a durable ownership
  // generation so stale requests and stale deletion jobs can be fenced.
  const claimToken = randomToken(16);
  const t = now();
  const claimTTL = envInt(e, 'CONFIRM_CLAIM_TTL_SECONDS', 300);
  const claim = await e.DB.prepare(
    `UPDATE devices SET
       claim_token = ?,
       claim_expires_at = ?,
       claim_generation = claim_generation + 1,
       tailscale_node_id = NULL,
       tailscale_stable_id = NULL,
       tailscale_api_node_id = NULL,
       tailscale_public_key = NULL,
       tailscale_ips = NULL,
       updated_at = ?
     WHERE id = ? AND user_id = ? AND installation_id = ?
       AND status = 'pending' AND pending_expires_at > ?
       AND (claim_token IS NULL OR claim_expires_at <= ?)`,
  ).bind(
    claimToken,
    t + claimTTL,
    t,
    deviceRowId,
    a.userId,
    a.installationId,
    t,
    t,
  ).run();
  if (!claim.meta.changes) {
    throw new ApiError(409, 'DEVICE_STATE_CHANGED', 'Device is already being confirmed or is not pending');
  }
  const claimed = await e.DB.prepare(
    `SELECT claim_generation, enrollment_hostname FROM devices
     WHERE id = ? AND claim_token = ? AND status = 'pending'`,
  ).bind(deviceRowId, claimToken).first<Row>();
  if (
    !claimed ||
    typeof claimed.enrollment_hostname !== 'string' ||
    !/^tono-[a-f0-9]{32}$/.test(claimed.enrollment_hostname)
  ) {
    await clearClaim(e, deviceRowId, claimToken, Number(claimed?.claim_generation ?? -1));
    throw new ApiError(409, 'DEVICE_STATE_CHANGED', 'Device claim was lost');
  }
  const claimGeneration = Number(claimed.claim_generation);

  // 2) Resolve management id from inventory (list, never GET by client id)
  let resolved: ResolvedTailscaleDevice;
  try {
    resolved = await resolveFromInventory(e, {
      stableNodeId,
      nodeId,
      publicKey,
      ips: ipsList,
      enrollmentHostname: claimed.enrollment_hostname,
    });
  } catch (err) {
    await clearClaim(e, deviceRowId, claimToken, claimGeneration);
    throw err;
  }

  // 3) Store identity columns under the claim (management id in tailscale_node_id)
  try {
    const storeAt = now();
    const store = await e.DB.prepare(
      `UPDATE devices SET
         tailscale_node_id = ?,
         tailscale_stable_id = ?,
         tailscale_api_node_id = ?,
         tailscale_public_key = ?,
         tailscale_ips = ?,
         updated_at = ?
       WHERE id = ? AND claim_token = ? AND claim_generation = ?
         AND status = 'pending' AND pending_expires_at > ?
         AND claim_expires_at > ?
         AND NOT EXISTS (
           SELECT 1 FROM revocation_jobs
           WHERE tailscale_node_id = ? AND completed_at IS NULL
         )`,
    ).bind(
      resolved.managementId,
      stableNodeId,
      resolved.apiNodeId ?? nodeId ?? null,
      resolved.publicKey ?? normalizedNodeKey(publicKey) ?? null,
      JSON.stringify(ipsList),
      storeAt,
      deviceRowId,
      claimToken,
      claimGeneration,
      storeAt,
      storeAt,
      resolved.managementId,
    ).run();
    if (!store.meta.changes) {
      await clearClaim(e, deviceRowId, claimToken, claimGeneration);
      throw new ApiError(409, 'DEVICE_STATE_CHANGED', 'Device state changed during confirm');
    }
  } catch (err) {
    if (err instanceof ApiError) throw err;
    // Unique constraint: another device already owns this management or stable id
    await clearClaim(e, deviceRowId, claimToken, claimGeneration);
    throw new ApiError(409, 'NODE_ALREADY_CLAIMED', 'Tailscale node is already bound to another device');
  }

  // 4) Persist a deletion guard BEFORE the irreversible external promotion.
  // The guard is completed atomically with D1 activation. If activation throws,
  // cron still owns a durable cleanup record.
  const guardAt = now();
  const [renewed, guard] = await e.DB.batch([
    e.DB.prepare(
      `UPDATE devices SET claim_expires_at = ?, updated_at = ?
       WHERE id = ? AND claim_token = ? AND claim_generation = ?
         AND status = 'pending' AND pending_expires_at > ?
         AND claim_expires_at > ? AND tailscale_node_id = ?`,
    ).bind(
      guardAt + claimTTL,
      guardAt,
      deviceRowId,
      claimToken,
      claimGeneration,
      guardAt,
      guardAt,
      resolved.managementId,
    ),
    e.DB.prepare(
      `INSERT INTO revocation_jobs(
         id, device_id, tailscale_node_id, created_at, ownership_generation, reason
       )
       SELECT ?, id, tailscale_node_id, ?, claim_generation, 'confirm_guard'
       FROM devices
       WHERE id = ? AND claim_token = ? AND claim_generation = ?
         AND status = 'pending' AND pending_expires_at > ?
         AND claim_expires_at > ? AND tailscale_node_id = ?
       ON CONFLICT(tailscale_node_id) DO UPDATE SET
         completed_at = NULL,
         last_error = NULL,
         device_id = excluded.device_id,
         created_at = excluded.created_at,
         ownership_generation = excluded.ownership_generation,
         reason = excluded.reason`,
    ).bind(
      id(),
      guardAt,
      deviceRowId,
      claimToken,
      claimGeneration,
      guardAt,
      guardAt,
      resolved.managementId,
    ),
  ]);
  if (!renewed.meta.changes || !guard.meta.changes) {
    await compensateConfirmFailure(e, deviceRowId, claimToken, claimGeneration);
    throw new ApiError(409, 'DEVICE_STATE_CHANGED', 'Device claim expired before promotion');
  }

  // 5) Promote tags using the server-authoritative management id only.
  try {
    const tagRes = await tailscale(e, `/device/${encodeURIComponent(resolved.managementId)}/tags`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tags: ['tag:tunnel-client'] }),
    });
    await tagRes.body?.cancel();
    if (!tagRes.ok) throw new ApiError(502, 'TAILSCALE_ERROR', 'Failed to promote Tailscale device tags');
  } catch (err) {
    await compensateConfirmFailure(e, deviceRowId, claimToken, claimGeneration);
    throw err instanceof ApiError ? err : new ApiError(502, 'TAILSCALE_ERROR', 'Failed to promote Tailscale device tags');
  }

  // 6) Activate and retire the guard in one D1 transaction. Both pending and
  // claim leases are checked again after the external API call.
  let activate: D1Result;
  try {
    const activatedAt = now();
    [activate] = await e.DB.batch([
      e.DB.prepare(
        `UPDATE devices SET
           status = 'active',
           pending_expires_at = NULL,
           confirmed_at = ?,
           last_seen_at = ?,
           claim_token = NULL,
           claim_expires_at = NULL,
           updated_at = ?
         WHERE id = ? AND claim_token = ? AND claim_generation = ?
           AND status = 'pending' AND pending_expires_at > ?
           AND claim_expires_at > ? AND tailscale_node_id = ?`,
      ).bind(
        activatedAt,
        activatedAt,
        activatedAt,
        deviceRowId,
        claimToken,
        claimGeneration,
        activatedAt,
        activatedAt,
        resolved.managementId,
      ),
      e.DB.prepare(
        `UPDATE revocation_jobs SET completed_at = ?, last_error = NULL
         WHERE tailscale_node_id = ? AND device_id = ?
           AND ownership_generation = ? AND completed_at IS NULL
           AND EXISTS (
             SELECT 1 FROM devices
             WHERE id = ? AND status = 'active' AND claim_generation = ?
               AND tailscale_node_id = ?
           )`,
      ).bind(
        activatedAt,
        resolved.managementId,
        deviceRowId,
        claimGeneration,
        deviceRowId,
        claimGeneration,
        resolved.managementId,
      ),
    ]);
  } catch {
    // The pre-promotion guard remains durable even if D1 is temporarily
    // unavailable here.
    try {
      await compensateConfirmFailure(e, deviceRowId, claimToken, claimGeneration);
    } catch {
      // Scheduled processing will retry the already-persisted guard.
    }
    throw new ApiError(503, 'CONFIRM_ACTIVATION_FAILED', 'Device activation could not be committed');
  }

  if (!activate.meta.changes) {
    await compensateConfirmFailure(e, deviceRowId, claimToken, claimGeneration);
    throw new ApiError(409, 'DEVICE_STATE_CHANGED', 'Device state changed');
  }

  const d = (await e.DB.prepare('SELECT * FROM devices WHERE id = ?').bind(deviceRowId).first<Row>())!;
  return publicDevice(d, a.deviceId);
}

// --- Router -------------------------------------------------------------------

async function route(req: Request, e: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  const p = url.pathname;
  const m = req.method;

  if (p === '/api/v1/health' && m === 'GET') {
    return Response.json({ ok: true, version: '0.0.1' });
  }

  if (p === '/api/v1/auth/methods' && m === 'GET') {
    const appleAudience = providerAudience(e, 'apple');
    const googleAudience = providerAudience(e, 'google');
    return Response.json({
      email: { enabled: emailDeliveryConfigured(e) },
      apple: { enabled: appleAudience !== undefined },
      google: {
        enabled: googleAudience !== undefined,
        ...(googleAudience ? { clientId: googleAudience } : {}),
      },
    });
  }

  if (p === '/api/v1/auth/email/start' && m === 'POST') {
    const b = await body(req, 16 * 1024);
    const submittedEmail = email(b.email);
    const name = str(b.deviceName, 'deviceName', 1, 100);
    const inst = str(b.installationId, 'installationId', 8, 200);
    if (!emailDeliveryConfigured(e)) {
      throw new ApiError(503, 'EMAIL_AUTH_UNAVAILABLE', 'Email sign-in is not configured');
    }
    await rateLimitEmailStart(e, req, submittedEmail);

    const existing = await e.DB.prepare('SELECT * FROM users WHERE email = ?')
      .bind(submittedEmail).first<Row>();
    // A verified mailbox is sufficient to create a test-stage account.
    // Disabled existing users remain ineligible and receive the same public
    // response shape as every other request.
    const eligible = existing
      ? !ineligible(existing)
      : await directSignupAllowed(e, submittedEmail);

    const challenge = id();
    const code = numericCode();
    const t = now();
    const ttl = envInt(e, 'EMAIL_CODE_TTL_SECONDS', 600);
    await e.DB.prepare(
      `INSERT INTO auth_challenges(
         id, kind, email, secret_hash, invitation_id, installation_id,
         device_name, attempts, max_attempts, expires_at, created_at
       ) VALUES(?, 'email_otp', ?, ?, ?, ?, ?, 0, 5, ?, ?)`,
    ).bind(
      challenge,
      submittedEmail,
      await challengeSecret(e, challenge, code),
      null,
      inst,
      name,
      t + ttl,
      t,
    ).run();

    if (eligible) {
      // Decouple provider latency from the public response so response timing
      // does not disclose whether an existing account was eligible.
      ctx.waitUntil((async () => {
        try {
          const delivered = await deliverEmailCode(e, submittedEmail, code, challenge, ttl);
          if (!delivered) {
            // Do not leave an undelivered code usable.
            await e.DB.prepare(
              'UPDATE auth_challenges SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL',
            ).bind(now(), challenge).run();
          }
        } catch (deliveryStateError) {
          console.error(
            'email delivery state update failed',
            deliveryStateError instanceof Error
              ? deliveryStateError.message
              : String(deliveryStateError),
          );
        }
      })());
    }
    return Response.json(
      {
        challengeId: challenge,
        expiresIn: ttl,
        message: 'If this email is eligible, a sign-in code has been sent.',
      },
      { status: 202 },
    );
  }

  if (p === '/api/v1/auth/email/verify' && m === 'POST') {
    const b = await body(req, 4 * 1024);
    const challenge = challengeID(b.challengeId);
    const code = str(b.code, 'code', 6, 6);
    if (!/^\d{6}$/.test(code)) throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid code');
    await rateLimitChallenge(e, req, 'email-verify', challenge);
    const t = now();
    const claimed = await e.DB.prepare(
      `UPDATE auth_challenges
       SET attempts = attempts + 1,
           consumed_at = CASE WHEN secret_hash = ? THEN ? ELSE consumed_at END
       WHERE id = ? AND kind = 'email_otp' AND consumed_at IS NULL
         AND expires_at > ? AND attempts < max_attempts
       RETURNING *`,
    ).bind(await challengeSecret(e, challenge, code), t, challenge, t).first<Row>();
    if (!claimed || claimed.consumed_at !== t) {
      throw new ApiError(401, 'INVALID_OR_EXPIRED_CODE', 'The sign-in code is invalid or expired');
    }
    const user = await accountForVerifiedEmail(
      e,
      String(claimed.email).toLowerCase(),
    );
    return Response.json(await completePasswordlessAuth(
      e,
      user,
      String(claimed.device_name),
      String(claimed.installation_id),
    ));
  }

  if (p === '/api/v1/auth/oidc/challenge' && m === 'POST') {
    const b = await body(req, 8 * 1024);
    const provider = oidcProvider(b.provider);
    const name = str(b.deviceName, 'deviceName', 1, 100);
    const inst = str(b.installationId, 'installationId', 8, 200);
    const audience = providerAudience(e, provider);
    if (!audience) {
      throw new ApiError(503, 'PROVIDER_UNAVAILABLE', 'This identity provider is not configured');
    }
    await rateLimitOidcStart(e, req, inst);
    const challenge = id();
    const nonce = randomToken(32);
    const t = now();
    const ttl = envInt(e, 'OIDC_CHALLENGE_TTL_SECONDS', 300);
    await e.DB.prepare(
      `INSERT INTO auth_challenges(
         id, kind, secret_hash, invitation_id, installation_id, device_name,
         attempts, max_attempts, expires_at, created_at
       ) VALUES(?, ?, ?, ?, ?, ?, 0, 3, ?, ?)`,
    ).bind(
      challenge,
      provider,
      await sha256(nonce),
      null,
      inst,
      name,
      t + ttl,
      t,
    ).run();
    return Response.json({
      challengeId: challenge,
      nonce,
      expiresIn: ttl,
      audience,
    });
  }

  if (p === '/api/v1/auth/oidc/verify' && m === 'POST') {
    const b = await body(req, 24 * 1024);
    const provider = oidcProvider(b.provider);
    const challenge = challengeID(b.challengeId);
    const idToken = str(b.idToken, 'idToken', 100, 16_384);
    const audience = providerAudience(e, provider);
    if (!audience) {
      throw new ApiError(503, 'PROVIDER_UNAVAILABLE', 'This identity provider is not configured');
    }
    await rateLimitChallenge(e, req, 'oidc-verify', challenge);
    const t = now();
    const pending = await e.DB.prepare(
      `SELECT * FROM auth_challenges
       WHERE id = ? AND kind = ? AND consumed_at IS NULL
         AND expires_at > ? AND attempts < max_attempts`,
    ).bind(challenge, provider, t).first<Row>();
    if (!pending) {
      throw new ApiError(401, 'OIDC_AUTHENTICATION_FAILED', 'Identity verification failed');
    }

    let identity: Awaited<ReturnType<typeof verifyOidcIdToken>>;
    try {
      identity = await verifyOidcIdToken(provider, idToken, audience, t);
    } catch (verificationError) {
      if (
        verificationError instanceof OidcVerificationError &&
        verificationError.temporary
      ) {
        throw new ApiError(
          503,
          'IDENTITY_PROVIDER_UNAVAILABLE',
          'The identity provider is temporarily unavailable',
        );
      }
      await recordChallengeFailure(e, challenge, provider);
      throw new ApiError(401, 'OIDC_AUTHENTICATION_FAILED', 'Identity verification failed');
    }
    const nonceHash = await sha256(identity.nonce);
    if (nonceHash !== pending.secret_hash) {
      await recordChallengeFailure(e, challenge, provider);
      throw new ApiError(401, 'OIDC_AUTHENTICATION_FAILED', 'Identity verification failed');
    }
    const consumed = await e.DB.prepare(
      `UPDATE auth_challenges
       SET attempts = attempts + 1, consumed_at = ?
       WHERE id = ? AND kind = ? AND secret_hash = ?
         AND consumed_at IS NULL AND expires_at > ? AND attempts < max_attempts`,
    ).bind(t, challenge, provider, nonceHash, t).run();
    if (!consumed.meta.changes) {
      throw new ApiError(401, 'OIDC_AUTHENTICATION_FAILED', 'Identity verification failed');
    }
    const user = await accountForOidcIdentity(e, identity);
    return Response.json(await completePasswordlessAuth(
      e,
      user,
      String(pending.device_name),
      String(pending.installation_id),
    ));
  }

  if (
    (p === '/api/v1/auth/redeem' || p === '/api/v1/auth/login') &&
    m === 'POST'
  ) {
    throw new ApiError(
      410,
      'PASSWORD_AUTH_DISABLED',
      'Password sign-in has been replaced by email, Apple, or Google sign-in',
    );
  }

  if (p === '/api/v1/auth/refresh' && m === 'POST') {
    const b = await body(req, 4 * 1024);
    const raw = str(b.refreshToken, 'refreshToken', 20, 500);
    const t = now();
    const s = await e.DB.prepare(
      `SELECT sessions.*, users.status user_status, users.quota_bytes, users.usage_bytes, users.expires_at user_expires_at,
              devices.installation_id, devices.status device_status, devices.pending_expires_at
       FROM sessions
       JOIN users ON users.id = sessions.user_id
       JOIN devices ON devices.id = sessions.device_id
       WHERE refresh_hash = ? AND revoked_at IS NULL AND sessions.expires_at > ?`,
    ).bind(await sha256(raw), t).first<Row>();
    if (
      !s ||
      s.user_status !== 'active' ||
      !['active', 'pending'].includes(s.device_status) ||
      (s.device_status === 'pending' && s.pending_expires_at <= t) ||
      (s.user_expires_at !== null && s.user_expires_at <= t) ||
      (s.quota_bytes !== null && s.usage_bytes >= s.quota_bytes)
    ) {
      throw new ApiError(401, 'INVALID_REFRESH_TOKEN', 'Invalid or expired refresh token');
    }
    const rotated = await e.DB.prepare(
      'UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL',
    ).bind(t, s.id).run();
    if (!rotated.meta.changes) throw new ApiError(401, 'INVALID_REFRESH_TOKEN', 'Refresh token was already used');
    return Response.json(await tokens(e, s.user_id, s.device_id, s.installation_id));
  }

  if (p === '/api/v1/auth/logout' && m === 'POST') {
    const a = await auth(req, e);
    const b: Row = await body(req, 4 * 1024).catch(() => ({} as Row));
    const raw = b.refreshToken;
    const t = now();
    const statements = [
      e.DB.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ? AND user_id = ?').bind(t, a.sessionId, a.userId),
    ];
    if (raw !== undefined) {
      str(raw, 'refreshToken', 20, 500);
      statements.push(
        e.DB.prepare(
          'UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND refresh_hash = ? AND revoked_at IS NULL',
        ).bind(t, a.userId, await sha256(raw)),
      );
    }
    await e.DB.batch(statements);
    return new Response(null, { status: 204 });
  }

  if (p === '/api/v1/me' && m === 'GET') {
    const uid = await userId(req, e);
    const u = await e.DB.prepare('SELECT * FROM users WHERE id = ?').bind(uid).first<Row>();
    if (!u) throw new ApiError(404, 'NOT_FOUND', 'User not found');
    return Response.json({ user: publicUser(u) });
  }

  if (p === '/api/v1/exit-catalog' && m === 'GET') {
    await auth(req, e);
    return Response.json(await publicManagedCatalog(e));
  }

  if (p === '/api/v1/traffic-policy' && m === 'GET') {
    await auth(req, e);
    return Response.json(await publicTrafficPolicy(e));
  }

  if (p === '/api/v1/device-actions' && m === 'GET') {
    const a = await auth(req, e);
    const t = now();
    await e.DB.prepare("UPDATE device_actions SET status = 'expired' WHERE device_id = ? AND status IN ('pending','delivered') AND expires_at <= ?")
      .bind(a.deviceId, t).run();
    const q = await e.DB.prepare(
      "SELECT * FROM device_actions WHERE device_id = ? AND status IN ('pending','delivered') AND expires_at > ? ORDER BY created_at LIMIT 20",
    ).bind(a.deviceId, t).all<Row>();
    const pending = q.results.filter((x) => x.status === 'pending');
    if (pending.length) {
      await e.DB.prepare(
        `UPDATE device_actions SET status = 'delivered', delivered_at = ?
         WHERE device_id = ? AND status = 'pending' AND expires_at > ?`,
      ).bind(t, a.deviceId, t).run();
    }
    return Response.json({ actions: q.results.map((x) => publicAction({ ...x, status: 'delivered', delivered_at: x.delivered_at ?? t })) });
  }

  const actionResultMatch = p.match(/^\/api\/v1\/device-actions\/([^/]+)\/result$/);
  if (actionResultMatch && m === 'POST') {
    const a = await auth(req, e);
    const b = await body(req, 8 * 1024);
    const canonical = canonicalActionResult(b);
    const t = now();
    await e.DB.prepare("UPDATE device_actions SET status = 'expired' WHERE id = ? AND device_id = ? AND status IN ('pending','delivered') AND expires_at <= ?")
      .bind(actionResultMatch[1], a.deviceId, t).run();
    const existing = await e.DB.prepare('SELECT * FROM device_actions WHERE id = ?').bind(actionResultMatch[1]).first<Row>();
    if (!existing || existing.device_id !== a.deviceId) throw new ApiError(404, 'NOT_FOUND', 'Action not found');
    if (['succeeded', 'failed'].includes(existing.status)) {
      if (existing.status === canonical.result.outcome && existing.result_json === canonical.json) return Response.json({ action: publicAction(existing) });
      throw new ApiError(409, 'ACTION_RESULT_CONFLICT', 'Action already has a different result');
    }
    if (existing.status !== 'delivered') throw new ApiError(409, 'ACTION_NOT_DELIVERED', 'Action is not available for completion');
    const changed = await e.DB.prepare(
      `UPDATE device_actions SET status = ?, completed_at = ?, result_json = ?
       WHERE id = ? AND device_id = ? AND status = 'delivered' AND expires_at > ?`,
    ).bind(canonical.result.outcome, t, canonical.json, actionResultMatch[1], a.deviceId, t).run();
    if (!changed.meta.changes) throw new ApiError(409, 'ACTION_STATE_CHANGED', 'Action state changed');
    const row = await e.DB.prepare('SELECT * FROM device_actions WHERE id = ?').bind(actionResultMatch[1]).first<Row>();
    return Response.json({ action: publicAction(row!) });
  }

  // User-initiated only: there is no silent reporting path, and the normal
  // access token is required so every stored report has an owner (and inherits
  // account rate limiting). An unauthenticated fallback for "auth itself is
  // broken" is deliberately not offered: a token this endpoint would accept is
  // a token the client can also spend on /auth/refresh over the same recovery
  // channel, and an anonymous write endpoint on a VPN control plane is a worse
  // trade than losing reports from an unauthenticatable client.
  if (p === '/api/v1/diagnostics/reports' && m === 'POST') {
    const a = await auth(req, e);
    const b = await body(req, DIAGNOSTICS_BODY_MAX_BYTES);
    // The client sends `{report}` and nothing else; the version columns are
    // lifted out of the report rather than repeated at the top level.
    rejectUnexpectedKeys(b, ['report']);
    const { json: reportJson, appVersion, osVersion } = canonicalDiagnosticsReport(b.report);
    await rateLimitDiagnostics(e, req, a.userId);
    // The reference code (plus the display-only receipt time) is the entire
    // response; the payload is never echoed.
    return Response.json(
      await storeDiagnosticsReport(e, a.userId, appVersion, osVersion, reportJson),
      { status: 201 },
    );
  }

  if (p === '/api/v1/devices' && m === 'GET') {
    const a = await auth(req, e);
    await expirePending(e, a.userId);
    const q = await e.DB.prepare('SELECT * FROM devices WHERE user_id = ? ORDER BY created_at DESC').bind(a.userId).all<Row>();
    return Response.json({ devices: q.results.map((x) => publicDevice(x, a.deviceId)) });
  }

  let mt = p.match(/^\/api\/v1\/devices\/([^/]+)$/);
  if (mt && m === 'DELETE') {
    const uid = await userId(req, e);
    const d = await e.DB.prepare('SELECT * FROM devices WHERE id = ? AND user_id = ?').bind(mt[1], uid).first<Row>();
    if (!d) throw new ApiError(404, 'NOT_FOUND', 'Device not found');
    await revokeDevice(e, d);
    await processRevocations(e);
    return new Response(null, { status: 204 });
  }

  mt = p.match(/^\/api\/v1\/devices\/([^/]+)\/enrollment$/);
  if (mt && m === 'POST') {
    if (!tailscaleEnrollmentEnabled(e)) {
      throw new ApiError(410, 'TAILSCALE_DISABLED', 'Tailscale enrollment is temporarily disabled');
    }
    const a = await auth(req, e);
    if (a.deviceId !== mt[1]) throw new ApiError(404, 'NOT_FOUND', 'Device not found for this session');
    const b = await body(req, 4 * 1024);
    const requestedInstallation = str(b.installationId, 'installationId', 8, 200);
    if (requestedInstallation !== a.installationId) {
      throw new ApiError(404, 'NOT_FOUND', 'Device not found for this installation');
    }
    let d = await e.DB.prepare(
      "SELECT * FROM devices WHERE id = ? AND user_id = ? AND installation_id = ? AND status IN ('pending', 'active')",
    ).bind(mt[1], a.userId, a.installationId).first<Row>();
    if (!d) throw new ApiError(404, 'NOT_FOUND', 'Device not found for this installation');
    if (d.status === 'active') {
      const t = now();
      const generation = Number(d.claim_generation ?? 0);
      const [, r] = await e.DB.batch([
        e.DB.prepare(
          `INSERT INTO revocation_jobs(
             id, device_id, tailscale_node_id, created_at, ownership_generation, reason
           )
           SELECT ?, id, tailscale_node_id, ?, claim_generation, 'identity_reenrollment'
           FROM devices
           WHERE id = ? AND user_id = ? AND installation_id = ?
             AND status = 'active' AND claim_generation = ?
             AND tailscale_node_id IS NOT NULL
           ON CONFLICT(tailscale_node_id) DO UPDATE SET
             completed_at = NULL,
             last_error = NULL,
             device_id = excluded.device_id,
             created_at = excluded.created_at,
             ownership_generation = excluded.ownership_generation,
             reason = excluded.reason`,
        ).bind(id(), t, d.id, a.userId, a.installationId, generation),
        e.DB.prepare(
          `UPDATE devices SET
             status = 'pending',
             tailscale_node_id = NULL,
             tailscale_stable_id = NULL,
             tailscale_api_node_id = NULL,
             tailscale_public_key = NULL,
             tailscale_ips = NULL,
             claim_token = NULL,
             claim_expires_at = NULL,
             claim_generation = claim_generation + 1,
             pending_expires_at = ?,
             enrollment_issued_at = NULL,
             enrollment_hostname = NULL,
             confirmed_at = NULL,
             updated_at = ?
           WHERE id = ? AND user_id = ? AND installation_id = ?
             AND status = 'active' AND claim_generation = ?`,
        ).bind(
          t + envInt(e, 'PENDING_DEVICE_TTL_SECONDS', 1_800),
          t,
          d.id,
          a.userId,
          a.installationId,
          generation,
        ),
      ]);
      if (!r.meta.changes) throw new ApiError(409, 'DEVICE_STATE_CHANGED', 'Device state changed');
      await processRevocations(e);
      d = (await e.DB.prepare('SELECT * FROM devices WHERE id = ?').bind(d.id).first<Row>())!;
    }
    if (d.pending_expires_at <= now()) throw new ApiError(404, 'NOT_FOUND', 'Pending device expired');
    return Response.json({ enrollment: await issueEnrollment(e, d) });
  }

  mt = p.match(/^\/api\/v1\/devices\/([^/]+)\/confirm$/);
  if (mt && m === 'POST') {
    if (!tailscaleEnrollmentEnabled(e)) {
      throw new ApiError(410, 'TAILSCALE_DISABLED', 'Tailscale enrollment is temporarily disabled');
    }
    const a = await auth(req, e);
    const b = await body(req, 16 * 1024);
    const device = await confirmDevice(e, a, mt[1], b);
    return Response.json({ device });
  }

  if (p.startsWith('/api/v1/admin/')) {
    await privileged(req, e.ADMIN_API_TOKEN);
    if (p === '/api/v1/admin/device-actions' && m === 'POST') {
      const b = await body(req, 8 * 1024);
      rejectUnexpectedKeys(b, ['deviceId', 'action', 'ttlSeconds']);
      const deviceId = str(b.deviceId, 'deviceId', 1, 200);
      const action = fixedAction(b.action);
      const ttl = b.ttlSeconds ?? 300;
      if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > 3600) throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid ttlSeconds');
      const device = await e.DB.prepare("SELECT * FROM devices WHERE id = ? AND status != 'revoked'").bind(deviceId).first<Row>();
      if (!device) throw new ApiError(404, 'NOT_FOUND', 'Active device not found');
      const t = now();
      const commandId = id();
      await e.DB.prepare(
        'INSERT INTO device_actions(id,user_id,device_id,action,status,created_at,expires_at) VALUES(?,?,?,?,\'pending\',?,?)',
      ).bind(commandId, device.user_id, device.id, action, t, t + ttl).run();
      const row = await e.DB.prepare('SELECT * FROM device_actions WHERE id = ?').bind(commandId).first<Row>();
      return Response.json({ action: publicAction(row!) }, { status: 201 });
    }
    if (p === '/api/v1/admin/device-actions' && m === 'GET') {
      const t = now();
      await e.DB.prepare("UPDATE device_actions SET status = 'expired' WHERE status IN ('pending','delivered') AND expires_at <= ?").bind(t).run();
      const deviceId = url.searchParams.get('deviceId');
      if (deviceId !== null && (deviceId.length < 1 || deviceId.length > 200)) throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid deviceId');
      const q = deviceId
        ? await e.DB.prepare('SELECT * FROM device_actions WHERE device_id = ? ORDER BY created_at DESC LIMIT 100').bind(deviceId).all<Row>()
        : await e.DB.prepare('SELECT * FROM device_actions ORDER BY created_at DESC LIMIT 100').all<Row>();
      return Response.json({ actions: q.results.map(publicAction) });
    }
    mt = p.match(/^\/api\/v1\/admin\/diagnostics\/reports\/([^/]+)$/);
    if (mt && m === 'GET') {
      const row = await e.DB.prepare(
        'SELECT * FROM diagnostics_reports WHERE reference_code = ?',
      ).bind(normalizedReferenceCode(mt[1])).first<Row>();
      if (!row) throw new ApiError(404, 'NOT_FOUND', 'Diagnostics report not found');
      return Response.json({ report: publicDiagnosticsReport(row) });
    }
    if (p === '/api/v1/admin/traffic-policy' && m === 'GET') {
      return Response.json(await publicTrafficPolicy(e));
    }
    if (p === '/api/v1/admin/traffic-policy' && m === 'PUT') {
      const b = await body(req, 64 * 1024);
      const policy = canonicalTrafficPolicy(b.policy);
      const json = JSON.stringify(policy);
      const expectedRevision = b.expectedRevision;
      if (expectedRevision !== undefined && (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0)) {
        throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid expectedRevision');
      }
      const current = await e.DB.prepare(
        'SELECT revision FROM managed_traffic_policy WHERE singleton_id = 1',
      ).first<Row>();
      const currentRevision = Number(current?.revision ?? 0);
      if (expectedRevision !== undefined && expectedRevision !== currentRevision) {
        throw new ApiError(409, 'TRAFFIC_POLICY_CONFLICT', 'Managed traffic policy changed; reload before replacing it');
      }
      const revision = currentRevision + 1;
      const encrypted = await encryptTrafficPolicy(json, requiredCatalogKey(e));
      const digest = await sha256(json);
      const t = now();
      const changed = current
        ? await e.DB.prepare(
          `UPDATE managed_traffic_policy
           SET revision = ?, ciphertext = ?, nonce = ?, content_sha256 = ?, updated_at = ?
           WHERE singleton_id = 1 AND revision = ?`,
        ).bind(revision, encrypted.ciphertext, encrypted.nonce, digest, t, currentRevision).run()
        : await e.DB.prepare(
          `INSERT OR IGNORE INTO managed_traffic_policy(
             singleton_id, revision, ciphertext, nonce, content_sha256, updated_at
           ) VALUES(1, ?, ?, ?, ?, ?)`,
        ).bind(revision, encrypted.ciphertext, encrypted.nonce, digest, t).run();
      if (!changed.meta.changes) {
        throw new ApiError(409, 'TRAFFIC_POLICY_CONFLICT', 'Managed traffic policy changed; reload before replacing it');
      }
      return Response.json({ revision, json, sha256: digest, updatedAt: t });
    }
    if (p === '/api/v1/admin/exit-catalog' && m === 'GET') {
      return Response.json(await publicManagedCatalog(e));
    }
    if (p === '/api/v1/admin/exit-catalog' && m === 'PUT') {
      const b = await body(req, 2 * 1024 * 1024);
      const yaml = managedCatalogYAML(b.yaml);
      const expectedRevision = b.expectedRevision;
      if (
        expectedRevision !== undefined &&
        (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0)
      ) {
        throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid expectedRevision');
      }
      const current = await e.DB.prepare(
        'SELECT revision FROM managed_exit_catalog WHERE singleton_id = 1',
      ).first<Row>();
      const currentRevision = Number(current?.revision ?? 0);
      if (expectedRevision !== undefined && expectedRevision !== currentRevision) {
        throw new ApiError(409, 'CATALOG_CONFLICT', 'Managed catalog changed; reload before replacing it');
      }
      const revision = currentRevision + 1;
      const encrypted = await encryptCatalog(yaml, requiredCatalogKey(e));
      const digest = await sha256(yaml);
      const t = now();
      let changed: D1Result;
      if (current) {
        changed = await e.DB.prepare(
          `UPDATE managed_exit_catalog
           SET revision = ?, ciphertext = ?, nonce = ?, content_sha256 = ?, updated_at = ?
           WHERE singleton_id = 1 AND revision = ?`,
        ).bind(
          revision,
          encrypted.ciphertext,
          encrypted.nonce,
          digest,
          t,
          currentRevision,
        ).run();
      } else {
        changed = await e.DB.prepare(
          `INSERT OR IGNORE INTO managed_exit_catalog(
             singleton_id, revision, ciphertext, nonce, content_sha256, updated_at
           ) VALUES(1, ?, ?, ?, ?, ?)`,
        ).bind(revision, encrypted.ciphertext, encrypted.nonce, digest, t).run();
      }
      if (!changed.meta.changes) {
        throw new ApiError(409, 'CATALOG_CONFLICT', 'Managed catalog changed; reload before replacing it');
      }
      return Response.json({ revision, sha256: digest, updatedAt: t });
    }
    if (p === '/api/v1/admin/signup-allowlist' && m === 'GET') {
      const q = await e.DB.prepare(
        'SELECT email, created_at FROM signup_allowlist ORDER BY created_at DESC, email ASC',
      ).all<Row>();
      return Response.json({
        entries: q.results.map((entry) => ({
          email: entry.email,
          createdAt: Number(entry.created_at),
        })),
      });
    }
    if (p === '/api/v1/admin/signup-allowlist' && m === 'POST') {
      const b = await body(req, 4 * 1024);
      const address = email(b.email);
      const createdAt = now();
      const inserted = await e.DB.prepare(
        'INSERT OR IGNORE INTO signup_allowlist(email, created_at) VALUES(?, ?)',
      ).bind(address, createdAt).run();
      const entry = await e.DB.prepare(
        'SELECT created_at FROM signup_allowlist WHERE email = ?',
      ).bind(address).first<Row>();
      return Response.json(
        {
          email: address,
          createdAt: Number(entry?.created_at ?? createdAt),
          created: inserted.meta.changes === 1,
        },
        { status: inserted.meta.changes === 1 ? 201 : 200 },
      );
    }
    if (p === '/api/v1/admin/signup-allowlist' && m === 'DELETE') {
      const b = await body(req, 4 * 1024);
      await e.DB.prepare(
        'DELETE FROM signup_allowlist WHERE email = ?',
      ).bind(email(b.email)).run();
      return new Response(null, { status: 204 });
    }
    if (p === '/api/v1/admin/invitations' && m === 'GET') {
      const q = await e.DB.prepare(
        'SELECT id, email, expires_at, redeemed_at, created_at FROM invitations ORDER BY created_at DESC',
      ).all();
      return Response.json({ invitations: q.results });
    }
    if (p === '/api/v1/admin/invitations' && m === 'POST') {
      const b = await body(req, 16 * 1024);
      const code = randomToken(24);
      const t = now();
      const days = Number(b.expiresInDays ?? 7);
      if (!Number.isInteger(days) || days < 1 || days > 90) {
        throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid expiresInDays');
      }
      await e.DB.prepare(
        'INSERT INTO invitations(id, code_hash, email, expires_at, created_at) VALUES(?, ?, ?, ?, ?)',
      ).bind(id(), await sha256(code), email(b.email), t + days * 86400, t).run();
      return Response.json({ inviteCode: code, expiresAt: t + days * 86400 }, { status: 201 });
    }
    mt = p.match(/^\/api\/v1\/admin\/invitations\/([^/]+)$/);
    if (mt && m === 'DELETE') {
      await e.DB.prepare('DELETE FROM invitations WHERE id = ? AND redeemed_at IS NULL').bind(mt[1]).run();
      return new Response(null, { status: 204 });
    }
    if (p === '/api/v1/admin/users' && m === 'GET') {
      const q = await e.DB.prepare('SELECT * FROM users ORDER BY created_at DESC').all<Row>();
      return Response.json({ users: q.results.map(publicUser) });
    }
    mt = p.match(/^\/api\/v1\/admin\/users\/([^/]+)$/);
    if (mt && m === 'PATCH') {
      const b = await body(req, 16 * 1024);
      const status = b.status;
      const quota = b.quotaBytes;
      const deviceLimit = b.deviceLimit;
      if (status !== undefined && !['active', 'disabled'].includes(status)) {
        throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid status');
      }
      if (quota !== undefined && quota !== null && (!Number.isSafeInteger(quota) || quota < 0)) {
        throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid quotaBytes');
      }
      if (
        deviceLimit !== undefined &&
        (!Number.isSafeInteger(deviceLimit) || deviceLimit < 1 || deviceLimit > 25)
      ) {
        throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid deviceLimit');
      }
      if (status === 'active') {
        const residual = await e.DB.prepare(
          `SELECT
             users.status current_status,
             (SELECT COUNT(*) FROM devices
              WHERE user_id = ? AND status IN ('active', 'pending')) live_devices,
             (SELECT COUNT(*) FROM revocation_jobs
              JOIN devices ON devices.id = revocation_jobs.device_id
              WHERE devices.user_id = ? AND revocation_jobs.completed_at IS NULL) pending_jobs
           FROM users WHERE users.id = ?`,
        ).bind(mt[1], mt[1], mt[1]).first<Row>();
        if (!residual) throw new ApiError(404, 'NOT_FOUND', 'User not found');
        if (
          residual.current_status !== 'active' &&
          ((residual.live_devices ?? 0) > 0 || (residual.pending_jobs ?? 0) > 0)
        ) {
          throw new ApiError(409, 'REVOCATION_PENDING', 'Wait for tailnet device revocation before re-enabling this user');
        }
      }
      const updated = await e.DB.prepare(
        `UPDATE users SET
           status = COALESCE(?, status),
           quota_bytes = CASE WHEN ? THEN ? ELSE quota_bytes END,
           device_limit = CASE WHEN ? THEN ? ELSE device_limit END,
           updated_at = ?
         WHERE id = ?`,
      ).bind(
        status ?? null,
        quota !== undefined,
        quota ?? null,
        deviceLimit !== undefined,
        deviceLimit ?? null,
        now(),
        mt[1],
      ).run();
      if (!updated.meta.changes) throw new ApiError(404, 'NOT_FOUND', 'User not found');
      await enforceUser(e, mt[1]);
      return Response.json({ ok: true });
    }
    if (p === '/api/v1/admin/devices' && m === 'GET') {
      const q = await e.DB.prepare(
        'SELECT devices.*, users.email FROM devices JOIN users ON users.id = devices.user_id ORDER BY devices.created_at DESC',
      ).all<Row>();
      return Response.json({
        devices: q.results.map((x) => ({ ...publicDevice(x), userId: x.user_id, email: x.email })),
      });
    }
    mt = p.match(/^\/api\/v1\/admin\/devices\/([^/]+)$/);
    if (mt && m === 'DELETE') {
      const d = await e.DB.prepare('SELECT * FROM devices WHERE id = ?').bind(mt[1]).first<Row>();
      if (!d) throw new ApiError(404, 'NOT_FOUND', 'Device not found');
      await revokeDevice(e, d);
      await processRevocations(e);
      return new Response(null, { status: 204 });
    }
  }

  if (p === '/api/v1/home/inventory' && m === 'GET') {
    await privileged(req, e.HOME_AGENT_TOKEN);
    const rows = await e.DB.prepare(
      `SELECT
         devices.tailscale_stable_id,
         devices.tailscale_public_key,
         devices.user_id,
         devices.status,
         users.usage_bytes
       FROM devices
       JOIN users ON users.id = devices.user_id
       WHERE devices.tailscale_stable_id IS NOT NULL
         AND devices.tailscale_public_key IS NOT NULL
       ORDER BY devices.tailscale_stable_id, devices.created_at
       LIMIT 2001`,
    ).all<Row>();
    if (rows.results.length > 2_000) {
      throw new ApiError(
        503,
        'HOME_INVENTORY_TOO_LARGE',
        'Home inventory requires a paginated agent upgrade',
      );
    }
    return Response.json({
      devices: rows.results.map((row) => ({
        stableNodeId: String(row.tailscale_stable_id),
        // This key was matched against server-side inventory during confirm.
        // Older Device API versions may not expose stableNodeId, so the home
        // agent uses publicKey—not client audit metadata—for attribution.
        publicKey: String(row.tailscale_public_key),
        userId: String(row.user_id),
        status: String(row.status),
        usageBytes: Number(row.usage_bytes),
      })),
    });
  }

  if (p === '/api/v1/home/usage' && m === 'POST') {
    await privileged(req, e.HOME_AGENT_TOKEN);
    const b = await body(req, 512 * 1024);
    const reports = b.reports;
    if (!Array.isArray(reports) || reports.length < 1 || reports.length > 500) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'reports must contain 1-500 items');
    }
    const receivedAt = now();
    const unique = new Map<string, {
      reportId: string;
      userId: string;
      totalBytes: number;
      observedAt: number;
    }>();
    const users = new Set<string>();
    for (const x of reports) {
      if (x === null || typeof x !== 'object' || Array.isArray(x)) {
        throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid usage report');
      }
      const reportId = str(x.reportId, 'reportId', 1, 100);
      const reportUserId = str(x.userId, 'userId', 1, 100);
      if (
        !Number.isSafeInteger(x.totalBytes) ||
        x.totalBytes < 0 ||
        !Number.isSafeInteger(x.observedAt) ||
        x.observedAt < 0 ||
        x.observedAt > receivedAt + 300
      ) {
        throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid usage report');
      }
      const normalized = {
        reportId,
        userId: reportUserId,
        totalBytes: x.totalBytes as number,
        observedAt: x.observedAt as number,
      };
      const prior = unique.get(reportId);
      if (prior && JSON.stringify(prior) !== JSON.stringify(normalized)) {
        throw new ApiError(400, 'VALIDATION_ERROR', 'Conflicting duplicate reportId');
      }
      unique.set(reportId, normalized);
      users.add(reportUserId);
    }
    if (users.size > 100) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'A batch may contain at most 100 distinct users');
    }

    const encodedReports = JSON.stringify([...unique.values()]);
    const unknownUser = await e.DB.prepare(
      `WITH input AS (
         SELECT json_extract(value, '$.userId') AS user_id
         FROM json_each(?)
       )
       SELECT input.user_id
       FROM input LEFT JOIN users ON users.id = input.user_id
       WHERE users.id IS NULL
       LIMIT 1`,
    ).bind(encodedReports).first<Row>();
    if (unknownUser) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Usage report references an unknown user');
    }

    try {
      await e.DB.batch([
        e.DB.prepare(
        `WITH input AS (
           SELECT
             json_extract(value, '$.reportId') AS report_id,
             json_extract(value, '$.userId') AS user_id,
             CAST(json_extract(value, '$.totalBytes') AS INTEGER) AS total_bytes,
             CAST(json_extract(value, '$.observedAt') AS INTEGER) AS observed_at
           FROM json_each(?)
         )
         INSERT OR IGNORE INTO usage_reports(
           report_id, user_id, total_bytes, observed_at, created_at
         )
         SELECT report_id, user_id, total_bytes, observed_at, ?
         FROM input`,
        ).bind(encodedReports, receivedAt),
        e.DB.prepare(
        `WITH input AS (
           SELECT
             json_extract(value, '$.reportId') AS report_id,
             json_extract(value, '$.userId') AS user_id,
             CAST(json_extract(value, '$.totalBytes') AS INTEGER) AS total_bytes,
             CAST(json_extract(value, '$.observedAt') AS INTEGER) AS observed_at
           FROM json_each(?)
         ),
         accepted AS (
           SELECT input.user_id, MAX(input.total_bytes) AS total_bytes
           FROM input
           JOIN usage_reports
             ON usage_reports.report_id = input.report_id
            AND usage_reports.user_id = input.user_id
            AND usage_reports.total_bytes = input.total_bytes
            AND usage_reports.observed_at = input.observed_at
           GROUP BY input.user_id
         )
         UPDATE users
         SET usage_bytes = MAX(
               usage_bytes,
               (SELECT accepted.total_bytes FROM accepted WHERE accepted.user_id = users.id)
             ),
             updated_at = ?
         WHERE id IN (SELECT user_id FROM accepted)`,
        ).bind(encodedReports, receivedAt),
      ]);
    } catch (x) {
      if (String(x).includes('USAGE_REPORT_CONFLICT')) {
        throw new ApiError(409, 'USAGE_REPORT_CONFLICT', 'reportId was already used with different content');
      }
      throw x;
    }

    const ineligibleUsers = await e.DB.prepare(
      `WITH input AS (
         SELECT DISTINCT json_extract(value, '$.userId') AS user_id
         FROM json_each(?)
       )
       SELECT users.id
       FROM users JOIN input ON input.user_id = users.id
       WHERE users.status != 'active'
          OR (users.expires_at IS NOT NULL AND users.expires_at <= ?)
          OR (users.quota_bytes IS NOT NULL AND users.usage_bytes >= users.quota_bytes)`,
    ).bind(encodedReports, receivedAt).all<Row>();
    for (const user of ineligibleUsers.results) {
      await enforceUser(e, user.id, false);
    }
    if (ineligibleUsers.results.length > 0) await processRevocations(e);
    return Response.json({ accepted: reports.length, uniqueReports: unique.size });
  }

  throw new ApiError(404, 'NOT_FOUND', 'Route not found');
}

export default {
  async fetch(req: Request, e: Env, ctx: ExecutionContext) {
    const origin = req.headers.get('origin');
    const url = new URL(req.url);
    const path = url.pathname;
    const isReleaseHost = url.hostname.toLowerCase() === 'releases.afk.ccwu.cc';
    const secure = (r: Response, includeCors = true) => {
      const h = new Headers(r.headers);
      h.set('content-security-policy', "default-src 'self'; base-uri 'none'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'none'; object-src 'none'; script-src 'self'; style-src 'self'");
      h.set('permissions-policy', 'camera=(), geolocation=(), microphone=()');
      h.set('referrer-policy', 'no-referrer');
      h.set('x-content-type-options', 'nosniff');
      h.set('x-frame-options', 'DENY');
      if (path.startsWith('/api/') || path === '/' || path.endsWith('.html')) {
        h.set('cache-control', 'no-store');
      }
      if (includeCors && origin) {
        h.set('access-control-allow-origin', origin);
        h.append('vary', 'Origin');
      }
      return new Response(r.body, { status: r.status, statusText: r.statusText, headers: h });
    };
    if (isReleaseHost) {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        return secure(new Response('Method not allowed', {
          status: 405,
          headers: { allow: 'GET, HEAD' },
        }), false);
      }
      const assetPath = new Map([
        ['/', '/releases/'],
        ['/index.html', '/releases/'],
        ['/releases', '/releases/'],
        ['/releases/', '/releases/'],
        ['/style.css', '/releases/style.css'],
        ['/manifest.json', '/releases/manifest.json'],
        ['/appcast.xml', '/appcast.xml'],
        ['/macos/appcast.xml', '/appcast.xml'],
      ]).get(path);
      if (!assetPath) {
        return secure(new Response('Not found', { status: 404 }), false);
      }
      const assetURL = new URL(req.url);
      assetURL.pathname = assetPath;
      return secure(await e.ASSETS.fetch(new Request(assetURL, req)), false);
    }
    if (origin && origin !== e.ALLOWED_ORIGIN) {
      return secure(error(new ApiError(403, 'ORIGIN_NOT_ALLOWED', 'Origin is not allowed')), false);
    }
    if (req.method === 'OPTIONS') {
      return secure(new Response(null, {
        status: 204,
        headers: {
          'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
          'access-control-allow-headers': 'authorization,content-type',
          'access-control-max-age': '86400',
        },
      }));
    }
    try {
      return secure(
        path.startsWith('/api/')
          ? await route(req, e, ctx)
          : await e.ASSETS.fetch(req),
      );
    } catch (x) {
      return secure(error(x));
    }
  },
  async scheduled(_controller: ScheduledController, e: Env, ctx: ExecutionContext) {
    ctx.waitUntil(enforceAll(e));
  },
} satisfies ExportedHandler<Env>;
