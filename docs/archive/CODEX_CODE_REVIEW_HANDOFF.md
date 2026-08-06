# Codex code review handoff — Tono 0.0.1

**Date:** 2026-07-28  
**Repo path:** `/Users/rw/Downloads/Project/liquidclash`  
**Audience:** Codex (backend-strong code review)  
**Goal:** Security- and correctness-focused review of **uncommitted** control-plane + client changes.  
**Not a goal:** Deploy, commit, push, write secrets, or ship a release.

> Status update (2026-07-28): this file preserves the original review brief.
> After that review, the user separately authorized a staging-only deployment.
> The user later selected an email-only Developer ID Release because native
> Sign in with Apple is not available to Developer ID apps. A staging Release
> archive passes strict nested-signature validation. The current helper 3.2.2
> submission `CD451028-9E5A-4333-9346-84AFEDC22624` was accepted, and its
> stapled app/ZIP pass Gatekeeper after extraction.
> See `HANDOFF.md` for the current state; production remains undeployed.
>
> Post-review remediation later on 2026-07-28 replaced the UID-only/Python Kill
> Switch with one signed native helper using audit-token code requirements,
> exact DERP/STUN allowlisting, and SHA-256-bound root runtime snapshots. It
> also implemented verified-public-key home usage attribution with stable ID
> retained only as audit/counter metadata. Older notarized artifacts predate
> those changes. Build 2 `20260729-r3` additionally removed the incorrect
> Home-US SOCKS hard gate for independent managed cloud exits and safely
> degraded on startup/runtime home failure. Build 3 `20260729-r4` then added
> authenticated catalog retry after PF state replacement and propagated
> catalog request/validation failures instead of silently reporting no nodes.
> Apple submission `37119603-AFDC-49DE-99D0-59B83A5AB9FA` is the current
> candidate; clean-Mac live validation remains pending. See `HANDOFF.md`.

---

## 0) Paste this prompt to Codex (start here)

```text
请先阅读仓库根目录：
  CODEX_CODE_REVIEW_HANDOFF.md
  HANDOFF.md
  README.md
  cloudflare/README.md（如有）

然后：
1. git status 与完整 uncommitted diff（含 untracked cloudflare/、Swift 新文件）。
2. 以控制面/安全为主做 code review（你擅长后端）：
   - Cloudflare Worker + D1 账号/设备/enrollment/confirm/revoke
   - Tailscale 三种 ID 合同与 inventory 解析
   - confirm claim 并发与 durable revocation
   - auth rate limit
   - ACL 策略 artifact
   - home usage 契约
3. 客户端只审查与安全边界相关的路径：Kill Switch、订阅门控、owned runtime、
   enrollment confirm 请求体、SOCKS 健康检查。
4. 不要部署、不要提交、不要写入真实密钥、不要回退现有改动。
5. 输出格式见 CODEX_CODE_REVIEW_HANDOFF.md §8。
6. 先跑：
     cd cloudflare && npm test && npm run typecheck
   若有 Xcode：
     export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
     xcodebuild -project LiquidClash.xcodeproj -scheme LiquidClash \
       -configuration Debug -destination 'platform=macOS' build
```

---

## 1) Product contract (do not redesign)

| Rule | Detail |
|------|--------|
| Product | macOS-only **Tono** `0.0.1`, bundle `com.raydocs.tono` |
| Traffic path | App → owned Mihomo TUN → selected `Tono-Exit`: local Tailscale Home-US SOCKS or one imported VLESS TLS/Reality endpoint |
| Control plane | Cloudflare Worker + D1 only — **never** relays user proxy bytes |
| Accounts | Allowlisted verified email/OIDC creates test accounts directly; **≤2** pending/active devices per user (DB trigger) |
| Kill Switch | When armed, host must **not** fall back to clearnet if tunnel dies; intentional disconnect/logout/quit may disarm |
| Naming | Call it **Kill Switch** only — no third-party brand comparisons in docs/UI |

---

## 2) Current repo state

- **Branch:** `main` tracking `origin/main` with large **local uncommitted** work.
- **No deploy**, no real secrets, no PR.
- Placeholders still in tree:
  - `Tono/Info.plist`: `TonoAPIBaseURL=https://api.tono.invalid`, empty `TonoExitNode`
  - `cloudflare/wrangler.jsonc`: `REPLACE_WITH_D1_DATABASE_ID`, example tailnet/origin
- Secrets must only ever be via `wrangler secret put` (never commit):
  `JWT_SECRET`, `ADMIN_API_TOKEN`, `HOME_AGENT_TOKEN`, `TAILSCALE_OAUTH_CLIENT_ID`,
  `TAILSCALE_OAUTH_CLIENT_SECRET`, and optional `RESEND_API_KEY`

### 2.1 Already verified on this machine (2026-07-28)

```text
cd cloudflare && npm test          → 37 tests pass
cd cloudflare && npm run typecheck → pass
cd cloudflare && npm audit         → 0 vulnerabilities (including dev dependencies)
# Vitest 4.1.10 + Workers pool 0.18.8; route tests reset D1 per test and
# exercise passwordless OTP/OIDC signature, nonce, audience, replay, and limits
# Xcode 26.6 via DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcodebuild … -configuration Debug  build → BUILD SUCCEEDED (Tono.app)
xcodebuild … -configuration Release build → BUILD SUCCEEDED
scripts/test-multi-exit-policy.sh <real US/JP YAML> → pass for both files
# Both real files also pass Mihomo syntax validation and their TCP/443 listeners
# are reachable; authenticated proxy/external-IP acceptance still needs login.
# Nested binaries in app: tailscale 1.86.2, tailscaled, mihomo Meta v1.19.21, helper
# Legacy clash-fetcher, Rust sources, and unused geodata are excluded from Tono.app
# Launch smoke: Release app opens/quits
```

The prior abandoned-request-stream warning is no longer present: oversized
request streams are drained before the Worker responds.

### 2.2 Not verified (out of scope for pure code review, but note)

- Real Tailscale enroll → confirm → home exit IP → revoke
- Kill Switch admin install + crash fail-closed E2E
- Live Home-US ↔ US VLESS ↔ Japan VLESS switching and observed exit IPs
- Deployed Worker + D1 + OAuth
- Home usage agent production attribution
- Notarization / distribution signing of nested binaries

---

## 3) What was wrong before (prior review) → what this pass claims to fix

| Severity | Issue | Claimed fix (review against code) |
|----------|--------|-----------------------------------|
| Critical | Client StableNodeID used as Device API path id; mock hid mismatch | Inventory list resolve; store mgmt / stable / api nodeId separately; mock uses 3 distinct IDs |
| Critical | Not system fail-closed on sidecar death | `KillSwitchService` (pf + root LaunchDaemon); health failure keeps armed |
| Critical | Network before transport ready + proxy latency bypass | Gate downloads; HTTPS policy; tonoMode proxy-only; Home-US-only delay tests |
| High | Text YAML delete as security boundary | `buildOwnedTonoRuntime` owns dns/tun/rules |
| High | Confirm race: promote then D1; loser may DELETE winner | Atomic claim; durable outbox; ownership check before delete |
| High | Pending revoke never deleted from tailnet | Persist mgmt id / expire + orphan inventory cleanup |
| High | No auth rate limit | D1 window limits on every passwordless start/verify path → 429 |
| Medium | TCP-only SOCKS probe | SOCKS5 greeting + CONNECT |
| Gap | Quota no home agent | Verified-key reporter implemented; deployment/live validation pending |

---

## 4) File map — **prioritize backend**

### 4.1 Cloudflare control plane (PRIMARY review)

| Path | Role |
|------|------|
| `cloudflare/src/index.ts` | All routes: auth, devices, enrollment, **confirm**, admin, home usage, cron |
| `cloudflare/src/crypto.ts` | JWT HS256, SHA-256, random tokens |
| `cloudflare/src/oidc.ts` | Apple/Google JWKS and OIDC ID-token verification |
| `cloudflare/migrations/0001_initial.sql` | users, devices, sessions, 2-device triggers |
| `cloudflare/migrations/0002_sessions_and_enrollment.sql` | enrollment_issued_at, device-bound sessions |
| `cloudflare/migrations/0003_revocation_jobs.sql` | durable Tailscale DELETE outbox |
| `cloudflare/migrations/0004_identity_and_rate_limit.sql` | stable/api ids, claim_token, unique indexes, rate_limits |
| `cloudflare/migrations/0005_durable_claim_ownership.sql` | ownership generations + public key + outbox fencing |
| `cloudflare/migrations/0006_usage_report_immutability.sql` | immutable report-id trigger |
| `cloudflare/migrations/0007_enrollment_possession_binding.sql` | server-issued enrollment hostname |
| `cloudflare/migrations/0008_revocation_enrollment_fence.sql` | indexed prior-identity revocation fence |
| `cloudflare/migrations/0009_passwordless_auth.sql` | identities, one-time challenges, password retirement |
| `cloudflare/test/worker.test.ts` | Integration tests + Tailscale mock (3 distinct IDs) |
| `cloudflare/test/crypto.test.ts` | crypto unit tests |
| `cloudflare/test/setup.ts` | D1 migrations apply |
| `cloudflare/vitest.config.ts` | low rate-limit bindings for tests |
| `cloudflare/wrangler.jsonc` | bindings, cron `*/5`, vars |
| `cloudflare/policy/tailnet-acl.hujson` | pending tag isolation + policy tests (doc only until applied) |
| `cloudflare/public/*` | admin static assets |

### 4.2 Home usage (secondary backend)

| Path | Role |
|------|------|
| `home-agent/README.md` | Contract for monotonic usage reports |
| `home-agent/report_example.py` | Durable verified-key usage reporter |

### 4.3 Client security-relevant (SECONDARY, still read)

| Path | Role |
|------|------|
| `Tono/Services/TonoSidecarService.swift` | status parse, enroll identity, SOCKS5 probe, userspace daemon |
| `Tono/Services/AccountSession.swift` | restore/login/enroll/confirm/monitor; kill switch arm/disarm policy |
| `Tono/Services/TonoAPIClient.swift` | HTTPS API, refresh, confirm body |
| `Tono/Services/TonoIdentityProviders.swift` | Apple nonce/state; Google loopback/state/PKCE |
| `Tono/Models/TonoAPIModels.swift` | wire models; `stableNodeId` CodingKeys |
| `Tono/Services/KillSwitchService.swift` | pf helper install, arm/disarm, reassert |
| `Tono/Services/AppState.swift` | connect/disconnect + kill switch; subscription gate; latency policy |
| `Tono/Services/SubscriptionManager.swift` | `tonoMode` download path (no noproxy) |
| `Tono/Support/SubscriptionURLPolicy.swift` | HTTPS + private host reject |
| `Tono/Core/ConfigPipeline.swift` | `buildOwnedTonoRuntime` |
| `Tono/LiquidClashApp.swift` | URL import gate; terminate disarm |

### 4.4 Client product shell (skim only unless bug)

Views, UI rebrand, existing Mihomo UI, `HelperManager` for mihomo core only.

### 4.5 Binaries / scripts

| Path | Role |
|------|------|
| `Tono/Resources/tailscale`, `tailscaled` | Pinned ~v1.86.2 userspace sidecar |
| `scripts/build-tailscale-sidecar.sh` | Rebuild pin |
| `Tono/Resources/mihomo`, `liquidclash-helper` | Existing core helper |

---

## 5) Backend review checklist (Codex deep dive)

### 5.1 Tailscale identity contract

- [ ] Confirm body requires `stableNodeId` + `publicKey` + `tailscaleIPs[]` (optional `nodeId`).
- [ ] Worker **never** does `GET /device/{clientStableId}` as primary resolve.
- [ ] Resolve only via `GET /tailnet/{tailnet}/devices`.
- [ ] Match requires `tag:pending-tunnel-client` + **exact address multiset**.
- [ ] Prefer exact `nodeId` / publicKey / exact id equality; avoid loose `.includes` hazards where possible.
- [ ] Tag promotion and DELETE use **management** `id` only.
- [ ] D1 stores: `tailscale_node_id` = management id; `tailscale_stable_id`; `tailscale_api_node_id`.
- [ ] Tests: three IDs deliberately different (`mgmt-abc` / `nodeid-xyz` / `stable-n123`).

### 5.2 Confirm claim / concurrency

- [ ] Atomic claim (`claim_token`, short TTL) **before** external promotion.
- [ ] Activate is conditional on same claim_token + `status=pending`.
- [ ] Losing concurrent confirm → 409; **must not** DELETE a node owned by another device.
- [ ] If promote succeeds but D1 activate fails → **revocation_jobs outbox first**, then best-effort process.
- [ ] UNIQUE partial indexes on non-null management id and stable id.
- [ ] Re-read `compensateConfirmFailure` / ownership guards carefully.

### 5.3 Pending cleanup & revocation

- [ ] `expirePending` enqueues revoke when management id present.
- [ ] Cron `enforceAll` + `cleanupOrphanPendingNodes` for `tag:pending-tunnel-client` + `tono-device-{id}` description.
- [ ] Active revoke: D1 session/device first, then durable outbox; cron retries DELETE.
- [ ] Re-enable user blocked while revocation jobs pending (if still implemented).

### 5.4 Auth & sessions

- [ ] Email OTP: generic start response; peppered hash; 6 digits/10 minutes/5 attempts; atomic single-use; installation/device binding.
- [ ] New email/OIDC account requires exact `DIRECT_SIGNUP_ALLOWLIST` membership plus mailbox/provider verification; invitations are not consulted.
- [ ] OIDC: fixed JWKS origins; RS256 signature; issuer/audience/exp/iat/nonce/sub/verified-email checks; no token persistence.
- [ ] Provider subject is authoritative after linking; verified-email auto-link cannot cross an existing conflicting identity.
- [ ] Refresh: hash-only storage, one-time rotate (conditional update).
- [ ] Access JWT re-checked every call against session + user + device + quota/expiry (not JWT-only trust).
- [ ] Rate limit email/OIDC start and verify by hashed IP/email/installation/challenge; 429 `RATE_LIMITED`; failed attempts consume limits.
- [ ] CORS: exact `ALLOWED_ORIGIN`; native clients may omit Origin.

### 5.5 Admin / quota / home usage

- [ ] Admin routes require `ADMIN_API_TOKEN`.
- [ ] `/home/usage`: `HOME_AGENT_TOKEN`; monotonic `MAX(usage_bytes)`; idempotent `report_id`.
- [ ] Quota hit → enforce revoke path.
- [ ] Note: without home-agent, usage stays ~0 — mark incomplete, not “done”.

### 5.6 ACL policy artifact

- [ ] `tag:pending-tunnel-client` has **no** useful grants in `tailnet-acl.hujson`.
- [ ] Policy `tests` section is coherent.
- [ ] Document that policy is **not applied** until human applies to tailnet.

### 5.7 Crypto / injection / DoS

- [ ] No secret logging.
- [ ] SQL uses bound parameters.
- [ ] Tailscale OAuth and API errors don’t leak secrets to clients.
- [ ] OIDC/JWKS and challenge limits bound signature/network abuse on the Worker.
- [ ] Enrollment key: one-time, short TTL, pending tag only, cooldown.

### 5.8 Tests quality

- [ ] Mock inventory path is the one production uses.
- [ ] Concurrent claim test is real enough (even if sequential simulation).
- [ ] Promo-fail compensation enqueues job.
- [ ] Pending expire enqueues job when mgmt id set.
- [ ] Rate limit 429 tested.
- [ ] Oversized request streams are drained; flag any recurrence of the old
  abandoned-stream warning.

---

## 6) Client security checklist (lighter)

### 6.1 Kill Switch

- [ ] Armed before enroll/connect.
- [ ] Authenticated sidecar + loaded local state auto-start mandatory TUN.
- [ ] Mihomo-owned `utun199` watchdog fails closed and retries only the same selection.
- [ ] Health failure: clear descriptor → stop Mihomo/sidecar → **leave armed**.
- [ ] User disconnect / logout / quit / signed-out restore: **disarm**.
- [ ] Reassert on relaunch if armed; re-supply API host allowlist (avoid bricking `api.me()`).
- [ ] Helper uid-gates arm/disarm; status checks live pf when possible.
- [ ] Imported-node exception is one exact public IPv4/TCP/port tuple,
      `user root`; private/hostname/IPv6/UDP proxy endpoints are rejected.
- [ ] Re-arm flushes old PF states before a selected-node transition completes.
- [ ] Honest residual risks: legacy LaunchDaemon lifecycle, exact `utun199`,
      DERP-only bootstrap, and not Network Extension.

### 6.2 Pre-ready network

- [ ] Catalog fetch requires authenticated enrollment/confirm and an already
      armed PF bootstrap; it may precede optional Home-US sidecar health.
- [ ] `tono://install-config` is rejected without storing or fetching its
      credential-bearing URL.
- [ ] Tono download only via local mixed-port or sidecar SOCKS — no `noproxy` / clash-fetcher direct.
- [ ] No bulk subscription latency tests in Tono mode.

### 6.3 Runtime config

- [ ] Owned runtime: no inherited subscription `rules`/`dns`/`tun`.
- [ ] Managed catalog YAML is parsed and re-serialized; source documents/anchors/merge
      keys cannot become runtime policy.
- [ ] Catalog revision and SHA-256 are verified; rollback, oversize, symlink,
      wrong-owner, and group/world-readable cache states fail closed.
- [ ] Protected nodes accept only uniquely named TCP-carried VLESS TLS/Reality nodes with
      public IPv4 literals and verified certificates.
- [ ] Final `MATCH,Tono-Exit`; group contains Home-US plus managed nodes;
      process bypass is limited to sidecar bootstrap and loopback.
- [ ] Removing the currently selected cloud node stops Mihomo, retains PF, and
      requires explicit user selection instead of silently falling back.

### 6.4 Enrollment wire

- [ ] Confirm request matches Worker (`stableNodeId`, not management id as path).
- [ ] Device model decodes Worker `stableNodeId` → `tailscaleStableId`.

---

## 7) Suggested review order (backend-first)

1. Read this file + `HANDOFF.md` + `README.md`.
2. `cloudflare/migrations/*` schema evolution.
3. `cloudflare/src/crypto.ts` then entire `index.ts` (confirm + revoke + rate limit).
4. `cloudflare/test/worker.test.ts` — do mocks match production contract?
5. `policy/tailnet-acl.hujson` + `home-agent/*`.
6. Client: `TonoSidecarService` identity → `AccountSession` confirm → `TonoAPIClient`.
7. Client: `KillSwitchService` + disconnect paths in `AppState` / `LiquidClashApp`.
8. Client: managed-catalog application/cache + `ConfigPipeline.buildOwnedTonoRuntime`;
   verify the legacy subscription UI and deep link cannot bypass it.
9. Run tests/builds listed in §0.
10. Write findings per §8.

---

## 8) Required output format from Codex

```markdown
# Tono code review (Codex)

## Summary
- Overall: (ready for next stage / not ready)
- Backend confidence: high/med/low
- Client security confidence: high/med/low

## Findings (ordered by severity)
### Critical
- **Title** — file:line — evidence — impact — suggested fix (size S/M/L)

### High
…

### Medium
…

### Low / nits
…

## What looks correct
- bullets of solid patterns (claim SM, hashes, triggers, etc.)

## Test / build results
- npm test / typecheck / xcodebuild (commands + pass/fail)

## Residual ship blockers (not pure code)
- real tailnet smoke, deploy placeholders, home-agent, signing…

## Recommended next engineering tasks (priority order)
1. …
```

**Severity guide:**

- **Critical:** production enrollment fails; auth bypass; wrong node deleted; clearnet leak while “protected”; quota/revoke hole exploitable.
- **High:** race/DoS/missing durable cleanup; test mocks that hide production bugs.
- **Medium:** incomplete disambiguation, weak health probe, ACL not applied, etc.
- **Low:** style, naming, non-security warnings.

---

## 9) API surface cheat sheet (Worker)

| Method | Path | Auth |
|--------|------|------|
| GET | `/api/v1/health` | public |
| GET | `/api/v1/auth/methods` | public |
| POST | `/api/v1/auth/email/start` | public + rate limit |
| POST | `/api/v1/auth/email/verify` | public challenge |
| POST | `/api/v1/auth/oidc/challenge` | public + rate limit |
| POST | `/api/v1/auth/oidc/verify` | public challenge + provider ID token |
| POST | `/api/v1/auth/refresh` | refresh token |
| POST | `/api/v1/auth/logout` | access |
| GET | `/api/v1/me` | access |
| GET | `/api/v1/devices` | access |
| DELETE | `/api/v1/devices/:id` | access |
| POST | `/api/v1/devices/:id/enrollment` | access (same installation) |
| POST | `/api/v1/devices/:id/confirm` | access — **body: stableNodeId, publicKey, tailscaleIPs, optional nodeId** |
| * | `/api/v1/admin/*` | `ADMIN_API_TOKEN` |
| POST | `/api/v1/home/usage` | `HOME_AGENT_TOKEN` |
| GET | `/api/v1/home/inventory` | `HOME_AGENT_TOKEN` |
| scheduled | cron `*/5` | enforce + revocations + orphan pending cleanup |

**Confirm success criteria (must hold):**

1. Device row pending, not expired, claim won.  
2. Inventory device: pending tag + exact IPs (+ identity match).  
3. Promote tags → `tag:tunnel-client` via management id.  
4. D1 status → active with management id stored.  
5. Failures never delete another device’s node; post-promo failures go to outbox.

---

## 10) Known residual risks (already documented — confirm or refute)

1. Kill Switch remains **pf + LaunchDaemon**, not Network Extension, but the
   helper now authenticates the peer audit token and exact Tono signing
   requirement. Live install/lifecycle validation remains.
2. The current pf helper permits only the exact existing `utun199` plus exact
   resolved control/DERP/STUN endpoints. Direct WireGuard is intentionally
   blocked; DERP reachability has not been proven live.
3. Imported VLESS endpoints add one root-only exact public IPv4/TCP exception
   for the current selection. Only file/syntax/listener checks are complete;
   authenticated handshakes, observed exit IPs, and live switching are pending.
4. SOCKS probe proves SOCKS reply, not full exit-node public IP.  
5. `publicKey` matching depends on Device API field availability.  
6. Concurrent confirm is exercised with the first request paused after its D1
   guard and before tag-promotion completion.
7. Home verified-public-key/peer-counter attribution is implemented but not
   deployed or live-validated; quota remains incomplete operationally.
8. Real Resend delivery and Apple/Google tenant flows are unverified; Apple also
   needs the signed App ID capability/entitlement before its button is enabled.
9. System `xcode-select` may still point at CLT; use `DEVELOPER_DIR` for Xcode.

---

## 11) Commands Codex should run

```bash
cd /Users/rw/Downloads/Project/liquidclash

# Status / diff
git status -sb
git diff --stat
# Also inspect untracked: cloudflare/, Tono/Services/AccountSession.swift, etc.

# Backend
cd cloudflare && npm test && npm run typecheck && cd ..

# Client (if Xcode present)
scripts/test-multi-exit-policy.sh /absolute/path/to/vless.yaml
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcodebuild -project LiquidClash.xcodeproj -scheme LiquidClash \
  -configuration Debug -destination 'platform=macOS' build
```

Do **not**:

- `wrangler deploy` / `secret put` with real values  
- `git commit` / `push` / force-push  
- Delete user work or reformat entire tree  
- Soften security checks to “make tests pass”

---

## 12) Definition of “review complete”

Codex review is complete when:

1. Backend findings for §5 are written with file:line evidence.  
2. Client security §6 is at least skimmmed with any Critical/High called out.  
3. Tests/builds in §11 are run and reported.  
4. Residual non-code ship blockers are listed separately from code bugs.  
5. No secrets or deploy actions were performed.

After Codex returns findings, human (or next agent) should fix **Critical/High** before any real tailnet smoke or deploy.

---

## 13) Related docs

| File | Purpose |
|------|---------|
| `HANDOFF.md` | Engineering state + remediation history |
| `README.md` | Product-facing status table |
| `THIRD_PARTY_NOTICES.md` | License obligations |
| `cloudflare/policy/tailnet-acl.hujson` | Intended ACL |
| `home-agent/README.md` | Usage report contract |

---

**End of handoff.**  
Primary ask for Codex: **break the control plane if you can** (identity mixup, confirm races, revoke holes, rate-limit bypass, mock lying about production). Secondary: client leak paths (pre-ready net, kill switch disarm on failure, YAML inheritance).
