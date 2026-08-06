# Claude Handoff — Tono Windows Test 6

**Date:** 2026-08-02  
**Author of this handoff:** Grok (prior agent)  
**Repo:** `/Users/rw/Downloads/Project/liquidclash`  
**Focus tree:** `tono-win/` (Windows Tauri App + LocalSystem Service + tono-core)

---

## 0. One-line status

**Source is a Test 6 *code* candidate. There is no installable Test 6 package yet. Do not tell the user to install/test Test 4 or Test 5. Do not claim “ready for user testing” until NSIS is built and 7zz payload gates pass.**

Static P0–P4 freeze/safety issues that could be closed from code review alone are largely done. Remaining work is **release packaging proof** and **real Windows fault injection**, not another full rewrite.

---

## 1. Commits to start from (already on `main` local)

| SHA | Message |
|---|---|
| `fb59a51` | `fix(windows): harden Test 6 connect safety and packaging gates` |
| `3786195` | `fix(windows): keep Service status readable after mutex poison` |

```bash
git log --oneline -5
# expect:
# 3786195 fix(windows): keep Service status readable after mutex poison
# fb59a51 fix(windows): harden Test 6 connect safety and packaging gates
# 59737f5 feat: add hardened Tono Windows client
```

**Note:** Working tree may still be dirty with unrelated paths (LiquidClash deletions, macOS `Tono/`, Cloudflare, handoff docs). Those were **intentionally excluded** from the commits above. Do not mix them into a Test 6 release commit.

---

## 2. What was already fixed (do not re-do)

### P0 — freezes / safety races
- Service IPC on **dedicated 2-worker runtime**; Tauri runtime **≥4 workers**.
- Connect **absolute budget 120s** (`CONNECT_TRANSACTION_TIMEOUT`), not 45s.
- **CancellationToken** + generation bump; Disconnect/Sign-out/Quit retire old work.
- **Release single-flight** (`ReleaseOperation`); Connect refused while `release_in_progress`.
- Late StartClash/DNS: detached mutation + **privileged RW barrier** so late commits cannot cross an in-flight release.
- Windows **atomic** owner-gated release: DNS restore → Core stop → WFP remove under one lifecycle lock.
- **Protocol revision 9** required App↔Service (`MIN_REQUIRED_SERVICE_REVISION = 9`).
- Kill-switch lock retries only for **TUN-not-ready** errors (`is_retryable_lock_error`); permanent errors fail immediately.
- Stable error prefixes: `TONO_SERVICE_BUSY`, `TONO_RELEASE_RECONCILING`, `TONO_SERVICE_TOO_OLD` + frontend i18n.

### P1 — lifecycle / recovery
- Native Win32 process + **Job Object kill-on-close** (no tasklist/taskkill main path).
- Dynamic controller port; TUN `mixed-port=0`; DNS 53 TCP/UDP preflight.
- DIRECT: pre-TUN `GetBestRoute2` + `GetIfEntry2.Alias`; Unicode aliases OK; >256 endpoints hard fail.
- Service multi-thread runtime (4 workers); status reads **do not** take lifecycle write lock.
- DNS restore **fail-closed** (no “fail N times then open”).
- Quit: interactive path async (no Tao `block_on` for preventable exit); WM_ENDSESSION short budget.

### P2 — UX / size
- Bootstrap UI ≤2s; reduced blur; WebSocket reconnect hardening.
- Frontend dist slimmed (Monaco out of production bundle via tree-shake).
- Status mutex poison recovery on WFP/DNS status paths.

### P3/P4 — packaging gates (config + automation)
- `tauri.conf.json`: `externalBin = ["sidecar/verge-mihomo"]` only.
- `resources` = **7-file Windows whitelist** (not whole `resources/` dir).
- `pnpm release:preflight --config-only`
- Full preflight: clean tree + tag + **7zz payload** + commit/service SHA (hard).
- Portable scripts no longer `addLocalFolder(resources)`.
- `scripts/build-windows-release.sh`: config-only before build, 7zz smoke after.

### Verified locally (macOS host)
| Suite | Result |
|---|---|
| tono-core | 152/152 |
| Service lib (`standalone,client,test`) | 160/160 |
| App `tono::connection` | 20/20 |
| packaging unit tests | 4/4 |
| preflight `--config-only` | OK |

---

## 3. Remaining P0–P4: honest inventory

### No more “easy static P0” left to code-fix
If Claude finds a **new** static P0 (proof: code path freezes UI, fail-open after arm, release tears new connect, App pairs with rev&lt;9 Service, dual Mihomo in bundle config), fix it. Do **not** invent work by re-litigating already-fixed items above.

### Release blockers (process, not more app logic)
These **block user testing**, not more unit tests:

1. **No Test 6 NSIS built from `3786195` (or a later clean tip).**
2. Must pass real payload list:
   - exactly one stable `verge-mihomo*.exe`
   - **no** `verge-mihomo-alpha`
   - **no** `clash-verge-service*`, `set_dns.sh`, `unset_dns.sh`
3. Manifest must include: `commit`, `service.sha256`, installer/mihomo SHA, tag URL.
4. Tag must point at clean commit; no dirty “source snapshot” like Test 5.

### Residual risks (known; need Windows, not macOS refactor)

| ID | Pri | Topic | Why not “just fix in code now” |
|---|---|---|---|
| S1 | P1→P0 if proven | WFP/BFE or CIM hang inside `spawn_blocking` | Timeout+retry is unsafe (late mutation). Needs helper process or actor journal + real dump. |
| S2 | P2 | No durable operation journal / cancel on Service | Architectural; current design uses idempotent owner-gated repair. |
| S3 | P2 | Status multi-source snapshot | Diagnostically fine; destructive ops must re-gate on Service. |
| S4 | P2 | Port 53 / controller TOCTOU | Inherent without inherited FDs; bounded by connect deadline. |
| S5 | P2 | Legacy Clash commands/plugins still compile | Size/attack surface; delete in separate clean commits. |
| S6 | Gate | Real WFP/DNS/WinTUN/SCM/sleep-wake | Only Windows machine proves these. |

### Optional small follow-ups (P2/P3 only if time)
- Poison-safe recovery on remaining WFP **write** path `.lock().unwrap()` (status path already fixed).
- Collapse dual StartClash for cloud DIRECT into stage+permit update (big behavior change; needs design).
- Delete unused Monaco/legacy pages after knip/audit (do not break other programmer’s WIP).
- Network-monitor GetBestRoute2 interface-level filter (commented as follow-up to P0-13 debounce).

---

## 4. What Claude should do

### Preferred order
1. **Re-read** these reports (don’t re-audit from zero):
   - `Tono/reports/TONO_WINDOWS_P0_P4_FINAL_REVIEW_2026-08-02.md`
   - `Tono/reports/TONO_WINDOWS_PRETEST_GATE_2026-08-02.md`
   - `Tono/reports/TONO_WINDOWS_TEST5_REMEDIATION_REVIEW_2026-08-02.md`
2. **Verify HEAD** includes `3786195` / packaging whitelist.
3. **Only fix new bugs** with static proof or failing tests.
4. If no new code P0: **drive Test 6 release gates**:
   - clean worktree (or isolated commit) containing only Windows release surface
   - build Service → copy resources → `cargo tauri build` NSIS
   - `7zz l -ba` + `pnpm release:preflight <tag> <installer.exe>`
5. Update handoff with installer SHA / payload list / residual findings.
6. **Do not** push unless user asks. **Do not** mark Test 5 safe.

### Commands (quick)
```bash
cd tono-win
# packaging gate
(cd app && node scripts/windows-release-preflight.mjs --config-only)
(cd app && node --test scripts/windows-packaging.test.mjs)

# unit suites used so far
cargo test --manifest-path crates/tono-core/Cargo.toml --lib
cargo test --manifest-path service/Cargo.toml --lib --features 'standalone,client,test'
(cd app/src-tauri && cargo test --lib tono::connection)

# full Windows release (needs pinned toolchain under tono-win/.toolchain)
# from repo root:
# ./scripts/build-windows-release.sh 2.5.4
```

### Critical files
| Area | Path |
|---|---|
| Connect FSM | `app/src-tauri/src/tono/connection.rs` |
| Release single-flight | `app/src-tauri/src/tono/state.rs` |
| Commands / quit | `app/src-tauri/src/tono/commands.rs` |
| Service IPC client | `service/src/client/mod.rs` |
| Service router / lifecycle | `service/src/core/server.rs` |
| WFP facade | `service/src/core/windows_kill_switch.rs` |
| DNS | `service/src/core/dns.rs` |
| Job Object | `service/src/core/manager.rs`, `service/src/core/process.rs` |
| Protocol | `service/src/lib.rs` (`PROTOCOL_REVISION=9`) |
| Bundle map | `app/src-tauri/tauri.conf.json` |
| Packaging gates | `app/scripts/windows-packaging.mjs`, `windows-release-preflight.mjs` |
| Release script | `scripts/build-windows-release.sh` |

### Product invariants (do not break)
- Fail-closed after WFP arm: only Disconnect / Sign out / Quit release.
- Never cancel a mutating IPC that may have committed; use generation + late repair.
- Never package alpha Mihomo or Unix helpers on Windows.
- App must refuse Service revision &lt; 9.
- Do not re-enable whole-directory `bundle.resources: ["resources"]`.

---

## 5. Explicit non-goals for Claude right now
- Rewriting Mihomo in Rust.
- Rewriting UI as pure Rust.
- Large Clash Verge deletion in the shared dirty tree without isolation.
- Claiming xwin/unit tests = Windows WFP proven.
- User-facing “go install Test 6” without NSIS payload proof.

---

## 6. Suggested reply template after Claude’s pass
- **New code P0 found?** list + fix + tests + commit.
- **No new P0:** say so, list residual S1–S6, and either:
  - produce Test 6 build + 7zz proof, or
  - clearly block on “need Windows build machine / push of clean tag”.
- Always restate: **Test 4 UNSAFE, Test 5 superseded, not for testing.**

---

## 7. User intent
Owner has been burned by repeated “fixed” builds that still hang or brick network. Prefer **fewer, proven gates** over more speculative refactors. Prefer dump-driven diagnosis if freezes remain after Test 6 payload is clean.
