# Tono Windows Test 6 — Bug-Fix + Connect-Perf Pass

**Date:** 2026-08-02
**Author:** Claude (this pass), following `CLAUDE_HANDOFF_WINDOWS_TEST6_2026-08-02.md`
**Base:** `3786195` (clean HEAD verified). All changes below are **uncommitted** working-tree edits scoped strictly to `Tono-win/` — none of the unrelated dirty paths (LiquidClash deletions, macOS `Tono/`, Cloudflare) were touched.

---

## 0. One-line status

12 adversarially-verified residual bugs fixed (2 of them new P1 availability bugs in the connect FSM), connect critical path parallelized and de-slept, all suites green including Windows-target cross-compilation. Test 6 packaging gates still pass. Still **no NSIS build** — the release blockers from the handoff (§3) remain the next step, unchanged.

## 1. Process

- 20-agent find/verify workflow (6 dimension scouts → dedup → adversarial verification, 35 raw → 12 confirmed).
- Fixes implemented (app side by orchestrator, service/frontend by 6 parallel agents on disjoint files).
- Second 8-agent adversarial review of the full diff: 1 introduced regression found → fixed (reverted a gate; see §4), 4 claims refuted.

## 2. Bugs fixed (all statically proven + adversarially verified)

### App (`app/src-tauri/src/tono/`)
1. **P1 — Connect-timeout handler aborted its own task** (`connection.rs`, `state.rs`): `retire_timed_out_generation` called `invalidate_connection`, whose `abort_connection_tasks()` aborts the very task the timed-out attempt runs in (reconnect loop / monitor re-entry / switch). `fail_connect` + `schedule_reconnect` never ran → FSM stranded in Connecting forever, auto-reconnect chain dead. Fix: new `retire_connection_generation` (generation bump + token cancel, **no task aborts**) used only by the timeout path.
2. **P1 — Failed release cleared the armed latch** (`connection.rs` `stay_armed_after_failed_release`, `commands.rs` sign-out branch): `connect_failed()` on an armed-but-unverified session resolves to FullRelease and cleared `kill_switch_armed` even though the Service release just FAILED — UI showed notConnected over a live WFP barrier and `quit_release` would then skip the release. Fix: `initial_release_failed()` at both sites (also un-sticks a pre-arm `is_disconnecting`).
3. **P1 — Reconnect self-invalidation loop** (`connection.rs` success block): monitor seeds (`network_events_counter` / `last_core_pid` / `last_restart_count`) were never reset on connect success, so every invalidation-driven reconnect compared the fresh monitor's first poll against pre-reconnect values → deterministic connect/teardown flapping after the first genuine network event. Fix: reset all three in the success block (re-enters "first sample seeds without firing").
4. **P2 — `restore_session` NoToken mutated FSM before its generation check** (`commands.rs`): could wipe a concurrent fresh connect's FSM. Fix: generation check hoisted, matching every sibling block.

### Service (`service/src/`)
5. **P1 — Stale resolver cache after DNS enable** (`core/dns.rs`): no flush after pointing resolvers at loopback; cached real-IP answers defeated the fake-ip probe (up to ~7 s burned, sometimes whole-connect failure). Fix: best-effort `engine_flush_cache()` on the full-apply success path (mirrors restore-path idiom; can never fail `enable()`).
6. **P1→P2 — Transport killed mutating handlers at 60 s** (`core/server.rs`): kode-bridge `write_timeout` drops the handler future mid-transaction, releasing the lifecycle lock while detached spawn_blocking work continues. Fix (low-risk variant): new `IPC_TRANSPORT_WRITE_TIMEOUT = 300s`; `IPC_HANDLER_TIMEOUT = 60s` remains the per-step budget. Client 65 s expiry while a handler runs is the already-supported lost-response case (generation late repair).
7. **P2 — Mutating IPCs on the 150 ms default timeout** (`client/mod.rs`): `update_writer`/`set_system_proxy` now `Some(LIFECYCLE_TIMEOUT)`; log routes get explicit `LOG_FETCH_TIMEOUT = 10s`. Also IPC runtime 2→4 workers (mitigates sync-SCM-verify worker parking; full fix needs a kode-bridge patch — see §5).
8. **P2 — WFP boot fail-open window on upgrade** (`core/windows_kill_switch.rs`): legacy-sublayer sweep ran before intent read/install (v1→current upgrade could boot with zero filters; permanent open if the intent read then errored). Fix: install-before-sweep on every branch; non-NotFound intent read error now arms the same emergency block as corrupt intent. Fresh-install no-op preserved (NotFound guard + provider-scoped checks).
9. **P2 — Netmon debounce starvation** (`core/netmon.rs`): trailing-edge-only 750 ms debounce never fired under sustained churn. Fix: 3 s max-wait cap via `FIRST_RAW_MILLIS`. Also fixed (verified real): `PENDING_RAW`-before-`LAST_RAW_MILLIS` store ordering (zero-debounce fires) and the STARTED latch swallowing registration failure (permanently dead monitor).
10. **P2 — `start_core` failure paths stuck at `Starting`** (`core/manager.rs`): 5 error paths left lifecycle state at Starting (reported as "settling" forever; masked Fatal). Fix: per-path rollback (Fatal for unconfirmed-stop, Running for settled rollbacks).
11. **P3 — Startup reconciliation had no retry** (`core/reconcile.rs`): one transient error blocked all core starts until service restart. Fix: `ensure_startup_reconciled` retries; latch remains success-only; serialized against double-reconciliation.

### Frontend (`app/src/`)
12. **P2 — Shared mihomo WS subscription could die permanently** (`hooks/use-mihomo-ws-subscription.ts`): reconnect timer no-oped against a hung in-flight connect. Fix: connect epoch + 10 s attempt timeout; stale attempts can't touch state; late sockets closed. Plus exponential backoff with ±20 % jitter (1/2/5/10 s cap) replacing the flat 1 Hz hammer.
13. **P3 — `TONO_*` error prefixes rendered raw** (`pages/tono/connect-progress.tsx`): now routed through the existing `formatTonoActionError` i18n mapping (keys already existed in zh+en).

## 3. Connect-speed / stability improvements

| Change | Where | Saving |
|---|---|---|
| 5 prep probes (bootstrap DNS, physical-interface, port alloc, DNS:53 preflight, core-path IPC) run **concurrently** under one transaction wait | `connection.rs run_stages` | ~0.3–2 s+ typical (bootstrap DNS alone budgets 2 s); all cancellation-safe/read-only |
| Bootstrap API host resolution parallelized (was sequential 2 s × up to 16 hosts before WFP arm) | `windows_kill_switch.rs resolve_api_hosts` | worst case ~32 s → ~2 s; order/dedup/cap semantics preserved |
| Resolver-cache flush after DNS enable | `dns.rs` | 0.5–7 s whenever gstatic was cached (very common), plus removes spurious connect failures |
| Controller readiness poll: 8 × 50 ms fast grid then 250 ms (deadline unchanged 15 s) | `connection.rs wait_controller` | ~100–200 ms every connect |
| `probe_exit` no longer sleeps 500 ms after the final failed attempt | `connection.rs` | 500 ms on failure paths |
| Core IPC pipe wait: 20 ms first 10 polls then 50 ms (same total budget) | `manager.rs` | tens of ms per core start (×2 with cloud policy) |
| WS reconnect backoff + no permanent death | frontend | stability + stops idle 1 Hz hammering |

Honest estimate (unmeasurable on macOS — needs the S6 Windows machine): **cold/stale-cache/slow-resolver connects improve well over 30 %** (the DNS-cache and host-resolution items alone dominate); warm clean-path connects improve ~10–25 %. The *stability* wins (no reconnect flapping loop, no stranded Connecting, no dead WS) are likely the most user-visible.

## 4. Reviewed-and-reverted

The second review pass caught one regression introduced by this pass itself: an idle gate on `connect-progress.tsx` status-push refetches could permanently hide the failure card after a milliseconds-fast pre-arm failure (ref lags React commit; no polling/focus recovery). Reverted to unconditional refetch with an explanatory comment. 4 other review claims were adversarially refuted.

## 5. Deliberately NOT done (with reasons)

- **Collapse dual StartClash for cloud DIRECT** (5–15 s when policy non-empty): handoff explicitly requires a design first; needs a new owner-gated Service route + protocol rev bump + intent persistence. Biggest remaining perf item.
- **Replace PowerShell CIM bridge for DNS apply** (1–2.5 s): verifier rated the WMI/COM in-process variant HIGH risk (unkillable hung RPC = the S1 hang class the killable-child design prevents). Needs real Windows validation.
- **kode-bridge sync-connect patch** (S1-adjacent): needs a fork of the git dep; mitigated via 4 IPC workers.
- `ensure_service_ready` double get_version + tray rebuild dedup: touches shared Run State machinery for ~tens of ms.
- `preflight_macos_kill_switch` still falls through to the transport default timeout (non-Windows read route; flagged by agent, out of Windows scope).

## 6. Verification

| Suite | Result |
|---|---|
| tono-core `--lib` | 152/152 |
| service `--lib` (`standalone,client,test`) | **166/166** (was 160; +6 new tests incl. unreadable-intent emergency block, resolve-order, debounce cap, start-rollback, reconcile retry) |
| app `--lib` (full) | 388/388 |
| packaging `node --test` | 4/4 |
| `release:preflight --config-only` | OK (7-file whitelist intact) |
| `cargo xwin check` service+app `x86_64-pc-windows-msvc` | clean (pinned `.toolchain`) |
| frontend `tsc --noEmit` | clean |

## 7. Release execution (updated 2026-08-02, second pass)

All of the above is now **committed and built**:

| Item | Value |
|---|---|
| Fix commit | `e1a5a55` fix(windows): close residual Test 6 P1s and speed up the connect path |
| Docs commit | `480be36` |
| Gate-fix commit | `36b70c2` fix(windows): parse real 7zz NSIS listings in the release preflight |
| Tag | `tono-windows-2.5.4-test6` → `36b70c2` (clean tree at tag time; **local only, not pushed**) |
| Installer | `Tono-win/dist-windows/Tono_2.5.4_x64-setup.exe`, 30,852,322 bytes (Test 5 was 35.4 MB) |
| Installer SHA-256 | `ef92f8bce4c4fdea9db4e44dcfd68d570f5bacb179892bcc6bf4b46eb97a4ece` |
| tono-service.exe SHA-256 | `26852af3462596443105a60c6d8abbf4dc756e0005b8cac4c804ef042fec834b` |
| verge-mihomo SHA-256 | `a064b52f2e4c476189edc7e078f22a45e16252d265afe9be1ee90afe0fec9969` |
| Manifest | `Tono-win/dist-windows/Tono-Windows-2.5.4-test6-release-manifest.json` |

**Payload proof (7zz, 18 entries):** exactly one `verge-mihomo.exe`; no `verge-mihomo-alpha`; no `clash-verge-service*`, `set_dns.sh`, `unset_dns.sh`; `Tono.exe` + `tono-service{,-install,-uninstall}.exe` all present. Full `release:preflight <tag> <installer> <manifest>` **passed** (clean tree, tag==commit, version triple-match, all three SHA cross-checks).

Note on `36b70c2`: the full payload gate had **never run against a real installer** — real 7zz output (blank date/time + blank compressed columns) matched zero lines of the old inline regex, failing every candidate. Parser extracted to `windows-packaging.mjs::parseNsisListing` + unit tests (packaging suite now 5/5). The installer was built at `480be36`; `36b70c2` changes build scripts only (nothing that ships), so the tag points at the gate-complete commit.

### Remaining (needs a real Windows machine — S6)
- Fault injection: WFP/DNS/WinTUN/SCM/sleep-wake.
- Measure connect timings to validate §3's estimates.
- Push tag + attach installer to the GitHub release when the owner decides (`releaseURL` in the manifest anticipates `releases/tag/tono-windows-2.5.4-test6`).

**Test 4 remains UNSAFE; Test 5 superseded; neither is for user testing. Test 6 is payload-proven but not yet real-machine-tested.**
