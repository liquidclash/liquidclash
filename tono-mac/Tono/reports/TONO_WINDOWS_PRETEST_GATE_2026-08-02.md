# Tono Windows — Pre-Test System Gate (2026-08-02)

**Verdict for existing installers: DO NOT test Test 4 or Test 5.**  
**Verdict for current source: OK to build Test 6 after the gates below.**  
**Verdict for “user can install and test right now”: NO — there is no Test 6 package yet that includes these fixes.**

This review re-audited the Windows control plane after Test 5 and the P0–P4 remediation work. Goal: find remaining system-level bugs that make the app hang, freeze, or leave the machine network-broken, before another wasted real-device cycle.

---

## 1. Why previous tests kept failing

| Build | What users hit | Root cause class |
| --- | --- | --- |
| Test 4 | Network broken / unsafe | Fail-open / incomplete kill-switch contract |
| Test 5 | `Not Responding` during Starting Kill Switch | UI runtime starved by Service IPC + global locks + unbounded waits |
| Current source (unreleased) | Would still false-timeout cold connects; could pair with old Service | Absolute 45 s connect budget too tight; protocol probe did not require rev 9 |

The app is **already mostly Rust** (Tauri + Service + tono-core + Mihomo sidecar). Rewriting the UI in Rust would not fix WFP/DNS/Service races. The remaining work is lifecycle, timeouts, and packaging discipline — not “make it native Rust.”

---

## 2. What is already solid in source (post-remediation)

These are real improvements vs Test 5 and should ship together as **protocol revision 9**:

1. **App IPC isolation** — dedicated 2-worker Service IPC runtime; Tauri runtime min 4 workers.
2. **Cancellation-safe StartClash / DNS enable** — detached mutation tasks + generation/stale-arm patch + privileged-transition RW lock so release waits for late commits.
3. **45→120 s absolute connect budget** (this pass) — covers dual StartClash + DNS + lock on cold machines.
4. **Service multi-thread runtime (4 workers)** — no longer freezes the whole control plane on one sync OS call.
5. **Lock-free status paths** — `/status`, kill-switch status, DNS status read committed/cached snapshots; writers still serialize on `OWNER_LIFECYCLE_LOCK`.
6. **Windows Job Object** for Mihomo (kill-on-close) + native `TerminateProcess` (no tasklist/taskkill).
7. **Dynamic controller port**; TUN does not open unused mixed port 7890.
8. **DNS 53 TCP/UDP preflight** before WFP arm.
9. **DNS restore is fail-closed** (no “three failures then open network” degrade).
10. **Windows release is one Service transaction** (DNS restore → Core stop → WFP remove) under one lifecycle lock.
11. **Quit no longer block_on’s the UI event loop** for release.
12. **Bootstrap preload budget 2 s** so first paint cannot hang forever on vault/language IPC.
13. **Chinese / Unicode adapter aliases allowed** for DIRECT physical interface.
14. **DIRECT endpoints hard-fail above 256** (no silent truncate).

---

## 3. Bugs fixed in this pre-test pass

| ID | Severity | Fix |
| --- | --- | --- |
| G1 | **P0 product** | Connect absolute budget **45 s → 120 s**. Cold dual-StartClash + PowerShell DNS was racing the old deadline and looking like hang/fail. |
| G2 | **P0 safety** | Service compatibility probe now requires **`MIN_REQUIRED_SERVICE_REVISION` (9)**, not just “has WFP/release/verify features” (which Test 5 rev 8 already had). Prevents new App + old Service silent pairing. |
| G3 | **P1 freeze** | Windows `GetBestRoute2` / `GetIfEntry2` moved to **`spawn_blocking`** so IP Helper cannot starve Tauri workers. |
| G4 | **P2 size/attack surface** | `tauri.conf.json` resources changed from whole `resources/` dir to a **Windows whitelist** (drops ~5 MB Unix clash-verge-service + set_dns scripts). |
| G5 | **P3 tooling** | Service `test` feature now includes `serde_json` so focused unit tests compile. |

---

## 4. Remaining residual risks (cannot be closed by macOS unit tests)

These are the only classes still worth treating as **real-device gates**. None of them are “static proof of freeze,” but they are the ones that have burned previous test cycles.

### R1 — Cold first connect still heavy (P1)

Worst path still does:

1. StartClash #1 (WFP bootstrap + WinTUN + core) — Service handler up to 60 s  
2. Controller ready ≤ 15 s  
3. Lock retries ≤ ~10 s  
4. Optional cloud-policy StartClash #2 (another full start)  
5. Protected DNS enable (registry + one PowerShell CIM batch, 10 s kill)  
6. Fake-IP / exit probe / verify / mark verified  

**Mitigation in source:** 120 s absolute budget + stage status pushes + cancellation-safe late commits.  
**Still needs device proof:** first connect after reboot with policy present, under 120 s, UI never “Not Responding.”

### R2 — Installer Service replacement (P0 process)

If NSIS/UAC fails to replace `tono-service.exe`, App now **refuses connect** with a clear “Service too old / reinstall” error (G2).  
**Must verify on device:** after install, `sc qc` / version probe shows protocol **revision 9**, not 8.

### R3 — PowerShell DNS path (P1 device)

DNS live apply still uses a **single PowerShell process** with a **10 s hard kill**. Unusual CIM/WMI hangs are bounded, but machines with broken WMI can fail restore and correctly **keep WFP armed** (fail-closed). Users may see “cannot restore network” until repair — this is intentional safety, not a hang.

### R4 — Residual Clash Verge surface (P2 product)

- Legacy routes/components still exist in the tree (profiles, Monaco, old settings mods).  
- Product navigation is Tono-only (`dashboard/servers/account/settings/login`).  
- Capability surface was tightened (no open `http://*/*`); plugins still initialized for compatibility.  
- **Do not open leftover deep links** during Test 6 acceptance.

### R5 — Packaging leftovers on disk (P2)

`sidecar/` still contains alpha binaries on the build machine (~47 MB).  
`externalBin` only ships **stable** `verge-mihomo`.  
**Release gate:** unpack the NSIS payload and assert **no** `verge-mihomo-alpha`, **no** Unix helper binaries.

### R6 — Source not yet a released artifact (P0 process)

All of the above is **working tree / uncommitted source**. Test 5 tags do **not** include this. Testing an old installer again will re-hit old bugs and waste dump cycles.

---

## 5. What we deliberately did **not** do

- **Did not rewrite Mihomo** (would be multi-month and not the freeze root cause).  
- **Did not rewrite UI in pure Rust** (Tauri WebView is fine if IPC never blocks UI).  
- **Did not remove dual StartClash for cloud DIRECT** in this pass (correctness requires permit-before-selector; budget was raised instead). Future optimization: in-place stage + permit-only WFP update without full core restart.  
- **Did not claim Windows WFP/BFE real-machine proof** from unit tests on macOS.

---

## 6. Verification evidence (this machine)

| Suite | Result |
| --- | --- |
| tono-core `--lib` | **152 passed** |
| Service `--lib --features standalone,client,test` | **160 passed** |
| App `tono::connection` unit tests | **19 passed** |
| App `cargo check --lib` | **ok** (host) |

Windows-only truth still required: x86_64-pc-windows-msvc release build, NSIS pack, Service install, WFP arm/lock/release on a real Windows host.

---

## 7. Test 6 release blockers (must all pass before user testing)

1. **Commit** the full Windows safety delta (App + Service + core + packaging) as one coherent commit.  
2. **Bump/install Service** from that commit (protocol **epoch 2 / revision 9**).  
3. **Build** NSIS on Windows (or the project’s Windows release pipeline).  
4. **Unpack payload and assert:**
   - `Tono.exe`
   - `resources/tono-service.exe` (+ install/uninstall)
   - **one** `verge-mihomo-*.exe` (stable only)
   - **no** `verge-mihomo-alpha*`
   - **no** `clash-verge-service*` / `set_dns.sh` / `unset_dns.sh`
5. **SHA-256** App + Service + Mihomo recorded in manifest with **git commit SHA**.  
6. Mark Test 5 / Test 4 as superseded / UNSAFE.

---

## 8. Real-device acceptance script (after Test 6 install)

### A. Idle UI (before any connect)

1. Kill any stuck old `Tono.exe`.  
2. If network already broken: install only if needed, open App, **Restore Normal Internet**, reboot.  
3. Install Test 6, reboot once preferred.  
4. Open App only:
   - Window drags / minimizes / paints  
   - **No** “Not Responding”  
   - Local network (non-tunnel) works  

### B. First connect

1. Sign in, select server, Connect.  
2. Stage timers **must keep increasing** (not stuck at 0.0 s).  
3. Window remains interactive through Starting Kill Switch / Tunnel / Lock / DNS.  
4. Ends in **Connected**, or a **clear error** with Restore still available.  
5. Total first connect should finish inside **120 s** on healthy hardware; if longer, capture audit log + dump (do not spam Connect).

### C. Disconnect / failure injection

1. Disconnect → network restored; DNS not stuck on 127.0.0.1.  
2. Connect, then Disconnect mid-stage → no permanent blackhole.  
3. Quit while Connected → network restored or clearly fail-closed with recoverable Restore.  
4. Optional: disable NIC / sleep-wake once while Connected → Protected Offline + auto reconnect or clear error.

### D. If it freezes again

**Do not reconnect repeatedly.** Collect:

- Task Manager → Tono.exe → **Create dump file**  
- `%AppData%\com.raydocs.tono\tono\logs\traffic-audit.jsonl`  
- Screenshot of stage + seconds  
- Service binary version / protocol revision  

Thread stacks / Wait Chain Analysis beat screenshot guessing.

---

## 9. Architecture direction (after Test 6 is green)

Priority order for “smaller + faster + fewer freezes”:

1. **Keep Service actor model**: one writer, many snapshot readers (already half-done).  
2. **Collapse dual StartClash** for DIRECT into permit update + staged runtime rewrite without full TUN recreate when possible.  
3. **Delete dead Clash Verge UI/deps** (Monaco, old pages, unused plugins) after Tono settings fully cover needed toggles — biggest size win after single Mihomo.  
4. **Keep Mihomo as the data plane** until there is a product reason to replace it; Service (~3 MB) is not the size problem.  
5. **Never block Tao UI thread** on Service or vault I/O (already the rule).

---

## 10. Final gate answer

| Question | Answer |
| --- | --- |
| Are there more system bugs? | Yes — residual device risks R1–R6; source no longer has the known freeze classes of Test 5. |
| Is current source safer than Test 5? | **Yes.** |
| Can the user install something *now* and trust it? | **No.** Need a **Test 6** build from this source with packaging gates. |
| Should user re-test Test 5? | **Absolutely not.** |
| Is a full Rust rewrite needed to stop freezes? | **No.** |

**Next step for release owner:** commit → clean tag → Windows release build → payload SHA audit → publish Test 6 → then the user runs §8 only.
