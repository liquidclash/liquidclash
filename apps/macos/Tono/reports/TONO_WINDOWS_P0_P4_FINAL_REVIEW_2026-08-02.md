# Tono Windows P0–P4 完成复审与 Test 6 发布门报告

日期：2026-08-02  
审查对象：`/Users/rw/Downloads/Project/liquidclash/tono-win` 当前共享工作树  
结论范围：源码修复、静态并发复审、自动测试、Windows x64 交叉检查与 PE release 构建；不包含真实 Windows/WFP 运行结论

## 1. 执行结论

P0–P4 主线已经完成到“可作为 Test 6 源码候选”的程度。原审计中能够从代码证明的 UI runtime 饥饿、重试放大、退出重复释放、迟到 IPC 提交、WFP/DNS 恢复顺序、进程回收、固定 Controller 端口、首屏阻塞、WebSocket 不重连和主要体积问题均已处理。

最后一轮复审额外发现并修复了一个新的 P0 竞态：显式释放在 UI 侧超时后仍于后台继续时，用户若马上重新连接，旧释放可能在新连接提交后恢复 DNS、停止 Core 或解除新 WFP。现在所有 Disconnect、Sign Out、Quit 和启动对账共享一个可加入的 release operation；Connect 在释放对账结束前被拒绝，迟到的 StartClash/DNS 提交也必须先越过同一个读写屏障，因此旧释放不能再拆掉新连接。

当前结论分三层：

| 层级 | 结论 |
|---|---|
| 当前源码 | 可以作为新的 Test 6 候选基线 |
| 当前 Test 5 安装包 | 不能代表这些修复；不得继续当作最新代码验证 |
| 正式稳定版 | 尚不能放行；必须完成真实 Windows WFP/DNS/SCM/WinTUN/Job Object 故障注入 |

另有两个安装载荷问题：**Test 5 实包**曾同时包含 stable+alpha Mihomo 和约 4.8 MB Unix helpers。当前源码已将 `externalBin` 改为仅 stable、`resources` 改为 7 文件白名单，prebuild/portable/preflight/build 脚本均已强制；**仍缺真实 Test 6 NSIS 解包证据**。在解包门绿之前，不应发给用户测试。

## 2. 架构判断：不需要全面重写 Rust

Tono 的安全控制面已经是 Rust：Tauri 主进程、产品状态机、LocalSystem Service、WFP/DNS 控制、进程所有权和恢复逻辑都是 Rust。Mihomo 是成熟 Go 数据面，UI 是 React/WebView2。

本轮证明，卡死主因是并发边界和系统调用生命周期，而不是“Rust 用得不够”：

```text
React / WebView2
      │ 短 Tauri command + 状态事件
      ▼
Tauri Rust runtime（至少 4 worker）
      │ 独立 2-worker Service IPC runtime
      ▼
Rust LocalSystem Service（4 worker）
      ├── DNS / WFP / desired-state
      └── Win32 Job Object → Mihomo / WinTUN
```

正确方向是继续原生化 Windows 进程、路由、LUID、WFP 和可取消操作边界；不建议重写 Mihomo，也不建议在缺少 ETW/WebView2 数据时全面重写 UI。删掉遗留后端能力和不再路由的前端代码，比再换一种 UI 技术更直接地减小体积与攻击面。

## 3. P0 完成项：卡死、安全与竞态

### P0-01 UI runtime 与 Service IPC 隔离

- Tauri Tokio runtime 最少 4 个 worker，blocking pool 单独设置。
- 所有 Service IPC 在独立 2-worker runtime 执行，不占用 Tauri UI runtime。
- 读请求最多 2 次；写请求只发送 1 次，避免响应丢失后重放 Start/Stop/DNS/WFP mutation。
- status timeout 缩短；调用方 timeout/drop 不会取消已经发送的安全 mutation，其后台对账继续完成。

结果：Service pipe、SCM 或 WFP 慢时，窗口事件循环仍能处理绘制、拖动和最小化。

### P0-02 统一 Connect transaction

- 单次 Connect 使用 **120 秒**绝对 deadline（曾短暂为 45 秒，对冷启动双重 StartClash + DNS 过紧），而不是每个阶段重新取得完整预算。
- 使用 `CancellationToken`；Disconnect、Sign Out、Quit、节点切换与新 generation 会退休旧事务。
- bootstrap DNS、Controller readiness、fake-IP DNS、exit probe 均有独立短边界并受总 deadline 限制。
- `Starting Kill Switch` 使用真实开始时间，秒数持续增长。

### P0-03 新发现并修复：后台释放拆掉新连接

旧竞态：

```text
Disconnect → release IPC 已发送 → UI 2.5 s 超时
                                  ↓
用户再次 Connect → 新 Core/WFP 提交
                                  ↓
旧 release 迟到提交 → 拆掉新 Core/WFP/DNS
```

修复：

- `ReleaseOperation` 保存结果并唤醒所有 joiner；首个调用者超时不会产生第二个 release。
- `release_operation` 是 App 级 single-flight；Disconnect、Sign Out、Quit、恢复路径加入同一任务。
- Connect 的 guard 在 release 对账存在时明确拒绝重连。
- StartClash 和 DNS-enable 的 detached reconciliation 持读 guard；release 持写 guard，先等待所有迟到提交落定，再进入 Service。
- release worker 由 supervisor 监管；panic/JoinError 也会完成结果并清理 coordinator，不留下永久假 single-flight。
- Windows 只调用一次 Service owner-gated release，避免 App 在 DNS、Core、WFP 三个 IPC 之间被取消。

新增单元测试覆盖多个 joiner 同时等待以及结果重放；App 测试数增加到 387。

### P0-04 Windows 原子显式释放

Windows Service 的 owner-gated release 在同一个 lifecycle lock 内按以下顺序执行：

```text
证明并恢复 DNS
      ↓
验证 active Core owner
      ↓
停止 matching Core + retire durable desired state
      ↓
解除 WFP，并回读 wanted/live
```

任何 DNS 不确定、owner mismatch、Core 无法安全停止或 WFP 删除失败都会返回错误并保留更严格状态。交互式 Quit/Restart 在无法证明释放时取消退出；不可阻止的 `WM_ENDSESSION` 仍使用短预算并按 fail-closed 记录。

### P0-05 Service 状态不再排在 mutation 后面

- `/status`、Kill Switch status 等关键读路径不取得全局 lifecycle mutex。
- Core/DNS/WFP 使用 committed/cached snapshot；status 同时返回 `active_operation`、开始时间和观察 deadline。
- mutation 仍由单 writer lifecycle lock 串行化，避免并发修改系统网络状态。
- 集成测试故意让 proxy mutation 持锁，断言 `/status` 在 500 ms 内返回。

这消除了“一个 Service 操作慢，连状态查询也冻住”的主要假死链。`deadline_at_ms` 目前是诊断信息，不是 Service 强制取消机制；见第 8 节残余风险。

### P0-06 fail-closed 启动恢复

- 未验证 intent 启动时先安装/保持严格 Blocked WFP。
- 先完成旧 Core/desired owner 对账，再恢复 DNS。
- 只有 DNS 恢复有证据且 Core 已安全退休后才允许移除 WFP 与 intent。
- legacy 无 `owner_key` 记录的 matching desired owner 同步停用，防止下次启动复活旧 Core。
- verified session 继续 fail-closed；首次失败才走安全恢复。

### P0-07 原生 Win32 Core 生命周期

- 删除 Windows 主路径 `tasklist`/`taskkill`。
- 使用 `OpenProcess`、`WaitForSingleObject`、`TerminateProcess` 检查和回收 PID。
- 每个新 Mihomo 进入独立 Job Object，并设置 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`。
- direct-child 终止确认 3 秒，watchdog join 5 秒；超时 abort 后按 PID 再对账。
- Service 崩溃或 Job handle drop 会由 Windows 回收 Mihomo 进程树。

### P0-08 WFP、DIRECT 与物理网卡

- WFP status 在正确的同步边界读取，不再返回锁前旧副本。
- DIRECT runtime plan 与 WFP permits 使用同一 canonical endpoint set；超过 256 项明确拒绝，不再静默截断成选择性黑洞。
- 在 WinTUN 启动前调用 `GetBestRoute2`，再通过 `GetIfEntry2.Alias` 获取与 Service alias→LUID 一致的物理接口。
- Windows alias 接受合法 Unicode、括号和标点；拒绝控制字符、首尾空白、loopback/Tono 和超长 UTF-16。
- hostname WFP resolution 有上限，DNS restore 必须验证。

## 4. P1 完成项：功能、恢复与卡顿

| 项目 | 当前实现 |
|---|---|
| 首屏 | 先渲染 loading shell；preload 最多阻止 React 2 秒，慢任务后台完成 |
| 旧 Provider | Tono 根路由不再挂载全量 Clash `AppDataProvider` 轮询 |
| WebSocket | listener 先安装；onConnected、handoff、close 异常都会清理并重连 |
| Controller | 每次连接动态分配 loopback port；不再固定 9090 |
| mixed listener | Tono TUN-only，`mixed-port=0`，不再开放 7890 |
| DNS 53 | WFP 前同时预检 TCP/UDP `127.0.0.1:53`，冲突立即失败 |
| Restore | 30 秒绝对预算，账户/目录/策略阶段受同一 deadline 约束 |
| 节点测试 | 后端真实 probe，不再等待 400 ms 后读取历史值 |
| UI 特效 | 降低 blur/glow，并尊重 `prefers-reduced-motion` |
| Quit | 正常交互式退出异步运行，Tao 事件循环不再等待 release |

动态 Controller port 和 DNS 53 preflight 都存在“检查后、Mihomo bind 前被其他进程抢占”的窄 TOCTOU。Mihomo 当前没有 Windows inherited-FD 接口，无法完全消除；现在会受 **120 秒**总 deadline 限制并给出明确失败，不会无限卡住。

## 5. P2 完成项与剩余结构债务

### 已完成

- Windows `externalBin` 只配置 `sidecar/verge-mihomo`。
- Windows prebuild 跳过 alpha 下载，两个 portable 脚本只加入 stable。
- 生产 `dist` 不再包含 Monaco/editor worker 资产。
- `release` 使用 thin LTO、单 codegen unit、`strip="symbols"`；PDB 作为外部文件保留。
- CSP 禁止外部默认加载、object、base 和 framing；asset protocol 关闭。
- capabilities 缩小；deep-link、protocol-asset 和 release devtools feature 已去除。
- 旧启动 timer、hotkey、lightweight、backup、DNS init 和无关 refresh 不再进入 Tono 启动路径。

### 仍需单独删除

- Rust 仍注册约百个旧 Clash command，并编译 boa、zip、WebDAV、多个 Tauri plugin 等遗留能力。
- `package.json` 和旧页面源码仍保留 Monaco；tree-shaking 已使其不进入当前生产 `dist`，但源码/依赖尚未物理删除。
- `TonoInner` 仍是一把较大的产品 mutex；UI status 已改用快照、长 I/O 多数为两阶段，但完整 domain split 尚未完成。
- mutation 仍是全局 single-writer mutex，不是带 operation journal、优先级和补偿的 actor。

这些删除应在独立 clean commit 中逐组进行，避免在当前共享 dirty tree 中误删另一位程序员尚未迁移的功能。它们不是 Test 6 的已知卡死阻断项，但仍是稳定版前的体积、攻击面和维护债务。

## 6. P3：可观测性、回归与发布治理

- Service protocol revision 9，Service crate 2.6.2。
- status 暴露 active operation、operation id、started/deadline 和 committed subsystem snapshots。
- `traffic-audit.jsonl` 继续记录 connect/release/protected-offline/health 事件。
- StartClash、DNS-enable、release 都具有“调用方取消后继续对账”的明确语义。
- 新增 status-vs-mutation、release joiner、WFP/DNS 恢复、Job Object/进程、DIRECT 上限、动态端口、真实 probe 和前端 WebSocket 回归测试。
- 新增 clean tag、版本一致、installer/Mihomo hash 和 Manifest 对账的 release preflight。

发布治理（当前源码状态）：

- `pnpm release:preflight --config-only`：强制 stable-only externalBin + resources 白名单  
- `pnpm release:preflight <tag> <installer>`：7zz 解包检查 + 强制 `commit` 与 `service.sha256`（可用 `TONO_RELEASE_ALLOW_INCOMPLETE_MANIFEST=1` 本地干跑）  
- `build-windows-release.sh`：构建前 config-only、构建后 7zz smoke  

**仍未关闭的只有：** 真实 Test 6 NSIS 尚未构建，因此还没有解包绿勾与可发布 Manifest。

## 7. P4：验证和体积结果

### 自动测试与构建

| 检查 | 结果 |
|---|---:|
| Tono Core | 152/152 |
| Windows Service library | 160/160 |
| Service integration/bin/doc | 全部通过 |
| Tauri App Rust | 387/387 |
| 前端 Vitest | 85/85 |
| Cloudflare | 44/44（本轮未改动） |
| Service xwin all-features | 通过 |
| App xwin `x86_64-pc-windows-msvc` | 通过 |
| App release PE build | 通过 |
| Service release PE build | 通过 |
| 前端 TypeScript + production build | 通过 |
| 选定修改文件 `git diff --check` | 通过 |

最后一轮之后没有重新跑 strict Clippy：工作区执行额度已耗尽。此前 strict Clippy 基线通过，最新代码已通过相应 Rust tests、xwin check 和 release build；不能把它写成“最新 strict Clippy 已通过”。当前编译仅剩 3 个旧启动函数的 dead-code warning：`AutoBackupManager::init`、`auto_lightweight_boot`、`init_dns_config`。

### 体积

| 产物 | 旧值 | 当前值 | 变化 |
|---|---:|---:|---:|
| 前端 `dist` | 约 18 MB / 245 files | 3.0 MB / 139 files | 约 -83% / -43% |
| `Tono.exe` | 49,136,640 B | 46,789,120 B | -2,347,520 B（-4.78%） |
| `tono-service.exe` | — | 2,849,280 B | 已很小 |
| Windows Mihomo 配置 | stable + alpha | stable only | 安装后预计少约 47.3 MB |

当前本地、尚未打包的 PE：

- `Tono.exe` SHA-256：`e324b3d4df889789b75f7e4c96c8e77ced67f1cd4611a9ffa7981a3e2ea431ba`
- `tono-service.exe` SHA-256：`127bfba6f338bd49c158c8c2711b5e023e7f56bd8565450fa0af3b11319d623c`

这些是本地 PE，不是 Test 6 安装包 hash，不得用于发布页。

### Test 5 安装包的真实载荷

使用 7-Zip 读取现有 `Tono_2.5.4_x64-setup.exe`：

- 包内 `Tono.exe` 仍为旧的 49,136,640 B；不是当前 release PE。
- 同时含 `verge-mihomo.exe` 和 `verge-mihomo-alpha.exe`，各 47,288,832 B。
- 还含旧 `clash-verge-service` 三件套约 4.8 MB，以及 `set_dns.sh`/`unset_dns.sh`。
- 当前 `app/src-tauri/resources` 本身没有 alpha；alpha 来自旧 Tauri external-bin 构建清单。
- 当前配置已经只列 stable，但新 Test 6 包尚未生成，不能用配置代替解包证据。

## 8. 最终系统级复审后仍存在的风险

### S1 — WFP/BFE 与 DNS 系统调用没有可安全强杀的 handler deadline

WFP RPC 和部分 Windows DNS/CIM/registry 操作已放到 `spawn_blocking`，所以不会占住 Tauri UI runtime；但 `spawn_blocking` future 本身仍可能无限等 OS API。简单套 `tokio::timeout` 不安全，因为 timeout 后 blocking closure 仍会继续并可能迟到修改系统状态，而 lifecycle lock/operation marker 已被上层释放。

当前结果是：窗口和 status 应继续响应，但 mutation、Disconnect 或 release 可能长时间不完成，系统保持 fail-closed。生产级解决方案应把 WFP engine 放进可终止 helper process，或建立 Service actor + durable operation journal；真实 Windows dump/Wait Chain 用来判断 BFE RPC、CIM、SCM、WinTUN 中哪一个需要先隔离。

### S2 — mutation 不是完整 actor/journal

当前 single-writer lock 保证顺序，读状态已解锁，但没有：

- 可查询的 committed/failed/unknown operation journal；
- release/stop 高优先级队列；
- 服务端真正执行的 deadline/cancellation；
- Service 重启后继续查询同一 operation id。

因此 App 不能安全地在 mutation timeout 后假设“没有提交”。本轮用 detached reconciliation + owner-gated idempotency 解决当前路径，但长期仍应实现 actor/journal。

### S3 — status 是多来源诊断快照，不是完全线性化事务快照

Core、desired owner、WFP、DNS 和 operation 来自不同 committed cache/文件。它能在 mutation 时快速返回并说明当前 operation，但极窄竞态下可能短暂混合相邻 generation。任何破坏性动作仍必须由 Service 内 owner/session gate 和二次验证决定，不能只相信一次 UI status。后续可用 seqlock 式 generation-before/after 重读增强一致性。

### S4 — 端口与 OS 退出边界

- 动态 Controller port 在临时 listener 释放后仍有 TOCTOU；失败有总 deadline。
- DNS :53 preflight 也是 point-in-time；另一个进程仍可能在 Mihomo bind 前抢占。
- 正常 Quit/Restart 不阻塞 Tao；只有不可阻止的 `RunEvent::Exit/WM_ENDSESSION` 使用 bounded `block_on`。
- 交互式 `clean_async` 故意不粗暴 timeout core stop，因为取消后进程可能迟到退出；它运行在后台并在失败时取消退出。

### S5 — 遗留能力与 Windows 资源白名单

旧 command/plugin/source 仍增加编译体积与维护面。

**配置层（当前工作树，本轮已落地）：**  
`tauri.conf.json` 的 `bundle.resources` 已改为显式 Windows 白名单，不再是整目录 `resources`：

- `Country.mmdb`
- `geoip.dat`
- `geosite.dat`
- `enableLoopback.exe`
- `tono-service.exe`
- `tono-service-install.exe`
- `tono-service-uninstall.exe`

源码目录 `src-tauri/resources/` 仍可能保留跨平台/历史文件（Unix helpers、`set_dns.sh` 等）；**只收紧 bundle mapping，不删源码树**。  
`pnpm release:preflight --config-only` 与 `scripts/build-windows-release.sh` 在构建前会拒绝整目录打包和 alpha sidecar。

**载荷层（仍未关闭）：**  
必须对真实 Test 6 NSIS 执行 `7zz l` / preflight 解包核验。配置正确 ≠ 安装包已生成。

### S6 — 只能在真实 Windows 证明的路径

以下不能由 macOS xwin 或 mock tests 证明：

- WFP/BFE transaction 和 filter 持久性；
- DNS CIM/registry 对真实网卡、VPN、Hyper-V 的处理；
- `GetBestRoute2`/LUID/Alias 在中文与多网卡系统中的结果；
- WinTUN 创建/销毁、Job Object kill-on-close；
- SCM、UAC、sleep/wake、logoff/shutdown；
- WebView2/GPU 在低端机、RDP 与驱动异常下的帧时间。

## 9. Test 6 构建与发布硬门

在交给用户安装前，必须全部满足：

1. 把当前精确工作树整理到独立 clean commit；不要把共享树中无关 macOS/Cloudflare 修改混入。
2. tag 必须指向该 commit；从 clean worktree 构建，不再用 dirty source snapshot 代替发布提交。
3. 先构建 Service 三个 exe并复制到 resources，再构建 Tauri/NSIS。
4. Windows resources 改为白名单，不能打包旧 Unix Service/macOS scripts。  
   **当前源码状态：** `tauri.conf.json` 已是 7 文件白名单；`pnpm release:preflight --config-only`、`prebuild` 结束校验、portable 打包与 `scripts/build-windows-release.sh` 均强制/检查此项。  
   **仍缺：** 真实 Test 6 NSIS 的解包绿勾。
5. `7zz l -ba Tono_2.5.4_x64-setup.exe` 必须：
   - 有且只有一个 `verge-mihomo.exe`；
   - 完全没有 `verge-mihomo-alpha.exe`；
   - 只有白名单 Windows resources。  
   **自动化：** `pnpm release:preflight <tag> <installer>` 与 `build-windows-release.sh` 的 7zz smoke 已实现；需有 installer 后才跑全门。
6. 解包后核对 `Tono.exe`、三个 Service binary、Mihomo、图标和卸载器；hash 与构建输入一致。
7. Manifest 写入 source commit、toolchain、App/Service/Mihomo/Installer SHA、测试计数和 `windowsRealMachine=false`。  
   preflight 在字段存在时校验 `commit` / `service.sha256`；缺失时告警。
8. 使用新 tag `tono-windows-2.5.4-test6`；不得覆盖 Test 5；Test 4 继续标记 UNSAFE。
9. 发布前再跑最新 strict Clippy、Rust tests、front tests/build、Cloudflare tests 和 xwin release build。

## 10. 真实 Windows 测试矩阵

### A. 未连接基线

1. 重启 Windows，卸载 Test 4/5，安装 Test 6。
2. 只打开 App 60 秒：网络不变、窗口可拖动/最小化、Task Manager 不出现 Not Responding。
3. 记录空闲 CPU、内存、GPU、线程数和 Service status。

### B. 正常连接与释放

1. 第一次 Connect：所有阶段秒数增长，尤其 Starting Kill Switch；窗口全程可交互。
2. Connected 后真实 server probe、DNS、网页、Google/YouTube 和策略 DIRECT 均正确。
3. Disconnect：DNS/Core/WFP 最终全清，网络恢复。
4. Quit 与 Restart：只有一次 release；失败时退出被取消且 UI 仍响应。

### C. 专门验证本轮 P0 竞态

在以下每个阶段各做一次 Disconnect：Preparing Service、Starting Kill Switch、Starting Tunnel、Locking Traffic、Enabling DNS、Verifying。

每次在 UI 显示 release timeout/error 后立刻点 Connect：

- 新 Connect 必须返回“release still reconciling”，不能启动第二条事务；
- 后台 release 完成后状态自动刷新；
- 再次 Connect 才可开始；
- 旧 release 绝不能拆掉新连接。

同样测试 Sign Out、Quit、Restart 与 Disconnect 同时触发；所有入口必须加入同一 release。

### D. 故障注入

- 在 intent 持久化后、Core 启动后、DNS enable 后、mark verified 前后分别终止 Service并重启。
- Connected 后终止 Mihomo：应进入 Protected Offline/恢复，不得保持假绿色。
- 占用 TCP 53、UDP 53、Controller 候选端口；必须快速、明确失败。
- Service IPC 丢响应/延迟 3、10、60 秒；窗口仍响应，后台对账最终收敛。
- 模拟 WFP/BFE RPC 卡住；保存 Service dump 和 Wait Chain，不要连续点击。

### E. 系统环境

- 中文 Wi-Fi/Ethernet alias；Hyper-V `vEthernet (...)`；Wi-Fi+有线；另一 VPN 共存。
- 连接中切网、断网、sleep/wake、锁屏、logoff、Windows shutdown。
- 普通用户和管理员用户；安装/卸载/UAC 取消；升级同版本 Test 5→Test 6。
- 低端 GPU、RDP 和关闭动画偏好，记录窗口拖动与阶段刷新。

### F. 卡死资料

若仍出现 Not Responding，不要反复连接。立即保存：

- `Tono.exe` dump；
- `tono-service.exe` dump；
- Task Manager Wait Chain；
- `%APPDATA%\com.raydocs.tono\tono\logs\traffic-audit.jsonl`；
- Service 日志；
- 卡死时 UI、Task Manager、网络和 DNS/WFP 状态截图。

## 11. 最终判断

当前源码没有发现新的、可由现有静态路径直接证明且尚未处理的 UI `Not Responding` P0。新发现的 release-vs-reconnect P0 已修复，自动测试、Windows 交叉检查和本地 PE release 构建通过。

但当前还不是“直接安装测试”的最终产物：新 NSIS 尚未构建（配置与自动门禁已齐，缺解包证据）；真实 Windows 的 WFP/BFE、DNS/CIM、SCM、WinTUN 与 GPU 路径也尚无证据。完成第 9 节载荷门后，可以进入受控 Test 6 真机测试；完成第 10 节并无系统级失败后，才适合讨论稳定版放行。
