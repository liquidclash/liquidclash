# Tono Windows 全量代码审计与卡死治理报告

审计日期：2026-08-02  
审计对象：`/Users/rw/Downloads/Project/liquidclash/tono-win`  
代码快照：`main` / `59737f5959907e3a5446144fa6cd95ea2e881774`  
报告性质：只读静态审计、构建与测试；未修改 `tono-win` 源码

> 重要边界：审计时工作区正在被另一位程序员修改，共有 67 个状态项；其中 59 个已跟踪文件的差异为 `+1465/-477`，另有 8 个未跟踪项。因此本文针对的是 2026-08-02 的工作树快照，而不是一个干净、稳定的提交。建议先把对方正在复现的版本做成临时提交或 tag，再按本报告逐项修复和回归。

## 1. 结论摘要

Tono 的关键底层实际上已经是 Rust：Tauri 主进程、LocalSystem Windows Service、WFP/DNS 控制和产品状态机都是 Rust；真正的数据面 Mihomo 是 Go 二进制，UI 是 React + WebView2。当前“卡死、慢、偶发无响应”的主要根因并不是 Rust 使用得不够，而是以下几类控制流问题叠加：

1. 连接流程把“单次最长 6 秒或 65 秒”的调用放进 40/50 次循环，导致注释中的秒级预算在极端情况下膨胀到数分钟乃至约 54 分钟；DNS 验证还没有明确 deadline。
2. Service 用一把全局生命周期锁包住完整操作，连只读状态查询也要排队；只要启动、停止、DNS 或进程回收卡住，整个控制面就像死机。
3. Mihomo 停止、watchdog join、`tasklist`/`taskkill` 没有完整的 OS 级 deadline，并且同步 shell 命令运行在 async 路径中。
4. 退出路径重复执行 Kill Switch release，并在 Tauri/Tao 事件循环中同步等待无总时限的清理。
5. WFP 状态查询存在旧快照竞态；“未 verified 的持久化意图在 Service 重启时自动解除 WFP”的新逻辑与 README 的 fail-closed 契约冲突。
6. 云策略 DIRECT 逻辑在 TUN 启动以后再探测物理网卡，且网卡名只允许 ASCII；策略和 WFP permit 又有静默截断不一致，都会表现为选择性断网或连接失败。
7. 前端首次渲染前等待无时限 IPC、全局加载大量旧 Clash 数据、WebSocket 有一个不再重连的异常分支，再叠加全屏模糊效果，造成白屏、假死和卡顿。
8. 安装包小不下来的首要原因是遗留 Clash Verge 代码和依赖仍被打包，以及同时携带两个各约 45 MB 的 Mihomo；不是 Rust Service（它只有约 2.7 MB）。

总建议：不要马上重写整个应用，也不要重写 Mihomo。先治理 deadline、锁、进程所有权和 WFP 状态机；随后删除遗留功能与依赖。只有在完成这些工作并用 ETW/WebView2 性能数据证明 UI 仍是瓶颈后，才值得评估 Slint/Iced/WinUI 3 等原生 UI。

## 2. 当前架构与体积画像

```text
React UI / WebView2
        │ Tauri invoke / events
        ▼
Tauri Rust 主进程（产品状态机、API、会话、连接编排）
        │ 本机鉴权 IPC
        ▼
TonoService.exe / LocalSystem / Rust
        ├── WFP fail-closed 与受保护 DNS
        └── Mihomo 生命周期和运行时配置
                 │
                 ▼
          Mihomo / Go sidecar + WinTUN
```

审计范围内共约 461 个 Rust/TypeScript/TSX 文件、121,363 行代码（排除 `target`、`node_modules` 和 `dist`）。当前产物画像：

| 产物 | 当前大小 | 观察 |
|---|---:|---|
| `Tono.exe` | 约 47 MB | release profile 保留符号，且编译了大量遗留依赖 |
| `TonoService.exe` | 约 2.7 MB | 已经很小，证明 Rust 不是体积主因 |
| Mihomo stable | 约 45 MB | 必要数据面候选 |
| Mihomo alpha | 约 45 MB | 与 stable 同时打包；若产品不可选则是直接浪费 |
| 前端 `dist` | 约 18 MB / 245 个文件 | 当前只有 5 个 Tono 页面，但仍带 Monaco 等旧功能 |
| NSIS 安装器 | 约 34 MB | 压缩后大小；安装后双 sidecar 和前端资源更明显 |

一次干净的诊断构建转换了 13,451 个前端模块。最大资源包括：

- TypeScript worker：约 6.6 MB
- Monaco editor API：约 3.5 MB
- Twemoji 字体：约 1.4 MB
- YAML/CSS/HTML/JSON worker：合计约 3.1 MB
- 主 JS：约 756 KB

当前路由只暴露 Dashboard、Servers、Account、Settings 和 Login（`app/src/pages/_navigation.tsx:26-63`）。Monaco 被带入的重要线索是 `main.tsx` 和 `tono-layout.tsx` 从 `components/base/index.ts` 桶文件导入 `BaseErrorBoundary`，而该桶同时重新导出 `MonacoEditor`（`app/src/components/base/index.ts:3,12`）。先改为直接导入并删除未使用导出，通常就能避免整条编辑器资源链进入构建。

## 3. 风险分级

| 等级 | 定义 |
|---|---|
| P0 | 可造成长时间卡死、fail-open/fail-closed 契约破坏、无法可靠退出或核心数据面错误；发布前必须解决 |
| P1 | 高频功能故障、假死、明显卡顿、错误状态或难恢复问题；应在下一个稳定版本解决 |
| P2 | 体积、攻击面、维护性和长期性能债务；在 P0/P1 稳定后清理 |

## 4. P0：卡死与数据面问题

### P0-01 连接事务没有单一绝对 deadline，重试预算被调用内超时放大

证据：

- `app/src-tauri/src/tono/connection.rs:47-55` 定义 controller 40 次、Kill Switch 50 次、验证 3 次。
- controller client 单次请求总超时为 6 秒（`:1266-1271`），但 `wait_controller` 连续调用 40 次（`:1274-1287`）。其注释写“≤ 40 × 250 ms”，实际上 250 ms 只是每次请求后的 sleep。
- Kill Switch 单次生命周期调用预算为 65 秒（`service/src/client/mod.rs:39-46`），又在 `lock_kill_switch_with_retries` 中执行 50 次（`connection.rs:1290-1303`）。注释仍写“≤ 20 × 100 ms”，与常量完全不一致。
- `verify_fake_ip` 使用 `tokio::net::lookup_host`，没有显式或事务级 timeout（`:1305-1322`）。Windows DNS 异常时可能长期等待。
- 云策略会重启 core，然后再次执行 controller wait 和 Kill Switch lock（`:1466-1475`）。

理论最坏值不是正常耗时，但它揭示了为何异常机器会“像彻底卡死”：

| 阶段 | 理论上界 |
|---|---:|
| controller readiness | `40 × (6 s + 0.25 s)` ≈ 250 s |
| Kill Switch lock | `50 × (65 s + 0.2 s)` ≈ 3,260 s，即 54 分 20 秒 |
| exit probe | `3 × (6 s + 0.5 s)` ≈ 19.5 s |
| fake-IP DNS | 当前无明确上界 |

通常 connection-refused 会很快返回，因此用户不一定每次都等到理论上界；但遇到半开 socket、Service 排队、DNS 卡住或系统工具挂起时，调用内 timeout 会真实放大。

修复：

1. 为整个 connect transaction 建立一个 `tokio::time::Instant` 绝对 deadline，建议交互预算先定为 30–45 秒，再由产品确认。
2. 每个阶段从同一个剩余预算中取时间，而不是各自重新获得完整预算。
3. readiness 单次尝试使用 300–800 ms connect/read timeout；生命周期调用不能在外层再做 50 次 65 秒重试。
4. 将 DNS lookup 包在 `timeout_at(deadline, ...)` 中。
5. 使用 `CancellationToken`；Disconnect、切换节点和 Quit 必须立刻取消未完成的连接阶段。
6. 每个阶段记录 `operation_id`、开始/结束时间、剩余预算、最后错误和取消原因。

验收：任何连接失败都必须在产品定义的总预算内回到可操作 UI，Disconnect 在 1 秒内使旧事务停止推进，日志能指出最后停留阶段。

### P0-02 Service 的全局生命周期锁造成队头阻塞

证据：

- `service/src/core/server.rs:1399` 的 `OWNER_LIFECYCLE_LOCK` 是一把进程级全局 mutex。
- `enter_owner_lifecycle` 返回 guard，让调用方在整个 handler 生命周期持锁（`:647-670`）。
- 聚合状态、Kill Switch 状态和 DNS 状态等只读路由也获取该锁（`:685-702`、`:717-732`、`:892-906`）。
- Service handler 预算为 60 秒（`:53,537`）；客户端 mutation 预算 65 秒、status 预算 5 秒。

影响：任一 Start/Stop、DNS 操作或进程回收变慢时，状态查询也无法返回。前端于是同时失去进度、取消反馈和诊断信息，看起来就是整个应用卡死。客户端 timeout 只停止等待，不能证明服务端 handler 已经被取消；随后重试还可能与旧操作重叠。

修复架构：

- mutation 进入单线程 actor/command queue，返回 `operation_id`；同一 owner/session 的幂等请求复用结果。
- 只读状态从不可变快照读取，例如 `ArcSwap<ServiceSnapshot>` 或 `watch::Receiver`，绝不等待 mutation 锁。
- 每个 mutation 有服务端 deadline、generation 和最终状态；超时后服务端自己终止操作，而不是只让客户端放弃。
- `/status` 暴露当前阶段、开始时间、deadline、PID、WFP generation、DNS generation 和最后一次错误。

### P0-03 core 停止与 watchdog join 无硬上界

证据：

- `service/src/core/manager.rs:399-415` 的 `stop_core` 等待 `stop_watchdog`。
- `stop_watchdog` 在 `:669-677` 直接等待 JoinHandle，没有 timeout。
- `kill_now` 在 `:82-93` 等待 `tokio::process::Child::kill()`，也没有 timeout。
- 这些调用可发生在持有全局生命周期锁的 handler 中。

修复：

1. Windows 上将 Mihomo 放入独立 Job Object，设置 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`，避免依赖进程树 shell 工具。
2. 用 `TerminateJobObject` + `WaitForSingleObject`，设 2–5 秒严格 deadline。
3. 超时后把进程标记为 `zombie/fatal` 并释放控制面；状态查询必须仍然可用。
4. 保存 PID 时同时保存进程创建时间或持有 process handle，防止 PID 重用误杀。
5. watchdog join 超时后 abort task，并记录结构化 dump，而不是无限等待。

### P0-04 Windows 进程管理在 async 路径调用同步 `tasklist`/`taskkill`

证据：

- `service/src/core/process.rs:166-176` 每次存活检查启动同步 `tasklist`。
- `terminate_process` 在 `:211-227` 同步执行 `taskkill`，随后最多再启动 20 次 `tasklist`。
- shell 命令本身没有 deadline；它们会阻塞 Tokio worker。

修复：使用 Win32 `OpenProcess`、`GetExitCodeProcess`/`WaitForSingleObject` 和 Job Object。仍需执行阻塞 API 时放入 `spawn_blocking`，并由外层 deadline 控制。这样同时减少延迟、进程创建开销和本地化输出解析风险。

### P0-05 Quit 释放执行两次，并同步阻塞 UI 事件循环

证据：

- `app/src-tauri/src/lib.rs:499-515` 的 `ExitRequested` 先调用 `quit_release`，随后调用 `feat::quit`。
- `feat::quit` 又在 `app/src-tauri/src/feat/window.rs:112-124` 调用一次 `quit_release`。
- 单次 `quit_release` 虽有 2.5 秒预算（`commands.rs:897-931`），两次会重复消耗预算。
- 随后的 `clean_async` 等待 `CoreManager::stop_core()` 完成，没有总 timeout（`window.rs:145-171`）。
- 整条链运行在 `AsyncHandler::block_on` 中，阻塞 Tao/Tauri 事件循环（`lib.rs:506-515`）；`RunEvent::Exit` 也使用 `block_on`。

修复：建立唯一的、幂等 single-flight `ShutdownCoordinator`。所有退出入口只提交一次关闭请求，由后台 runtime 执行：

```text
Requested → ReleasingProtection → StoppingCore → FlushingAudit → Committed/Cancelled
```

整个流程只有一个 3–5 秒绝对 deadline；事件循环只负责阻止默认退出和显示状态，不能等待清理 future。到期后应按明确安全策略结束，并准确展示“仍 fail-closed”或“已释放”，不能无响应。

### P0-06 WFP status 使用加锁前的旧快照

证据：`service/src/core/windows_kill_switch.rs:818-844` 先复制 `ARMED`，随后才等待 `WFP_OPERATION`。等待期间另一个任务可 arm、disarm 或换 owner；取得锁以后仍然验证并返回旧 `armed` 的 wanted、verified、mode、endpoints。

影响：UI 可能显示错误保护状态，恢复/退出路径也可能基于错误状态采取动作。

修复：先获取 `WFP_OPERATION` 再读取 `ARMED`；更好的方案是用带递增 generation 的不可变快照，WFP verify 结果也按 generation 缓存。若 verify 前后 generation 变化则丢弃结果并重试一次。

### P0-07 “未验证意图自动放行”与 fail-closed 契约冲突

证据：

- README 的连接事务说明：第 3 步原子持久化 protection intent；此后任何失败保留 WFP，只有显式 Disconnect、Sign Out 或 Quit 才释放（`README.md:179-203`）。
- 但 `restore_on_service_start` 对 `!intent.is_verified()` 先恢复 DNS、移除所有 WFP、retire owner 并删除 intent（`service/src/core/windows_kill_switch.rs:559-595`）。
- connect 只有在后续探测通过后才 mark verified；在“core 已启动但尚未 verified”的窗口里 Service 崩溃并重启，会走自动解除路径。

这是确定的代码/契约不一致；“存活的 Mihomo/TUN 是否会在该窗口形成实际 fail-open”需要 Windows 真机故障注入确认。当前代码片段在 disarm 前没有先证明记录的 core 已终止。

必须由产品与安全负责人明确二选一：

- 推荐：继续遵守现有 README，intent 一旦持久化就 fail-closed，直到显式释放。
- 若业务决定未 verified 的启动残留应自动放行：必须先通过 Job Object 或 PID+creation-time 强制终止并确认 core/TUN 已消失，再恢复 DNS、解除 WFP；同时修改 README、测试手册、UI 文案和恢复测试。

无论选择哪一种，都要对连接事务的每个步骤做 crash injection，重启 Service 后验证 WFP、DNS、core PID 和 UI 状态的一致性。

### P0-08 云策略 DIRECT 的物理网卡探测时机和名称校验错误

证据：

- 首次 core/TUN 启动并加锁后才进入 `apply_cloud_policy`（`connection.rs:325-360`）。
- `apply_cloud_policy` 在此时调用 `GetBestRoute2(8.8.8.8)` 探测“物理接口”（`:1410-1413,1676-1717`）。TUN/default route 已存在时，它很可能返回 Tono 接口，随后被校验器拒绝。代码自己也注明该 Windows 路径尚未在当前开发机验证。
- `DirectPlan::validate_physical_interface` 只允许 ASCII `[A-Za-z0-9 _-]`（`crates/tono-core/src/config.rs:67-85`），中文、日文等本地化网卡名会被确定拒绝。

修复：在启动 TUN 前捕获物理接口 LUID/index，并贯穿整个 connection generation；不要把易变的显示名称当身份。Mihomo 配置确需 alias 时再从稳定 LUID 解析，并允许经过长度/控制字符校验的 Unicode 名称。必须测试中文 Windows、Wi-Fi/Ethernet 同时存在、VPN 共存、网络切换和 metric 变化。

### P0-09 DIRECT plan 与 WFP permits 静默不一致

证据：`build_direct_plan` 保留完整的 `hosts` 和规则，却仅对 WFP direct endpoint 集合执行 `.take(256)`（`connection.rs:1612-1636`），没有报错或同步裁剪 plan。

影响：Mihomo 可以把第 257 个及之后的 tuple 路由为 DIRECT，但 WFP 没有对应 permit，表现为少数域名/媒体连接永久超时，非常难复现和定位。

修复：从一个经过校验的 canonical tuple set 同时生成 plan 与 WFP permits。超过上限必须明确拒绝连接或由服务端按可证明等价的规则压缩，绝不能静默截断。新增 `>256` 的单元测试和端到端策略测试。

## 5. P1：前端假死、状态与体验问题

### P1-01 首屏渲染被无时限 IPC 阻塞

`app/src/main.tsx:67-72` 在首次 `createRoot().render()` 前等待 `preloadAppData`；后者等待 `getVergeConfig` 和语言初始化（`app/src/services/preload.ts:48-58,97-105`），没有 deadline。如果 Tauri command、配置锁或文件系统卡住，窗口只显示空白，用户会判断为死机。

修复：立即渲染最小 shell，用系统主题和缓存语言启动；配置异步加载，1–2 秒后降级并显示“重试/复制诊断”。任何初始化错误都必须有可见页面。

### P1-02 全局遗留 AppDataProvider 在所有 Tono 页面持续轮询

`main.tsx:56-58` 对所有路由挂载 `AppDataProvider`。该 provider 不论登录或连接状态，都查询 runtime、proxy view、base config、rule providers、rules、system proxy、run state、uptime；proxy view 和 uptime 每 3 秒刷新，并订阅旧 Verge 事件（`app/src/providers/app-data-provider.tsx:52-176`）。

影响：未登录/断开状态仍持续触碰 Mihomo 和遗留命令；当 controller 或 service 异常时，它会放大错误、重试和渲染负载。

修复：为 Tono 新建最小 provider，只提供 account/catalog/connection snapshot；仅在 `Connected` 时启用必要 query。旧 Clash 诊断数据按页面 lazy-load，不挂在应用根部。

### P1-03 WebSocket 初始化异常后会进入“有 ws、无 listener、也不重连”的状态

`app/src/hooks/use-mihomo-ws-subscription.ts:89-128` 在 `entry.ws = ws` 后先 `await owner.onConnected(ws)`，最后才注册 listener。如果 `onConnected` 抛错，catch 只在 `!entry.ws` 时安排重连；此时 `entry.ws` 已非空，因此既没有 listener，也不会 reconnect。切换 owner 时 `void nextOwner.onConnected(...)` 的 rejection 也未处理（`:325-337`）。

修复：连接过程必须事务化。先注册 listener；任何初始化异常都要清空 `entry.ws`、关闭 socket、记录错误并按有抖动的 backoff 重连。对 owner handoff 的 promise 显式 catch。

### P1-04 固定 7890/9090 端口会把端口冲突变成长等待

`crates/tono-core/src/config.rs:15-16` 固定 mixed port 7890、controller 9090；Tauri 又硬编码 controller URL（`connection.rs:41`）。另一代理、旧进程或双开会导致 core 启动失败，然后进入 P0-01 的长 readiness 重试。

修复：每个 session 启动前预留随机 loopback 端口并通过 runtime/service 返回；状态中记录端口和 owner PID。若端口被占，立即报告占用 PID并 fail fast。若 Mihomo 将来支持 Windows named pipe，可进一步消除 controller TCP 暴露面。

### P1-05 单一 `TonoState` mutex 使无关操作互相等待

`app/src-tauri/src/tono/state.rs:195-201` 将整个 `TonoInner` 放在一个 `tokio::Mutex` 中，Tono 模块当前约有 84 个 `state.lock().await` 调用。代码注释声称 I/O 和 emit 前会释放锁，但实际多处在锁内 emit，部分路径还跨 await。严格 Clippy 也多次报告 `significant_drop_tightening`。

修复：

- UI 可读状态使用 `ArcSwap`/`watch` 不可变 snapshot。
- account、catalog、policy、connection operation 分离所有权，不共享一把大锁。
- 长操作采用“两阶段提交”：锁内取得 generation 和输入，锁外 I/O，锁内验证 generation 后提交。
- 事件统一在解锁后发送。

### P1-06 restore session 是高复杂度长事务，缺少总预算和阶段 UI

`restore_session` 从 `commands.rs:627-825` 串联 Service status、credential、`me()`、catalog 和 policy sync。严格 Clippy 给出 cognitive complexity 51/25。Service status 可等 5 秒，API 层还有自身重试，UI 可能长时间停在 Restoring；account 又在 catalog/policy 同步前先变成 Ready。

修复：拆成显式阶段和可取消 task；账户、缓存目录和云刷新分别有 deadline。允许先显示缓存/离线状态，再后台刷新。UI 必须展示当前阶段和重试按钮。

### P1-07 “测试当前服务器”按钮没有执行测试

`app/src/pages/tono/servers.tsx:51-61` 只等待 400 ms 后重读已有 latency history，注释也承认没有 backend test command。这是明确的功能欺骗，会让用户以为一次失败探测被重新验证。

修复：在实现有 3–5 秒 deadline、operation id 和取消能力的真实探测前禁用该按钮，或明确标注“显示缓存延迟”。

### P1-08 WebView2 大面积 backdrop blur 容易造成 GPU/软件回退卡顿

`MeshBackground` 对全窗口使用 `blur(40px) saturate(1.8)`；`GlassCard` 和 `ConnectPill` 使用 24 px backdrop blur，Servers 也有 20 px blur。低端 Intel GPU、RDP、虚拟机或 WebView2 软件回退时会触发大面积重复合成。

修复：把背景网格预合成为静态图片/渐变，卡片优先使用半透明实色；提供 reduced-effects 模式并尊重 `prefers-reduced-motion`。用 WebView2 DevTools/ETW 在 RDP、VM 和低端机验证 95 分位帧时间，而不是凭视觉调整。

## 6. P2：体积、攻击面和维护成本

### P2-01 遗留 Clash Verge 前后端远大于当前产品需要

静态未使用分析结果：137 个未使用文件、16 个未使用生产依赖、2 个未使用开发依赖、112 个未使用导出。遗留 Home/Profiles/Proxy/Rules/Logs/Advanced Settings 等页面虽不在路由中，仍有桶导出、命令和依赖把资源带入产物。

建议按“从入口向内”删除，而不是只让 tree-shaking 猜测：

1. 将 `BaseErrorBoundary` 改成直接文件导入，断开 Monaco 桶导出。
2. 删除未路由页面及其 hooks、services、contexts、locales 和测试。
3. 删除对应 Tauri commands 和 Rust modules。
4. 再移除 `package.json`/Cargo 依赖，逐步跑测试。
5. 每批提交记录 `dist`、`Tono.exe`、安装大小和冷启动时间差值。

### P2-02 同时打包 stable 和 alpha Mihomo

`app/src-tauri/tauri.conf.json:16` 同时列出两个 sidecar，各约 45 MB。如果 Tono 产品没有让用户选择 alpha core，应只保留经过 SHA-256 验证的 stable 版本。若确需灰度，alpha 应由受签名清单按需下载，不应默认进入每个安装包。

不建议用 Rust 重写 Mihomo：它涉及协议、TUN、DNS、路由、规则和长期安全维护，重写风险远高于约 45 MB 的收益。Tono 的差异化价值是安全控制面，不是重新实现代理内核。

### P2-03 Tauri 后端仍编译大量旧能力

`app/src-tauri/src/lib.rs:121-229` 注册 106 个命令，其中 Tono 专用约 17 个。`app/src-tauri/Cargo.toml` 仍包含 `boa_engine`、devtools、fs、shell、http、deep-link、clipboard、dialog、WebDAV/zip/crypto 等大批能力。release Tauri feature 还启用 `devtools`（`:49`）。

建议建立最小 Tono command allowlist，删除 profile/script/backup/updater/core selection 等旧模块，再让编译器指出可移除依赖。不要仅用 feature flag 隐藏前端入口而保留后端攻击面。

### P2-04 release profile 保留符号

`app/Cargo.toml:13-22` 当前 `panic = "unwind"`、`debug = 1`、`strip = "none"`。建议：

- 发布二进制 `strip = "symbols"`，PDB 独立归档到崩溃符号服务器。
- 只有确实依赖 `catch_unwind` 的边界才保留 unwind；否则可对正式包测量 `panic = "abort"`。
- `lto = "fat"`、`opt-level = "z"` 会影响构建时间或速度，只能通过 benchmark/体积对比决定，不能盲目开启。

### P2-05 Tauri capability 与 CSP 过宽

- `tauri.conf.json:42-49`：asset protocol scope 为通配，CSP 为 `null`。
- `capabilities/migrated.json`：文件读写 scope `**`，允许 shell execute/open/kill/spawn/stdin 和 process exit。
- `capabilities/desktop.json:17-21`：HTTP 允许任意 `http://*/*` 和 `https://*/*`。
- deep-link 仍支持旧 Clash scheme。

这不是卡死根因，但会显著扩大 WebView/XSS 或依赖被攻破后的影响。应设置严格 CSP，删除 wildcard asset/fs/http scope，去掉不需要的 shell/fs/http/deep-link plugin，仅保留 Tono API 域名和必要资源目录。

## 7. 哪些部分值得改成更原生的 Rust/Windows API

### 应立即原生化

| 当前实现 | 推荐实现 | 直接收益 |
|---|---|---|
| `tasklist`/`taskkill` | Win32 Process API + Job Object | 不阻塞 async worker、可设 deadline、可靠回收进程树 |
| 显示名称标识物理网卡 | LUID/ifIndex 作为稳定身份 | 避免本地化名称、改名和路由切换错误 |
| mutation 全局 mutex | Rust actor + `ArcSwap/watch` snapshot | 只读状态不再被长操作卡住 |
| 各层独立 timeout | Rust absolute deadline + CancellationToken | 保证总耗时上界和即时取消 |
| 分散退出逻辑 | Rust single-flight shutdown coordinator | 消除重复清理和 UI event loop 阻塞 |

### 可在稳定后评估

- Service IPC 从 loopback HTTP 迁移到 Windows named pipe，可减少端口/防火墙问题；但先修 handler 队列和 deadline，否则换传输层不会解决卡死。
- UI 若在删掉 Monaco、旧 provider 和高成本模糊后仍有明显 WebView2 CPU/GPU 问题，可做一个 Dashboard 的 Slint/Iced/WinUI 3 原型，以冷启动、内存、95 分位帧时间和开发成本作决策。

### 不建议现在做

- 不建议重写 Mihomo。
- 不建议把 React 全量重写成 Rust UI 作为第一阶段；这不会修复 Service 锁、WFP 竞态或无界进程停止，反而会制造一次大规模回归。

## 8. 已执行的验证

| 检查 | 结果 |
|---|---|
| 根 Rust workspace `cargo test --workspace --all-targets` | 150 个测试通过 |
| Service `cargo test --all-features --all-targets` | 158 个 unit 加 bin/integration/reliability 测试通过 |
| Tauri `cargo test --lib` | 385 个测试通过 |
| 前端 TypeScript | `tsc --noEmit` 通过 |
| 前端 Vitest | 12 个文件、83 个测试通过 |
| `git diff --check` | 通过 |
| core/service 严格 Clippy | `-D warnings` 通过 |
| Tauri 严格 Clippy，固定项目 Rust/Clippy 1.95 | 失败，共 92 个 lint error |
| app Windows xwin check | 通过 |
| Service Windows xwin check，all features | 通过；仅一个 dead-code warning |
| 干净前端诊断构建 | 成功；18 MB、245 个文件 |
| Knip 未使用分析 | 137 文件、16 dependencies、2 devDependencies、112 exports |

Tauri 的 92 项 Clippy 并不等于 92 个运行时 bug，许多是风格项；但其中多处 `significant_drop_tightening`、`restore_session` complexity 51/25、`network_monitor_loop` complexity 27/25，以及参数过多/遗留 async stub，是共享状态与职责过大的可信信号。

所有现有测试通过仍不能推翻本报告：当前最大的风险位于 timeout 组合、真实 Windows WFP/DNS、进程退出、TUN 路由和 UI event loop，这些并没有被 Linux/macOS 开发机上的 mock/unit tests 覆盖。xwin 只证明 Windows 目标能编译，不证明 WFP/WinTUN/PowerShell/多网卡运行正确。

## 9. 给正在复现的程序员的故障注入矩阵

每个场景都应记录同一个 `operation_id`，至少保存 Tauri log、Service log、Windows Event Log、当前 WFP filters、DNS adapter 配置、Mihomo PID/creation time、controller 端口和 UI 最后阶段。建议先用 VM checkpoint，避免测试中的 fail-closed 状态影响日常机器。

| 场景 | 注入点 | 当前风险/观察 | 修复后期望 |
|---|---|---|---|
| Service handler 排队 | Start/Stop 内人为延迟 70 秒，同时轮询 `/status` | status 5 秒超时，UI 假死 | status <200 ms，显示正在执行的 operation |
| Mihomo 不响应退出 | 让 child wait/kill 阻塞 | watchdog join 或 kill 无上界 | 2–5 秒内 Job Object 终止或进入 fatal 状态 |
| 半开 9090 | 占用端口但不回 HTTP | controller wait 可接近 250 秒 | 端口占用立即报错，总 connect 在预算内结束 |
| DNS resolver 卡住 | 在 protected DNS 后让 lookup 不返回 | fake-IP verify 无明确上界 | deadline 到期，保留正确 fail-closed 状态并可取消 |
| Quit during connect | 每个 connect 阶段触发 Quit | 重复 release、event loop 阻塞 | 单一 shutdown operation，窗口仍响应 |
| Service crash after intent persist | 在每个事务边界强杀 Service | 未 verified 分支可能解除 WFP | 行为严格符合选定安全契约 |
| status/disarm 并发 | status 在等待 `WFP_OPERATION` 时 disarm/arm | 可能返回旧 snapshot | generation 一致，不报告旧 owner/mode |
| 中文网卡名 | 网卡别名设为“以太网” | DIRECT 校验确定失败 | 以 LUID 识别并成功生成配置 |
| TUN 后 route detection | TUN 默认路由已生效再探测 | 可能得到 Tono adapter | 复用 TUN 前捕获的物理 LUID |
| DIRECT 257+ tuples | 云策略生成超过 256 个 permit | plan 与 WFP 静默不一致 | 明确拒绝或一致压缩，无选择性 hang |
| `onConnected` 抛错 | WebSocket 建立后初始化抛异常 | 有 ws、无 listener、无 reconnect | close/clear 后自动重连并展示状态 |
| 配置 IPC 不返回 | 启动时挂起 `getVergeConfig` | 空白窗口 | 1–2 秒内显示可操作 fallback UI |
| RDP/软件渲染 | 开启 Dashboard 动画和 blur | 帧率下降/输入滞后 | reduced-effects 下 95p 帧时间达标 |

建议增加可控 fault-injection feature，而不是靠随机断网：例如 `TONO_FAULT_STAGE=after_intent_persist`、`hang_core_stop`、`fail_owner_status`。只允许测试构建启用，并把注入点写入审计日志。

## 10. 分阶段执行路线

### 阶段 A：先让卡死可观测、可取消、有限时

1. 给 connect、disconnect、restore、quit 建立 operation id 和统一绝对 deadline。
2. UI 立即显示当前阶段、已耗时、取消和复制诊断按钮。
3. status 改成不等待 lifecycle mutation 的 snapshot。
4. 建立上述故障注入点和 Windows VM 自动测试。

退出条件：任何故障都能在定义预算内结束或明确进入 Protected Offline；UI 不再无反馈。

### 阶段 B：修 P0 控制面和安全状态机

1. Service actor 化；移除全局 read/write 共用锁。
2. Job Object 接管 Mihomo；删除 `tasklist`/`taskkill` 主路径。
3. 合并 Quit 为 single-flight coordinator。
4. 修 WFP status generation 竞态。
5. 明确并实现未 verified intent 的唯一安全契约。
6. DIRECT 使用 pre-TUN LUID，统一 tuple cap。

退出条件：故障注入矩阵全部通过；连接、断开、退出有严格上界；Service crash 后 WFP/DNS/core 三者一致。

### 阶段 C：移除前端假死和后台噪音

1. 首屏立即 render，初始化有 fallback。
2. 修 WebSocket reconnect 状态机。
3. 移除全局遗留 AppDataProvider。
4. 动态端口和真实 latency probe。
5. 低特效模式与低端 Windows 性能基线。

### 阶段 D：缩小二进制和攻击面

1. 删除 Monaco 桶导出和 137 个未使用文件链。
2. 删除 89 个左右非 Tono Tauri commands 及其 Rust/JS 依赖。
3. 默认只打包 stable Mihomo。
4. strip release symbols、外置 PDB。
5. 收紧 CSP、capabilities、URL 和文件 scope。

建议每一阶段都做独立、小范围提交；不要把状态机修复、UI 重写和依赖大删除合在一个 PR 中，否则无法可靠 bisect。

## 11. 发布验收指标

以下数字应在团队确认后写入 CI/发布门槛；它们比“感觉不卡”可验证：

- 冷启动到可交互 shell：95p < 1.0 s；配置异常时 < 2.0 s 显示 fallback。
- `/status`：mutation 正在执行时仍 95p < 200 ms。
- Cancel/Disconnect：提交后 < 1 s 阻止旧连接事务继续推进。
- Connect：成功和失败均有统一总 deadline，绝不超过产品预算。
- Quit：正常 < 3 s；异常 < 5 s 给出明确最终保护状态。
- Service/core crash recovery：WFP、DNS、PID 与 UI snapshot generation 一致。
- WebSocket：初始化异常后可自动恢复，不允许“socket 存在但无 listener”。
- UI：目标低端机/RDP 下输入无长任务，95p frame time 由实测门槛约束。
- 安装体积：先删除 alpha sidecar 与 Monaco/旧代码，再设目标；预期可获得明显双位数 MB 的安装后空间收益。

## 12. 已有值得保留的实现

审计并非说明底层全部需要推倒：

- Service client 已使用独立的两 worker IPC runtime（`service/src/client/mod.rs:30-37`），能避免普通 app runtime 被同步 Service IPC 完全占满。
- Windows DNS 当前实现已经把多个 adapter 合并到一次 PowerShell 批处理，有约 10 秒硬 timeout，并只重试失败项；这是正确方向。
- Service Rust release 约 2.7 MB，已有很好的体积基础。
- core/service/Tauri 的状态机与可靠性单元测试数量可观，所有现有测试通过。
- privileged installer 已避免用 `.output()` 等待继承管道导致的已知 hang，并有测试手册记录。
- WFP fail-closed 模型和 owner/session gate 的总体设计是合理的；问题主要在恢复语义、快照一致性和外围操作的 deadline。

## 13. 最终建议

优先级必须是：

```text
总 deadline/取消 → Service 状态快照与 actor → Job Object → Quit single-flight
→ WFP 恢复契约与 generation → DIRECT/LUID → 首屏/WebSocket/provider
→ 删除遗留代码和双 Mihomo → 再决定是否原生 UI
```

如果直接进行“全 Rust UI/重写代理内核”，当前最危险的锁、超时、进程回收和 WFP 竞态仍然存在，而且会新增大量回归。相反，上述 P0 改造都能在现有 Rust 架构中完成，既更小、更快，也真正针对卡死根因。
