# Tono Windows Test 5 修复后复审与下一测试候选报告

> **后续更新：** 本报告第 5–9 节的待办状态已被同日的
> [`TONO_WINDOWS_P0_P4_FINAL_REVIEW_2026-08-02.md`](./TONO_WINDOWS_P0_P4_FINAL_REVIEW_2026-08-02.md)
> 取代。后续复审已完成统一 connect deadline、lock-free Service status、动态 Controller
> port、真实 latency probe、稳定版单 sidecar、strip/前端瘦身，并额外修复 release timeout
> 后快速重连会被旧 release 拆除的新 P0 竞态。现有 Test 5 安装包不包含这些后续修复。

日期：2026-08-02  
审查对象：`tono-win` 本地工作树、GitHub `tono-windows-2.5.4-test5` 发布物及其源码快照  
结论类型：源码修复、静态复审、单元/集成测试、Windows 交叉编译；尚未进行真实 Windows/WFP 运行验证

## 1. 结论

Test 5 对 `Starting Kill Switch` 导致 Tauri 窗口 `Not Responding` 的隔离方向是正确的：Service IPC 已离开 Tauri runtime，Tauri runtime 至少有 4 个 worker，前端超时/取消不会取消已经开始的安全对账任务，阶段耗时也会持续刷新。

复审仍找到并修复了 8 组会影响卡死、安全恢复或随机断网的问题：

1. 只读 IPC 的嵌套重试可把两个专用 worker 占用数分钟；现已限制为 2 次，写操作保持单次、不自动重放。
2. 未验证 Kill Switch 在 Service 启动时曾先忽略 DNS 恢复错误、再解除 WFP，而且发生在旧 Core 对账之前；现改为先保持 `Blocked`，Core 对账后才按“停用 desired owner → 证明 DNS 恢复 → 解除 WFP”的顺序清理。
3. 旧版无 `owner_key` 的未验证记录可能解除 WFP 后又在下次启动恢复 desired Core；现会同时持久化停用遗留 active owner。
4. WFP status 曾在取得操作锁前复制旧状态，可能返回过期快照；现已先串行化再取快照。
5. DIRECT 规则曾只截断 WFP permit、不截断 Mihomo plan，形成选择性黑洞；现超过 256 个唯一端点会明确拒绝连接。
6. DIRECT 的物理网卡曾在 WinTUN 启动后探测，并把内部 interface name 当 friendly alias；现改为 pre-TUN `GetBestRoute2 + GetIfEntry2.Alias`，同时允许合法 Unicode Windows alias。
7. Windows Mihomo 回收仍依赖同步 `tasklist/taskkill`，watchdog join 无硬上界；现改为 Win32 Process API、kill-on-close Job Object、3 秒进程确认和 5 秒 watchdog join 上界。
8. Quit 双重 release、Tao 事件循环同步等待、首屏无时限 preload 和 WebSocket 初始化异常不重连均已修复。

当前代码审查门：**可以构建下一版测试候选**。  
当前分发门：**不能把现有 Test 5 安装包当成包含本报告修复的新版本**。这些修复发生在 Test 5 发布之后，必须构建新的 Test 6（或新候选名）。  
当前正式发布门：**仍需真实 Windows 机器验证 WFP、DNS、WinTUN、Job Object、退出和取消路径**。

## 2. Test 5 发布物核对

GitHub API 和发布附件核对结果：

| 项目 | 结果 |
|---|---|
| Release | `tono-windows-2.5.4-test5`，prerelease |
| 发布时间 | 2026-08-02 17:07 UTC |
| 安装包大小 | 35,420,076 bytes |
| 安装包 SHA-256 | `0cfd68444aefded4ed9bc2d687f4ce9d481e980f08940b5e65249e0fd393bb88` |
| Service | 2.6.1，协议 revision 8 |
| 本地 Test 5 源文件 | 与发布 source snapshot 中的 71 个文件逐字节一致（本轮修改前） |

发布追溯仍有一个必须在下一候选修正的问题：Release 的 `target_commitish`/tag 指向旧基线提交 `59737f5959907e3a5446144fa6cd95ea2e881774`，而实际 Test 5 是以 source asset 保存的 dirty snapshot。source asset 能辅助审计，但不能替代不可变、可检出的发布提交。

下一候选必须：

1. 先把完整、精确源码提交到独立 commit；
2. tag 指向该 commit；
3. 从 clean worktree 构建；
4. Manifest 记录 commit、工具链、Service/Mihomo/Installer SHA；
5. 不覆盖 Test 5，继续保留 Test 4 `UNSAFE` 标记。

## 3. 本轮具体修复

### 3.1 IPC runtime 与重试放大

Test 5 已有 2-worker 专用 IPC runtime，但 `kode-bridge` 的全局 `max_retries=20` 同时作用于连接和完整 HTTP 请求。两个 status/read 请求就可能长期占满两个 worker，使 release、stop 或 DNS 恢复在客户端侧排队。

本轮调整：

- read request：最多 2 次；
- mutating request：最多 1 次，禁止在响应丢失后自动重放；
- status timeout：5 秒降为 2 秒；
- version probe 的重试交给上层 Run State，不在单次 IPC 内再次放大；
- 保留“调用方超时/取消后，已开始 IPC 任务继续完成”的 Test 5 安全语义。

这解决的是 worker starvation 与写操作重放竞态，不会通过粗暴取消把 Service 留在未知提交状态。

### 3.2 未验证启动恢复的不可逆安全顺序

旧 Test 5 顺序存在两个问题：

- DNS 恢复错误被保存但不阻止 WFP 删除；
- WFP 删除早于 startup Core reconciliation，旧 Mihomo/TUN 可能仍然存在。

现顺序为：

```text
读取 unverified intent
        ↓
立即重装/保持严格 Blocked WFP
        ↓
startup reconciliation 确认旧 Core 已终止
        ↓
持久化停用 matching/legacy desired owner
        ↓
恢复并验证 DNS
        ↓
删除 WFP 与 intent
```

任何 owner mismatch、desired state 写失败、DNS 无法证明恢复或 WFP 删除失败，都会保留更严格的 fail-closed 状态和恢复证据。

新增覆盖：

- DNS snapshot 损坏时不得解除 WFP；
- DNS 证据恢复后才允许清理；
- verified intent 不得被 initial-attempt cleanup 清除；
- 无 `owner_key` 的 legacy intent 清理后，active desired Core 不得复活。

### 3.3 WFP status 一致性

原实现先复制 `ARMED`，再等待 `WFP_OPERATION`。等待期间完成的 arm/disarm 会被旧复制覆盖到响应中。

现实现先取得 WFP 操作锁，再读取 `ARMED`，确保 status 至少对应操作锁边界上的一致状态。WFP live verification 继续复用 watchdog 的短 TTL cache，避免每次 status 都执行完整 RPC sweep。

### 3.4 DIRECT 与 Windows 网卡身份

现实现：

- 在第一次 Mihomo/WinTUN 启动前取得物理出口；
- Windows 使用 `GetBestRoute2` 获取 LUID，再用 `GetIfEntry2.Alias` 获取与 Service alias→LUID 解析一致的值；
- 接受中文、日文、`vEthernet (...)`、标点等合法 alias；拒绝控制字符、首尾空白、loopback/Tono 和超长 UTF-16；
- runtime plan 和 WFP permits 从同一个完整唯一端点集合生成；超过 256 直接报错，不再 `.take(256)` 静默截断；
- WeChat/web DNS 查询并行执行。

这直接修复 `lockingTraffic error 123` 的 alias/name 类问题和“某些应用随机断网”的 plan/permit 不一致。

### 3.5 连接阶段硬时限

新增边界：

- bootstrap DNS：单次最多 2 秒，失败使用 pinned hosts；
- localhost controller poll：单次最多 750 ms，整体最多 15 秒；
- fake-IP system DNS：每次最多 2 秒，共 3 次；
- Controller connect timeout：500 ms；
- policy 两组 controller DNS 查询并行。

Service mutation 仍保留最长 65 秒的响应窗口，因为响应丢失时不能假设写操作未提交。下一阶段应通过 Service operation journal/actor 提供可查询的 operation id 后，再安全缩短这一边界。

### 3.6 原生 Rust/Win32 Mihomo 生命周期

已删除 Windows 主路径的 `tasklist`/`taskkill`：

- `OpenProcess + WaitForSingleObject` 判断存活；
- 查询失败除明确 invalid PID 外按“可能存活”处理，避免恢复流程 fail-open；
- `TerminateProcess + WaitForSingleObject(2s)` 处理旧版遗留 PID；
- 新启动 Mihomo 放入独立 Job Object；
- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 保证 Service 崩溃、watchdog abort 或 guard drop 时回收 Mihomo 及其子进程；
- child 终止确认最多 3 秒；watchdog join 最多 5 秒，超时后 abort 并按 PID 对账。

这是值得做的“原生 Rust/二进制化”：减少 shell 进程、本地化输出解析、async worker 阻塞和孤儿进程，而不重写成熟代理数据面。

### 3.7 Quit、首屏和 WebSocket

- preventable Quit 只由 `feat::quit` 执行一次 release；
- `ExitRequested` 只同步抢占 single-flight 标志，清理在 async runtime 运行，Tao 事件循环继续处理拖动、绘制和最小化；
- 只有 Quit 真正取消时才 resync FSM；
- 首屏显示 Tono loading shell，IPC/语言 preload 最多阻止 React render 2 秒；慢 preload 可在后台完成并恢复用户语言；
- WebSocket listener 在 `onConnected` 前安装；`onConnected`、listener 安装或 close handshake 失败都会 clear socket 并计划重连；owner 切换初始化失败也会重连。

## 4. 验证结果

| 检查 | 结果 |
|---|---:|
| Tono Core 全量 | 150/150 |
| Windows Service library（最终新增后） | 160/160 |
| Service integration/bin targets | 全部通过 |
| Tauri App 主库 | 386/386 |
| App 辅助 Rust crates | 1/1、7/7、2/2，通过 |
| 前端 Vitest | 85/85 |
| 前端 TypeScript | 通过 |
| Cloudflare Worker | 44/44 |
| Cloudflare TypeScript | 通过 |
| Service xwin `x86_64-pc-windows-msvc` | 通过 |
| 完整 Tauri App xwin `x86_64-pc-windows-msvc` | 通过 |
| `git diff --check` | 通过 |

说明：xwin 能证明 `cfg(windows)` 的 Win32 类型、feature 和链接符号可编译，不能证明真实 WFP/WinTUN/多网卡/SCM 时序正确。

## 5. 最终复审后仍存在的风险

以下不是本轮测试候选的已知代码回归，但仍是正式稳定版前的重要工程项。

### R1. Service 仍用全局 owner lifecycle lock

status 与 mutation 仍可能在 Service 内排队。Test 5 的专用 runtime 和本轮 read bound 能保证 Tauri 窗口不被一起冻住，但不能让安全操作越过正在执行的 mutation。

下一步应把 Service 改为：

- 单 writer lifecycle actor；
- `ArcSwap`/`watch` 发布只读状态快照；
- status 不等待 mutation；
- mutation 返回 operation id，客户端可查询 committed/failed/unknown；
- release/stop 拥有明确优先级和补偿状态。

### R2. 连接还没有一个统一的绝对 transaction deadline

本轮已封住 Controller 和 DNS 的主要乘法放大，但 Start/Stop/DNS/WFP mutation 为避免未知提交仍可能各等待 Service 的生命周期上界。

只有在 Service 提供 operation journal 后，才能安全实现真正的统一 deadline + cancellation token；直接在 App 侧粗暴 timeout mutation 会产生“客户端认为失败，Service 稍后提交”的更危险竞态。

### R3. Windows 原生路径只完成了交叉编译

Job Object、WFP、DNS CIM、WinTUN alias、SCM wait chain 必须在目标 Windows 机器实际运行。原卡死若仍发生，dump/Wait Chain 才能区分：

- WFP RPC；
- PowerShell/CIM；
- Service lifecycle lock；
- SCM process verification；
- Mihomo/WinTUN；
- WebView2/GPU。

### R4. 体积与遗留能力

控制面已经大部分是 Rust，Service 约 2.7 MB；体积主因不是“Rust 不够多”，而是：

- stable + alpha 两份约 45 MB Mihomo；
- Monaco/worker 与未路由旧页面；
- 约百个旧 Tauri command 和大量 plugin/dependency；
- release symbols 未 strip；
- CSP/capability scope 仍过宽。

优先删除未使用 alpha、断开 Monaco 桶导出、删除旧页面/command/plugin、外置 PDB 并 strip。不要为了体积重写 Mihomo；也不要在状态机稳定前全面重写 Rust UI。

### R5. 其他非阻断 P1

- 固定 7890/9090 端口仍可能和旧代理冲突；现在会在 15 秒内明确失败，但尚未动态分配或预检。
- “测试当前节点”仍只是等待 400 ms 后读取历史延迟，不是真实测试；实现 probe 前应改文案或禁用。
- 全局旧 `AppDataProvider`、大面积 backdrop blur 在低端 GPU/RDP 下仍需性能基线和 reduced-effects 模式。
- restore session 仍是高复杂度长事务，尚未拆成可视阶段和统一预算。

## 6. 是否应该全面改成原生 Rust

答案：**不应全面重写；应继续原生化控制面中与 Windows 状态、进程和并发有关的部分。**

推荐顺序：

```text
已完成：IPC runtime 隔离 → Win32 Process/Job Object → pre-TUN route/alias
下一步：Service actor + lock-free snapshot → operation journal/deadline → 全链路 LUID/ifIndex
随后：删除旧前后端能力、双 sidecar、Monaco、无用 plugin → strip/外置 PDB
最后：只有实测 WebView2 仍不达标，才原型比较 Slint/Iced/WinUI 3 Dashboard
```

不推荐：

- 用 Rust 重写 Mihomo；
- 因一次卡死就全面重写 React UI；
- 把 HTTP/named-pipe 传输替换当成 Service 锁和 deadline 的替代方案。

## 7. 下一测试候选的发布门

在交给用户测试前：

1. 把本轮源码和 Test 5 基线一起提交到 clean commit；
2. 用新 tag（建议 Test 6）构建 Service、App、NSIS；
3. 重新跑 Windows App/Service 交叉检查和 release build；
4. 解包核对 Service/Mihomo SHA；
5. 安装器、卸载器、主程序图标检查；
6. 发布新的 installer SHA-256、commit、Cloudflare version；
7. 明确 Test 5 被新候选取代，但继续禁止 Test 4。

本轮没有发布或覆盖任何 GitHub/Cloudflare 资产，避免让旧 Test 5 URL 指向与其 SHA/源码不同的内容。

## 8. 真实 Windows 首轮测试

优先顺序：

1. 全新重启后安装下一候选，只打开 App 60 秒：网络正常、窗口可拖动/最小化、Task Manager 不显示 `Not Responding`。
2. 第一次连接：`Starting Kill Switch` 秒数持续增长且窗口始终响应；进入 `Starting Tunnel` 后，Controller readiness 最多等待 15 秒并明确成功或失败。
3. 在 `Starting Kill Switch` 中点 Disconnect/退出一次：UI 继续响应；最终 WFP/DNS/Core 状态一致，不反复点击。
4. 正常 Connected 后结束 Mihomo：应进入 Protected Offline 并自动恢复，不得保持假绿色。
5. 正常 Connected 后退出 App：只执行一次退出序列，窗口仍能重绘，Mihomo 和子进程被 Job Object 回收。
6. 中文/虚拟网卡环境连接：不得出现 alias 相关 error 123。
7. 重启 Service：verified 会话保持 fail-closed 并恢复；未 verified 首次尝试在 Core/DNS 对账后安全清理。

若仍卡死，停止重复连接并收集：

- `Tono.exe` dump；
- `TonoService.exe` dump（若能创建）；
- Wait Chain；
- `traffic-audit.jsonl`；
- Service 日志；
- 卡死时 UI/Task Manager/网络状态截图。

## 9. 最终判断

静态复审、全量测试和 Windows 交叉编译没有发现本轮修改路径中的剩余编译/单测阻断项。可以把当前源码作为**下一测试候选的构建基线**，但不能声称现有 Test 5 安装包已经包含这些修复，也不能在没有真实 Windows 运行结果时宣布生产级问题全部关闭。
