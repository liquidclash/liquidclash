# Tono for Windows — 一夜构建报告

日期：2026-07-31。本报告记录「从 0 到 1」阶段实际完成的工作、验证证据、
三轮 review 的发现与修复，以及必须在真实 Windows 环境完成的剩余验证。

## 交付总览

| 组件 | 内容 | 验证 |
|---|---|---|
| `crates/tono-core` | 可移植产品层：节点准入、目录校验+安全缓存（含 Windows DACL 写入钩子）、owned 配置生成、API 客户端（refresh 轮换/并发合并/竞态修复）、连接状态机、凭据抽象 | 125 单测全过，clippy 0 警告 |
| `service/` | WFP kill switch（单 sublayer 权重模型）、DNS 快照/设置/验证/恢复、网络+电源事件 feed、IPC 协议 rev 5（kill switch/DNS 路由）+ rev 6（owner 门控释放，写路由绑定 intent owner）、emergency disarm、BFE 服务依赖、升级路径 legacy 清扫 | 139 单测 + 21 个测试目标全绿（含 stop→release 核心集成测试）；`cargo check --target x86_64-pc-windows-msvc` 干净 |
| `app/` 后端 | `tono/` 模块：15 个 Tauri 命令、§6 连接编排器（代际防并发）、目录同步、会话恢复、keyring 凭据、reqwest 安全 transport、Windows 缓存 ACL 实现、退出释放钩子、本地审计日志（字段级脱敏+writer 自愈） | `cargo check` 0 error/0 warning；369 测试全过；**`cargo xwin check --target x86_64-pc-windows-msvc` 通过**（cfg(windows) 代码全部实际编译验证） |
| `app/` 前端 | 登录 / 仪表盘 / 服务器 / 账号四个页面，CVR 页面收进 Advanced 折叠组，tono i18n（en/zh），设置页日志开关（含丢弃计数显示） | typecheck 0 错、lint 过、72 vitest 全过 |
| sidecar | mihomo v1.19.29 官方 Windows x64 二进制（stable+alpha 槽位） | SHA-256 见下文；生产应改走 prebuild.mjs 下载流 |

## 三轮 Review 与修复（重点）

### 第一轮：tono-core（2 Medium + 9 Low，全修）

重连谓词在 disconnecting 期间仍发放延迟；`connect_succeeded` 无前置守卫
（可产生未 arm 的 Connected）→ 受控转换。refresh/adopt 会话覆盖竞态、缓存
store/load 大小不对称、credentials 目录 fsync、UUID 严格 36 字符、SNI 全量
parity 校验、公网保留段补齐 4 段（比 macOS 更严）等。105→121 测试。

### 第二轮：service（1 Critical + 1 High + 5 Medium + 9 Low，全修）

**Critical：WFP 仲裁模型反转**。初版假设「filter 权重优先、sublayer 权重破
平局」，与 MSDN 真实语义相反（sublayer 权重是第一排序键）。旧规则表下
session sublayer 的 match-all block 会打死 loopback/DHCP/NDP——armed 即全断，
11 个单测全绿测不出。修复：Mullvad 式**单 sublayer + filter 权重分层**
（permit 8/7 > DNS block 6 > block-all 1），新增仲裁仿真测试：旧模型上失败
（精确复现 loopback 53 被打死）、新模型通过。

**High**：网络/电源事件无 IPC 出口 → `ServiceStatusSnapshot.network_events`
单调 counter，app 轮询比对触发重连。

**Medium**：emergency disarm 顺序（先恢复 DNS 再删 WFP）；单协议栈网卡
enable 必败；DNS restore 只证明注册表不证明运行态（记录 live_apply 结果，
失败判未证明，fail-closed）；/dns/enable 部分应用后无法自愈；Windows
core_path 无约束（白名单：服务持久目录 + ProgramFiles 下 tono 目录）。

### 第三轮：app 编排（1 Critical + 3 High + 5 Medium + 7 Low，全修）

**Critical：Protected Offline 释放死锁**。StopClash 是 session 门控，而
Protected Offline 路径恰恰已消费掉 session——显式 Disconnect/Sign-Out 永远
无法到达，kill switch 无法释放。修复（协议 rev 6）：service 新增
`POST /kill-switch/release`（ActiveOwner 门控、幂等、含 DNS-before-disarm
不变量、macOS 映射到既有 PF 释放语义）；app 所有显式释放路径（disconnect/
sign-out/restore-401/quit 钩子）统一走 `release_explicit()`。

**High**：连接中切节点/切号产生并发事务（connect 代际计数，9 处锁内校验，
Stale 无副作用退出；switch 任务纳入注册表）；连接中 sign-out 后重连拉到
无账号状态（guard 加 Ready 检查 + 代际 + 不吞释放失败）；Windows 目录缓存
因 DACL 不对称永远读不回（tono-core 增加 `secure_written_file` 钩子，app
实现受保护 DACL 写入，与检查端严格对称）。

**Medium**：keyring 读错误误判为无 token；tracker revision 先于落盘被推进
（install_and_persist 顺序化+测试）；sign-out 吞 DNS 恢复失败；运行时无
core 崩溃检测（监控 core_pid/restart_count）；节点消失重选后不恢复自动重连。

### 第五轮：整体重审（3 个新 High/P0 + 一批 Medium/Low，全修）

**service**：
- H1 越权释放——Unchecked 门控下同机任意用户可释放他人 armed 的 kill
  switch。修：intent 记录 owner_key（SHA256(SID)），release/restrict/
  dns-restore 三条写路由要求 caller 与记录 owner 一致（旧文件无 owner_key
  放行并注释为逃生门）。
- H2 lock() fail-open——接受任意接口名（传物理网卡即全进程放行）。修：
  强制与 arm 时记录的 tunnel_interface 一致。
- M1 升级路径——启动迁移清扫退役 sublayer（全量枚举不限 layer）+
  FILTER_NAMESPACE 版本化（key-only diff 不再收养过期内容）。
- M2 not-armed 的 disarm 分支跳过 DNS 恢复（release 返回 Ok 但解析器
  黑洞）。M3 dns enable 短路忽略 live_apply_failed。M4 client 封装
  50ms 超时对秒级 WFP/PowerShell 操作必然误报（统一 LIFECYCLE_TIMEOUT/
  STATUS_TIMEOUT）。L 系列：保留段补齐、文档与二进制名不一致、
  core_path 目录组件边界匹配、status 复用 watchdog 缓存。

**app 后端**：
- H1 同节点重选无条件 bump 代际+杀任务（三种卡死形态；双击服务器行
  即可触发）。修：纯函数 select_action，Noop 零副作用。
- M1 redact 可绕过（JSON 转义腐蚀/JSON 形态漏匹配/大小写）。修：字段级
  脱敏（序列化前）+ (?i) 全覆盖 + JSON 形态 + 对抗性测试。
- M2 release_on_stale 意图位被无事务 bump 覆盖。M3 quit 被取消后屏障
  已释放+审计死亡+FSM 说谎（flush 移到退出承诺点 + 取消路径重同步）。
- L：writer 自愈+丢弃计数（tono_audit_log_path 返回 {path,droppedCount}）、
  settings 原子写、drain 统一 flush、ConnectBegin 提前、restore 包 catch。

**前端**：
- **P0：authenticating 被守卫映射成全屏 loading——点"发送验证码"即
  卸载登录页，构建无法登录**，且错误断言把它钉成了规格。修：守卫矩阵
  修正 + 断言翻转 + 停留格/全链路回归测试。
- 订阅 effect 每渲染重注册（改 ref+空依赖，再收敛为模块级单订阅+引用
  计数）；重发倒计时误用验证码 TTL（固定 60s）；revoke 失败无反馈；
  kill switch mode 改 i18n；endpoints.protocol 类型补齐。

### 第七轮：F1/F2/F3 修复（Mac 差距分析 §6 的 2-4 项，代码层完成）

- **F1 控制面自锁**：钉死 IP 取自 macOS Info.plist（104.20.26.170、
  172.66.162.98，Cloudflare anycast）；API transport 用 reqwest
  `resolve_to_addrs` 钉定（SNI/证书仍按域名校验）；StartClash 的
  bootstrap_api_hosts = pins + 动态解析合并（≤8）。blocked 下 WFP 放行
  与 app API 访问都不再依赖系统 DNS。
- **F2 健康探测**：连接后 monitor 每 2s 校验 kill-switch 完整性
  （wanted+live+Locked，连续 2 次异常失效重连）+ 每 120s 单次出口
  探测（连续 2 次失败失效重连）；失败写 `healthProbeFail` 审计。
- **F3 步骤 UI**：后端 `tono/steps.rs` 步骤状态机（失败步永不被误标
  completed）+ `tono_connect_progress` / `tono_retry_now` 命令；前端
  `ConnectProgressCard`——8 步三态列表、每步耗时、TOTAL/TRY N、失败
  详情可复制块、重试倒计时、Retry Now、独立 Restore Normal Internet
  （确认对话框）、Copy details 诊断文本。
- 测试：后端 383（+13）、前端 81（+7）全绿。Windows 真机验证待做。
- **F4（微信 DIRECT）已实现（07-31，代码层）**：动机=微信走美国出口太卡。
  云端策略通道与 Mac Build 28 逐条对齐（`GET /api/v1/traffic-policy`，
  revision 单调 + sha256 + ≤32 域名/≤64 媒体 + 10 个硬编码域名后缀
  白名单 + permanentlyProtected 地址过滤 + 失败保留缓存）；连接事务
  新增 `applyingCloudPolicy` 阶段（lockingTraffic 后）：经隧道 controller
  解析域名 → 精确元组二次 StartClash（permit 先于 selector）→ hosts
  钉死 + `Tono-China-Direct` 组（绑物理接口）+ 逐条 AND 规则（UDP 媒体
  限 WeChat.exe）→ MATCH,Tono-Exit 兜底不变。WFP 侧
  `direct_endpoints`（≤256、TCP 80/443、UDP 443/8000、公网、
  omission=clear 不持久化不恢复不继承）。策略行为变化 → 受保护重连。
  真机验证待做（GetBestRoute2 物理接口探测、二次 StartClash 重启时延）。

### 第六轮：legacy 绕过面封堵 + Windows 真机语义（15+7 项，全修）

**绕过面封堵（app，P0 全 15 项）**：启动不再自动 start core（`init_core_manager`
删除）；core 生命周期直控命令、`patch_clash_mode/config` 全部
`Err("disabled by Tono")`；`patch_verge_config` 改白名单制（危险字段先
于 draft 拒绝）；profiles 写命令/deep-link/Timer 自动更新全禁；托盘裁到
dashboard/目录/日志/版本/quit；热键只剩 dashboard；系统代理写路径全删
（启动保留一次防御性 reset）；退出全部经 quit_release 漏斗（幂等）；
启动时 sanitize 覆写 11 个危险 verge 字段（防手改配置文件）；
`open_devtools` 仅 debug；lock 重试放宽到 10s；netmon 2s 去抖合并。
前端 Advanced 组及路由整体移除（旧页面留盘不链接）。

**Windows 语义（service，7 项）**：DNS live-apply 假成功（CIM
`ReturnValue` 被 `Out-Null` 吞掉——改检查返回值+合并为一次 PowerShell
调用+10s 超时）+ restore 后无条件 `DnsFlushResolverCache`（运行时
GetProcAddress 加载，SDK 导入库无此符号）+ 连续 3 次 live 失败的
degraded 放行策略（不再死锁 Protected Offline）；power event 只认
Suspend/Resume 类；WinTUN LUID 解析后校验确为 wintun 设备（防同名
物理网卡 fail-open）；service 恢复 core 后 Windows 侧重新 lock（此前
开机假死）；install MoveFileExW 退避重试+DELAY_UNTIL_REBOOT 兜底。后续
安全复审已撤回全局 NTP UDP/123 放行：它没有绑定 Windows Time Service，
实际允许任意进程借 UDP/123 绕过 TUN；连接时 NTP 应经隧道，Protected
Offline 则保持 fail-closed。

交叉编译又抓两个 host 不可见的 bug（xwin 实证）：HMODULE 在
windows-sys 0.61 是指针类型、`macos_kill_switch_mode` 的 cfg 泄漏。

### 第四轮：前端 + 修复复验（2 Critical + 3 High + 若干 Medium/Low，全修）

**Critical（前端）：snake_case/camelCase 全线错位**。后端 DTO 是
`rename_all = "camelCase"`，前端 tono.ts 全部声明成 snake_case——运行时
所有字段 undefined：登录守卫双方向失效、dashboard 永远显示未连接、
suspended 页不触发。修复：全部改 camelCase 并补 wire 形状契约测试（唯一
例外 `killSwitch.last_error`：嵌套 DTO 在 service crate 无 rename_all，
线上就是 snake_case，已注释钉死）。

**Critical（service）：释放路由门控选错**。rev6 的 release/dns-restore
用了 `ActiveOwner` 门控，而 StopClash 成功即清除 active-owner 记录——
**普通 Disconnect 也必然 409**，第三轮 C1 在主力路径上完全失效。修复：
断开/释放路径的 5 条路由（release、dns-restore、restrict-bootstrap、
kill-switch/status、dns/status）改 `OwnerLifecycleGate::Unchecked`
（身份仍由 SID+ACL token 认证），并补核心集成测试：
**stop(false) → release 必须成功**（修复前此处必然 409，修复后通过）。

**High**：StartClash 在途窗口的"迟到 arm"无人拆除（stale 出口按意图位
补 owner-gated release）；sign-out 的 protected 谓词漏 is_connecting；
前端 error 状态无重试出路（接 `tono_retry_restore`）、Sign Out 失败零反馈、
restoring 期间渲染完整 UI、跨账号 SWR 缓存泄漏。

### 本地审计日志（§8，用户可关）

对齐 macOS LocalTrafficAudit：`tono/logs/traffic-audit.jsonl`（JSONL，
10 MiB × 2 轮转，0600/私有 DACL），记录账号/目录/保护/服务四类事件
（连接各阶段、失败决策、释放、重连、kill switch 快照、网络变化、core
重启），7 组脱敏正则（Authorization/Cookie/Bearer/token=/password=/
URL query/userinfo），异步非阻塞写入（channel 满即丢，绝不阻塞连接逻辑）。
默认开，设置页 "Tono → Local diagnostic log" 可关（关闭时落最后一条
auditDisabled）。命令：`tono_audit_enabled / tono_set_audit_enabled /
tono_audit_log_path`。

## 验证命令（可复跑）

```sh
cd crates/tono-core && cargo test && cargo clippy --all-targets -- -D warnings
cd service && cargo test --features "standalone client test"
# Windows 目标（项目内隔离工具链）：
export RUSTUP_HOME=.toolchain/rustup CARGO_HOME=.toolchain/cargo
PATH="$CARGO_HOME/bin:$PATH"
cd service && cargo check --target x86_64-pc-windows-msvc --features "standalone client"
cd app/src-tauri && cargo xwin check --target x86_64-pc-windows-msvc  # 需 XWIN_CACHE_DIR=.toolchain/xwin
# app host 与前端：
cd app/src-tauri && cargo check && cargo test --lib
cd app && npx pnpm@11.3.0 run typecheck && npx pnpm@11.3.0 run lint && npx pnpm@11.3.0 run test
```

## 服务端契约对账（以 cloudflare/src/index.ts 为终极事实）

九个核对面（email start/verify、refresh、logout、me、devices、删除设备、
exit-catalog、错误码、传输假设）**逐字段一致**：字段名、无信封平铺响应、
epoch 秒日期、sha256=base64url 无 padding 的 UTF-8 SHA-256、409+精确
`DEVICE_LIMIT`、错误信封 `{error:{code,message}}`、设备注册/复用/上限语义。
真实 API 探测（只读+负例）：`auth/methods`、401 `INVALID_REFRESH_TOKEN`、
400 `VALIDATION_ERROR` 信封与解析假设完全一致。

发现并修复：logout 请求显式 `"refreshToken":null` 会被服务端 400（Swift 版
encodeIfPresent 省略该键所以只有 Windows 踩得到）——加
`skip_serializing_if` + 测试（126 测试全绿）。

遗留决策项（非客户端 bug）：① admin PUT 只做结构校验不做节点语义校验，
一个坏节点会毒化整份目录（客户端全有或全无拒收，fail-closed 但目录更新
停摆）——建议把 node.rs 准入移植到 Worker 发布路径；② 服务端
`TAILSCALE_ENROLLMENT_ENABLED=true` 时 Windows 端（无 confirm 流程）会话
会 30 分钟过期——部署时需确认该开关关闭或为 Windows 豁免。

## 运行时冒烟（macOS host）

第一轮（构建/启动）：

- 完整 `cargo build` 产出 arm64 二进制并真实启动：窗口标题 "Tono"、
  托盘、runstate、service 探测（找到本机既有服务且版本匹配）、Tono 后端
  初始化（restore_session 无 token → signedOut）全部正常。
- 发现：Tauri debug 二进制在编译期**内嵌** frontendDist——只重建 dist
  不重链二进制会展示陈旧 UI。

第二轮（启动死锁实证修复）：

- 真机 `sample` 抓到主线程在 Tauri setup → `TonoState::create` → keyring
  → `SecKeychainFindGenericPassword` 永久阻塞（debug 二进制每次构建签名
  身份变化，securityd 对旧 item 弹 ACL 框无人点）。修复：create 零
  keyring、凭据全部 spawn_blocking + 启动加载 3s timeout、ApiClient 持
  内存态 SessionCredentialStore、读错误走 Error 态不误判登出。此 bug 在
  Windows 上形态不同，但「setup 同步凭据 I/O」同样错误，修复对各平台
  都成立。
- 死锁修掉后窗口正常创建，371 后端测试全绿（窗口最小尺寸测试同步为
  860×540/920×600）。
- 单实例文件在 pkill 后需清理（冒烟流程记录）。
- UI 程序化截图未完成（System Events -1712 超时、webview 不进 a11y 树）；
  基线对照证明 headless 浏览器渲染空白是 CVR 既有行为（前端必须有
  Tauri 才挂载），不作为缺陷。视觉确认留给用户现场查看或 Windows 构建。

## 产品身份统一（Tono 命名）

- 主程序：`Tono.exe` / macOS `Tono`（`[[bin]] name` 改名，package 名不动）；
  窗口标题、进程名、runtime 线程名（tono-runtime-*）全部 Tono。
- service 四件套：`tono-service{,-install,-uninstall,-integration-driver}.exe`；
  SCM 名 `TonoService`、显示名 "Tono Service"、install 器同目录校验与
  `C:\ProgramData\Tono\bin\` 发布路径同步；emergency-disarm 指引同步新名。
- 数据目录 `com.raydocs.tono`（dev 为 `.dev`）——与 CVR 彻底分离（此前
  冒烟期间共享了本机 CVR 数据目录的问题同步消除）；计划任务名
  "Tono"/"Tono (Admin)"；publisher/描述 "Raydocs"/"Tono"。
- 保留：`verge-mihomo*` sidecar 名（第三方组件）、`clash_verge_service_ipc`
  crate 名、deep-link scheme（协议兼容面）、NSIS 旧版清理逻辑的旧名
  （清 CVR 残迹用）。
- macOS 冒烟终验：进程 "Tono"、窗口 "Tono"、a11y 树读出登录页
  （"Welcome to Tono" + 邮箱输入 + 发送验证码按钮），截图确认磨砂
  背景 + 470 玻璃卡渲染正确。

## 未验证 / 必须在 Windows 完成

**构建产物状态**：Windows x64 二进制已全部产出并集结到 `dist-windows/`
（142MB）——`app/`（Tono.exe 50MB + verge-mihomo[-alpha].exe 官方
v1.19.29）与 `service/`（tono-service/install/uninstall 三件套）。app 与
service 均 cargo-xwin release 构建 0 错误 0 警告。
真机测试步骤见 `docs/windows-testing-runbook.md`（按风险排序：
service 安装 → WFP 仲裁探针（armed 后 loopback DNS 必须通）→
fail-closed 矩阵 → 端到端连接 → emergency disarm）。

1. **WFP/DNS/CIM/注册表全部未经真实运行验证**——只有编译检查和纯逻辑/
   仲裁仿真测试。首次真机冒烟：armed 后 loopback DNS 解析应通（仲裁语义
   的直接探针）。
2. `WindowsCacheSafetyCheck`（缓存 ACL 检查+DACL 写入）已通过 xwin 对
   windows 目标实际编译——交叉编译还当场抓到一个真实 bug（
   `GetSecurityDescriptorDacl` 参数顺序写反，host 编译期不可见）——但
   仍未运行验证。
3. 连接全流程端到端（真 service + 真 mihomo + 真节点 + 真 API）。
4. `docs/roadmap.md` 验收矩阵全部行（kill GUI/mihomo/service、重启、睡眠、
   多网卡、IPv6、共存）需 pktmon/Wireshark + 独立公网观测。
5. 已知跨进程窄窗口：StartClash 在途时用户 disconnect，service 可能在
   release 后完成 arm——app 侧已用代际保证不再动 core，彻底关闭需
   service 侧 intent 代际撤销（后续项）。
6. CVR 功能裁剪（profiles/merge/script/backup/unlock 仍在 Advanced 后）、
   设置页缩减、tray 缩减、NSIS publisher/description 品牌收尾、签名与
   updater 渠道。

## 真机 Bug #1：service 安装槽位永久置位（2026-08-01，已修）

**症状**：首台 Windows 真机（Administrator 账户）首次 Connect 后，之后
每次点击都 fail `service operation already running`；`sc.exe query
TonoService` 未安装、无 tono-service 进程。

**根因链**：首次 refresh → NotInstalled → request_action(Install) →
`perform` → `block_in_place(install_service)`——install_service 永不返回
（三候选：runas 的 UAC 弹窗无人点 / 提权分支 `.output()` 等管道句柄永久
阻塞 / 安装器挂死），OperationGuard 永不 drop，`operation_running` 永久
置位。连带：每次点击在 `begin_connect` 前各自进 `ensure_service_ready`，
single-flight 拦不住（F5 的锁存在 service 探针之后）。

**修复**（app，391 测试全绿）：
- `perform` 对特权操作加 150s 硬超时（spawn_blocking + timeout）。超时只能
  停止等待，不能终止已提权 helper；此时 helper 是否仍在修改 SCM 不可知，
  因而进入 quarantine、保留操作槽位并拒绝第二个 helper，直到重启 Tono。
  错误文案明确指引检查 UAC/手动安装路径；HungEnv 测试钉死「永不返回→
  超时→槽位保持隔离→后续 begin 拒绝」。明确的 UAC 拒绝或 helper 非零退出
  仍会正常释放槽位。
- 提权分支 `.output()` → `.status()`（消除管道死等类）。
- single-flight 锁存前置到 service 探针**之前**（快速连点只有一个
  attempt 到达探针）。
- `TONO_SERVICE_BUSY` 稳定错误前缀（指引检查 UAC/重启）。
- Runbook 增「故障排查速查」节。

**给测试者的即时解锁**（无需新构建）：重启 Tono → 管理员手动跑
`C:\Program Files\Tono\resources\tono-service-install.exe` →
`sc.exe query TonoService` 应 RUNNING → 再 Connect。

## 真机前同类故障深审（2026-08-01，源码已修）

- **提权超时后的并发 SCM 风险**：超时只取消等待，不能证明旧 helper 已退出；
  旧实现若释放槽位，第二次 Repair/Install 可与旧 helper 并发。现改为结果不确定
  即 quarantine 到 App 重启。
- **mutating IPC 重放**：底层 kode-bridge 对 PUT 即使配置 `max_attempts=1` 仍会
  隐式二次尝试，可能重复提交 runtime/proxy 写操作；写路由改 POST，删除 PUT
  动词，wire-incompatible 协议升到 rev 7。
- **StartClash 丢响应/任务取消**：请求其实已成功但响应丢失时，App 会失去
  session proof；connect future 被取消时，迟到的 arm/DNS mutation 也可能失控。
  现以 service generation 对账，只在代际确实推进时收养 token；关键 mutation
  放入 detached child，父任务退出后仍完成 stale cleanup。
- **Release 过早拆 WFP**：显式 Disconnect 现先证明 DNS 已恢复，再停止当前 owner
  Core并退休持久 desired state；任一步不确定都保留 WFP。release/restrict/
  dns-restore 的 owner 校验也移入生命周期锁内，消除排队期间新 StartClash 换
  owner 后，旧请求凭过期授权拆掉新会话的 TOCTOU。
- **DNS 网卡集合错误**：历史、禁用、已拔除和伪网卡曾参与 CIM 全批设置，任一
  返回 84/找不到对象就使首次 Connect 失败。现用 IP Helper 只保护当前 Up 且
  非软件 loopback 的 IP adapter；snapshot 仍保留旧网卡原值用于恢复，并合并
  热插拔的新 GUID。成功重试会持久化清除 `live_apply_failed`。
- **Connected 假绿**：每 2 秒独立验证 WFP 和当前 live adapters 的 protected
  DNS；Service status IPC 连续失败也计作保护异常，不再 `continue` 后永久保留
  绿色 Connected，连续两次即进入 fail-closed 重连。
- **WFP 全局旁路**：原来的任意进程 → 任意公网 IP → UDP/123 NTP permit 可被
  当作隧道绕过；DHCP permit 也只看远端端口。现删除全局 NTP 放行，将 DHCPv4
  收紧为 UDP local 68 → remote 67、DHCPv6 为 local 546 → remote 547，并将
  filter namespace 升到 v3，确保升级时不会按旧 key 收养旧条件。
- **NSIS 自身也会永远等待**：App 内 150s 限制不覆盖安装器直接执行 helper 的
  路径。install/uninstall 两个 `nsExec::ExecToLog` 现带 180s 输出等待上限；超时
  按失败中止并保留恢复文件，而不是让安装/卸载界面永久卡死。
- **无用 SimpleSC 供应链**：模板已不再使用 SimpleSC，但 prebuild 曾继续下载
  第三方插件。现删除下载/安装分支，减少无意义的网络依赖与供应链面。

## NSIS 安装包（07-31）

- **状态提醒（08-01 最新源码）**：本轮后续修复尚未重新构建 Windows helper
  和 NSIS 安装包；`app/src-tauri/resources/` 下三个 service `.exe` 仍是旧产物。
  因此这里记录的安装包只能用于对照/复现，不能代表当前源码修复。
- **产物**：`dist-windows/Tono_2.5.3_x64-setup.exe`（35.4MB，NSIS
  perMachine 自解压安装器），SHA-256
  `122d278c7519cebc600519475b455963472aa90681280926823608cbffbf1dc3`。
  内含：Tono.exe、verge-mihomo[-alpha].exe、resources/ 下
  tono-service{,-install,-uninstall}.exe、WebView2 evergreen
  bootstrapper（静默嵌入）。
- **构建链（macOS 交叉，全部可复跑）**：cargo-tauri 2.11.4 +
  `app/.cargo/config.toml` 的 x86_64-pc-windows-msvc 段（lld-link +
  xwin 库路径）+ clang-cl/llvm-lib 环境变量 + brew nsis 3.12
  （`.toolchain/bin/makensis.exe` 软链）+ `.toolchain/bin/pnpm` shim。
  完整命令见会话记录或 REPORT 附录（环境变量较多，建议后续固化成
  scripts/build-windows.sh）。
- **NSIS 模板改动**：`installer.nsi` 的 StartVergeService/RemoveVergeService
  宏由 SimpleSC 插件（CI 外不可得、供应链风险）改为内建
  `sc.exe`/`nsExec` 实现（query→start / query→stop→sleep 3s→delete）。
- **未签名**：Authenticode 与 updater minisign 均未配置（后者报错
  "no private key" 属预期，安装包本体已完整产出）。签名属 Phase 4。
- **注意**：POSIX makensis 的 `-OUTPUTCHARSET` 警告无害；安装/卸载时
  服务的启停依赖 sc.exe 行为，真机过一遍 install→启动→uninstall
  流程确认（runbook §1/§6）。

## 环境说明

- `.toolchain/`（rustup + stable + 1.95.0 + windows 目标 + xwin SDK + tauri-cli + pnpm/makensis shim）完全
  隔离，删除即清理；brew 额外装了 nsis（系统侧唯一新增）。注意 app/rust-toolchain.toml 锁定 Rust 1.95.0。
- mihomo sidecar 为 MetaCubeX 官方 v1.19.29，
  `verge-mihomo-x86_64-pc-windows-msvc.exe` SHA-256：
  `98986b574e41f92b22ed65aa42a61ad8cadf886cc7b3f76b722cd73a3a52d878`
  （alpha 槽位暂为同一二进制占位，发布前需替换为真 alpha 并核验）。
- 未做任何 git 操作；`tono-windows/`（旧 WinUI 脚手架）未动。

## 增补：大陆弱网控制面超时与有限重试 + F5 single-flight（2026-07-31）

背景：中国大陆到 Cloudflare 境外 anycast 链路不稳定，TLS/首包偶发超
10 s（实测 Worker 正常，health/methods 200，20–30 ms）。Mac 已先行修：
超时 10/15 s → 30/45 s + 有限重试。本轮 Windows 对齐并补上连接事务的
最后一把竞态锁。

### 控制面超时与重试（对齐 Mac）

- `app/tono/transport.rs`：connect timeout 10 s → **30 s**、total timeout
  15 s → **45 s**（常量化并有测试锁定）。controller（loopback）不在此列。
- `tono-core::auth` 新增 `TransportKind { Dns, Connect, Tls, Timeout, Other }`，
  `ApiError::Transport` 携带 kind（Display 文案不变）。app 侧 reqwest 分类：
  `is_timeout()` → Timeout；`is_connect()` → Connect（覆盖 DNS 解析+TCP
  connect 两阶段——reqwest 无更细区分，此阶段 HTTP 字节必未送达）；TLS
  相关经 debug 链匹配 → Tls；其余 → Other。
- **重试矩阵**（`ApiClient::call` 统一漏斗，所有 API 请求经过）：

  | 方法/错误 | Dns | Connect | Tls | Timeout | Other | 4xx/5xx | 解析错误 |
  |---|---|---|---|---|---|---|---|
  | GET/HEAD | 重试×1 | 重试×1 | 重试×1 | 重试×1 | 重试×1 | 不重试 | 不重试 |
  | POST/DELETE | 重试×1 | 重试×1 | 不重试 | 不重试 | 不重试 | 不重试 | 不重试 |

  间隔 500 ms（无 waitsForConnectivity 等价物，定值部分覆盖其语义）；
  重试仍失败**传播原始错误**。与 401 refresh 重放独立：一次逻辑请求最多
  1 次传输重试 + 1 次 401 重放（重放本身不再传输重试——refresh 刚证明
  了连通性）。8 个新单测锁定矩阵（GET 各 kind 恰好一次、POST 仅
  Dns/Connect、500/解析不重试、email verify/refresh/logout 三个 POST 在
  Timeout 端到端不重试、组合上限）。
- `docs/product-contract.md` §1 已更新为 30/45 s + 重试策略段。

### F5 single-flight（连接事务最后一把竞态锁）

双击/竞态可让两个 attempt 先后穿过「命令预检」与「begin_connect」两把
独立的锁，导致双 StartClash。修复：`attempt_inner` 在同一把锁内复查
`is_connecting || is_connected` 并 `begin_connect`（纯函数
`single_flight_begin`）——命令入口预检保留为快速失败路径，真正的互斥由
锁内复查保证。并发测试：背靠背两次求值恰好一次准入；stale 代际拒；
失败后允许重试；Connected 中拒。

### 验证

- `tono-core`：148 测试全绿（140 + 8 重试矩阵），clippy 0 警告。
- `app`：`cargo check` 0 error / 0 warning；`cargo test --lib` 全绿。
