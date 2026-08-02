# WidenKillSwitchPermits — 最终设计文档（Final Design, rev 10）

消除 `applyingCloudPolicy` 阶段的第二次 StartClash：以一条新的 owner+session 双门控 Service 路由在活体 WFP 策略上事务性加宽 DIRECT endpoint permits，随后经既有 `StageRuntime` 推送 DIRECT-enabled runtime，并通过 mihomo controller reload + 运行时探针激活 selector。全程 fail-closed，任意失败回退到今天的完整第二次 StartClash 路径。

---

## 1. 背景与目标

现状（`app/src-tauri/src/tono/connection.rs:1817-1922`）：带非空 cloud policy 的每次连接，`apply_cloud_policy` 为了让 WFP 携带 DIRECT endpoint permits 而执行**完整的第二次 StartClash**——Service 侧 stop 运行中的 Mihomo（≤3 s）、重新 arm bootstrap、respawn core、拆除/重建 WinTUN；App 侧重复 `wait_controller`（≤15 s）与 `lock_kill_switch_with_retries`，并按 §5 轮换 controller secret。代价：**每次带策略连接多付 5–15 s**。

目标状态：widen（一次 WFP 事务，~100 ms）→ StageRuntime（文件级）→ `PUT /configs` reload + 探针（~1–2 s）。**预期节省 5–15 s/次**，且不触碰 core 生命周期、不重建 WinTUN、不轮换 secret。

---

## 2. 评审结论与评分

三份独立设计（safety-first / perf-first / operability-first）已逐条对照实际代码核验（`lib.rs:102`、`windows_kill_switch.rs:29/62-68/177/375/484/521/605/650`、`server.rs:736/1147`、`client/mod.rs:50/65`、`structure.rs:375-383`、`connection.rs:680/748/1817`）。三者事实基础均扎实；operability 设计存在一处小误：`StageRuntimeOutcome::Staged` **已经**携带 `config_path`（structure.rs:378），无需扩展。

| 维度 | safety-first（扩展 lock 路由） | perf-first（新路由） | operability-first（新路由+灰度） |
|---|---|---|---|
| R1 意图持久化 | ✓ | ✓ | ✓（并修复 legacy 路径重启缺口） |
| R2 代际/取消处理 | ✓（镜像 stale_after_arm） | ✓（镜像 stale_after_arm） | △（log-only 修补，论证成立但偏离既有 H-1 惯例） |
| R3 严格时序 permit→selector | ✓ | ✓ | ✓ |
| R4 协议 rev 10 | ✓ feature-detect | ✓ feature-detect | ✓ feature-detect |
| R5 secret 姿态 | ✓ | ✓（分析最透彻） | ✓ |
| R6 reload 契约+探针 | ✓（含 re-lock 修复 LUID） | ✓ | △（force=false 可疑；无 re-lock 修复腿） |
| R7 256 上限+WeChat 契约复用 | ✓ 字面复用 | ✓ 字面复用（重构为 `_against`） | ✓ |
| 简洁性 | 5（零新路由）但语义过载 | 4 | 3（flag/遥测管道） |
| 节省时钟 | ~1–2 s | ~1–2 s | 同，但默认关闭延迟兑现 |
| 对 fail-closed 机器的爆炸半径 | 中（rev-9 静默忽略陷阱需双重防御；`Some([])` 清空是脚枪） | 低（纯增量路由） | 低-中（restrict 清空、arm 持久化触及 legacy 路径，已声明） |

**裁决：以 perf-first 的骨架为准**（独立路由 `POST /kill-switch/widen-permits`，replace-set 语义，`mode==Locked` 前置，返回 `KillSwitchStatus`）。理由：本仓库的既有文化是 fail-loud（协议注释、独立 error string、`ServiceOperationKind` 进 `/status`）；独立路由在 rev-9 服务上**响亮失败**（路由不存在），而 lock 扩展需要"revision 门 + status 回显"两重防御去堵 serde 静默忽略陷阱，且给 lock 留下 `Some([])`=清空 的双义脚枪。

**嫁接**：
- 自 operability：dark-ship + A/B 发布（§14）、`PolicyFastPathStart/Fallback{step,error}` 审计事件、等价性单测（arm-携带 vs widen-后补 产出逐字节相同的 expected_filters）、restrict/stop 清空 DIRECT 的收紧、arm_bootstrap 同步持久化（修复 legacy 路径重启缺口）。
- 自 safety：`KillSwitchStatus` 增加 additive 的 `direct_endpoint_count` 字段（探针与遥测用）、"StageRuntime 传输歧义后**绝不 reload**"规则、探针中的 re-lock 腿（修复 TUN LUID 变化）、连续 2 次回退后的粘性降级。

---

## 3. 拒绝的替代方案（一句话理由）

1. **扩展 `LockKillSwitch` 携带可选 direct_endpoints**（safety 骨架）：rev-9 服务 serde 静默忽略未知字段并返回成功，需两重防御才安全，且 `Some([])`=清空 是长期语义脚枪——独立路由免费获得 fail-loud。
2. **首次 StartClash 前预解析策略域名**（perf 的零成本变体）：Protected Offline 下物理网络被封锁无法解析；且 pre-TUN 明文 53 端口解析给本地/门户攻击者送上"任意进程 WFP 直连 permits + selector 引流"原语——安全性一票否决。
3. **硬性要求 rev 10（提升 MIN_REQUIRED_SERVICE_REVISION）**：把安装器换服务失败的偏斜变成完全断连，而正确的慢路径必须永久存在（它同时是 reload 失败的运行时回退）。
4. **经 reload/PATCH 轮换 controller secret**：赌版本相关的 reload 语义，可能把 App 锁在自己的 controller 之外，零收益。
5. **保留 restrict/stop 后的 DIRECT permits**（safety 的 parity 选择）：Protected Offline 没有运行中的 DIRECT selector，permits 是无正当性的常驻孔洞——收紧为清空（内存+落盘）。
6. **在 wfp_model 内把 DIRECT permits 门控到 Locked 模式**：改变 legacy 路径行为，爆炸半径超出本设计；记入后续加固路线图。
7. **PUT /configs 以 body 直传 YAML**：把含 secret 的完整配置放上 loopback HTTP；path-based reload 让 secret 完全不经过该跳（`Staged.config_path` 已就绪）。
8. **增量添加 WFP filter 而非全集重装**：产生 partial-add 窗口；复用 `install_unlocked` 的单事务全集置换 + verify-by-key 是零新机制。
9. **stale_after_widen 仅记日志**（operability）：论证虽成立（release 的 remove_all_filters 会清扫），但偏离 `stale_after_arm`（connection.rs:748）确立的 H-1 惯例；镜像既有"best-effort stop + owner-gated release"更一致且幂等无害。
10. **`force=false` reload**（operability）：已知跨版本陷阱是"path 等于已加载 path 时静默 no-op"——`force=true` + P3 sentinel 断言双保险。

---

## 4. Service 路由设计（service_route）

**路由**：`POST /kill-switch/widen-permits` — 新增 `IpcCommand::WidenKillSwitchPermits`（`service/src/core/command.rs`，strum path `"/kill-switch/widen-permits"`），handler 置于 `server.rs` LockKillSwitch（:736）旁；新增 `ServiceOperationKind::WidenKillSwitch`（进 `/status` 的 `active_operation`，可诊断）。

**请求**：`AuthenticatedSessionRequest<WidenKillSwitchPermitsRequest { direct_endpoints: Vec<ProxyEndpoint> }>`。
**语义：REPLACE-SET，非 delta**——payload 是本 armed 会话的完整 DIRECT 集。幂等是硬性的：`MUTATING_REQUEST_ATTEMPTS=1`（client/mod.rs:65）下丢失响应即歧义，回退路径（arm_bootstrap 同为全集替换）必须收敛到同一状态。

**响应**：`ok_json(KillSwitchStatus)`（widen 后快照，同 release 的形制），并给 `KillSwitchStatus` 增加 additive 字段 `#[serde(default)] direct_endpoint_count: usize`（由 `Armed.direct_endpoints` 填充，旧客户端忽略）——App 一个往返内即可断言 `wanted && live && mode==Locked && direct_endpoint_count == plan 数`。

**门控（两层）**：
1. `enter_owner_lifecycle(&owner, OwnerLifecycleGate::ActiveSession(&request.session))` —— widen 是 mid-connect 会话变更，与 LockKillSwitch/StageRuntime 同门。**刻意不用** release 式的 ArmedPolicyOwner 门：release 必须活过会话失效（Protected Offline 死锁），widen 恰恰相反——StopClash 清掉会话后，迟到的 widen 在门上就被拒，免费 fail-closed。路由注释中写明这一偏离"字面 owner-gated"的理由。
2. facade `windows_kill_switch::widen_direct_permits(owner_key, endpoints)` 内部在 `WFP_OPERATION` 下显式校验 `armed.intent.owner_key == Some(owner_key)`（mark_verified :417-439 先例），即使门竞态漏过也守住 armed-policy-owner 属性。

**facade 执行序**（全程持 OWNER_LIFECYCLE_LOCK + `OperationGuard(WidenKillSwitch, IPC_HANDLER_TIMEOUT)`）：
- (a) `ensure_supported()`；(b) 取 `WFP_OPERATION` tokio mutex（与 lock/restrict/release/watchdog 1 s reinstall 串行）；(c) clone ARMED，None → `"kill switch is not armed"`；(d) owner_key 校验；(e) **要求 `mode == KillSwitchStatusMode::Locked`**，独立 error string `"kill switch is not locked; widen refused"`（App 回退分类器可区分时序 bug 与传输噪声；`apply_cloud_policy` 本就运行在首次 lock 之后）；
- (f) **校验（硬性要求 7）**：把 `validate_direct_endpoints`（windows_kill_switch.rs:177-210）重构为 `validate_direct_endpoints_against(node_endpoints, direct)`，以 `node_endpoints = armed.intent.endpoints`（**armed 记录，不信客户端**）调用——字面复用 MAX_DIRECT_ENDPOINTS=256、`parse_endpoint`、TCP 80/443 / UDP 443/8000 WeChat 端口契约、1.1.1.1/8.8.8.8 永久保护、选中节点 IP 去重。原 `validate_direct_endpoints(config)` 变为对新函数的薄包装，两条路径共享同一实现；
- (g) 构造 candidate：`armed.direct_endpoints = payload`、`armed.intent.direct_endpoints = payload`、`updated_at = now`；
- (h) `install_unlocked(&candidate)` —— **非增量**：既有 `wfp_model::expected_filters`（已在所有模式发射 per-tuple 的 permit-direct filter）+ `wfp::install` 单事务全集置换 + verify-by-key，不存在半加宽或无底洞瞬间；失败则旧 filter 集与旧意图原样保留，返回 Err；
- (i) **仅在活体成功后**：`atomic_write` 意图文件（现携带 tuples，见 §6），再 publish `*ARMED = Some(candidate)`，`record_outcome` 清 LAST_ERROR。

**live-first / persist-second 排序理由**：DIRECT permits 是 fail-open 方向的加法，与 `restrict_bootstrap_unlocked`（收紧，故 persist-first，:530）方向相反、与 `lock`（放宽，live-first，:509-514）方向一致——install 与 persist 之间崩溃，重启恢复到**更窄**的屏障（DIRECT 静默降级，安全）；persist-first 则会在重启时恢复从未被证明活体生效的 permits。

**client 包装**：`widen_kill_switch_permits(credentials, session, body)`（`service/src/client/mod.rs`，`Verb::Post` + `LIFECYCLE_TIMEOUT`=65 s，自动继承单次尝试不重放）；App 侧 `tono_widen_kill_switch_permits` 置于 `tono_lock_kill_switch` 旁（`app/src-tauri/src/core/service.rs`），另加薄包装 `tono_stage_runtime`。

---

## 5. App 侧时序（app_sequencing）

替换 `apply_cloud_policy`（connection.rs:1817）在 `build_direct_plan` 与空计划 early-return 之后的尾部；签名不变，返回后续阶段使用的 controller secret。不变式：**permit 严格先于 selector**——任何会把流量导向 DIRECT 的配置触达 core 之前，WFP permits 已活体生效并被验证。

- **S0**（不变）：`resolve_direct_domains` 经 controller `/dns/query`（DoH 走隧道，抗欺骗——这是拒绝预解析的根据）；`build_direct_plan`（App 侧 256 上限，connection.rs:~2057）；空计划 early-return；`ensure_fresh(state, generation)`。
- **S1 特性门**：`fast = cloud_policy_fast_path flag && ProtocolInfo::supports_kill_switch_widen()`（ProtocolInfo 已在 connect 起点取得）。`!fast` 或粘性降级 flag 置位 → 逐字执行今天的第二次 StartClash 体（提取为具名函数 `apply_cloud_policy_via_restart`）并返回其轮换后的 secret。fast 时审计 `PolicyFastPathStart{tcp,udp,web 计数}`。
- **S2 WIDEN（permit 先行）**：`widen_permits_cancellation_safe(state, direct_endpoints, generation)` —— 与 `start_core_cancellation_safe`（connection.rs:680-704）完全同构：取 `state.begin_connect_mutation()` read guard（`privileged_transition` RwLock 的读侧；`release_explicit` 的写侧因此**不可能**横穿 in-flight 的 widen——硬性要求 2 的 RW barrier）；检查代际；`tokio::spawn` detached task 持有 guard：(a) 发 IPC（单次，65 s）；(b) **无条件**执行 commit 后代际检查；(c) 失效则 `stale_after_widen(state)`——决策镜像 `stale_after_arm`（:748）：releasing bump（Disconnect/Sign-out/Quit）→ best-effort `tono_stop_core(false)` + owner-gated `tono_release_kill_switch`（幂等）；非 releasing bump（节点切换）→ 保留屏障，后继事务的 arm_bootstrap 全集替换 DIRECT 集。父任务 `await` JoinHandle，**绝不 abort**（硬性要求 2：绝不取消可能已提交的变更）。IPC Err → 回退 F。widen 无需启动 core、不创建会话，故 stale 修补严格不重于 stale_after_arm。
- **S3 回显断言**：从路由响应的 `KillSwitchStatus` 断言 `wanted && live && mode==Locked && direct_endpoint_count == plan 数`；不符 → 回退 F。`ensure_fresh`。
- **S4 构建 runtime**：`build_owned_runtime_with_ports(nodes, node, ORIGINAL_SECRET, Some(&plan), RuntimePorts{mixed_port:0, controller_port})` —— **同 secret、同端口**，staged YAML 与运行中配置仅在 rules/hosts/proxy-plan 上有差异，tun/dns/external-controller 段逐字节相同（reload 无理由触碰它们）。`write_redacted_copy`；`ensure_fresh`；`tono_core_binary_path`。
- **S5 STAGE（selector 就位但未激活）**：`stage_runtime_cancellation_safe`（同 detached 模式）调既有 session-gated `StageRuntime`（server.rs:1147）。`Staged{config_path}` → 继续（structure.rs:378 已携带 config_path，无需协议变更）；`RestartRequired{任意 reason}` → 回退 F（staging 的 config.yaml-last 原子排序保证盘上代与运行中 core 一致）；**传输丢失 → 回退 F 且绝不 reload**（盘上代状态歧义；staging 文档规定 stop+start 是唯一安全修复）。`ensure_fresh`。此后若任何环节失败、watchdog respawn core 会拾起 DIRECT 配置——安全，因 permits 在 S2 已活体生效；这正是 widen 必须先于 StageRuntime 而不可反序的原因。
- **S6 RELOAD（selector 激活）**：`PUT http://127.0.0.1:{controller_port}/configs?force=true`，body `{"path": config_path}`，Bearer = 原 secret，经 `controller_client()`（connection.rs:1587），5 s 超时，单次尝试（变更不盲重试；歧义交给探针裁决）。`ensure_fresh`。
- **S7 探针**（§10；总预算 ~6 s，各腿之间 `ensure_fresh`）：任一腿失败 → 回退 F。全过 → 审计 `PolicyActivated{..., fast_path:true}`，返回 `Ok(original_secret)`——不轮换 secret、无 wait_controller 15 s、无第二次全量 relock 循环；下游 §6.7 securingDNS 的 `verify_fake_ip`、§6.8 `probe_exit`、§6.9 `verify_locked` 原样运行，兼作端到端 reload 证明。
- **回退 F**（S2 之后任意失败且代际仍新鲜；单一 label）：审计 `PolicyFastPathFallback{step: "widen"|"echo"|"stage"|"reload"|"probe", error}`；连续 2 次触发后置位本 App 运行期粘性 flag（后续连接直走 legacy，把探针税封顶为每次运行两回）；执行 `apply_cloud_policy_via_restart` 逐字原样：fresh secret → 携带**同一** direct_endpoints 的 KillSwitchConfig 走 `start_core_cancellation_safe`（arm_bootstrap 重新校验并全集替换，幂等吸收已成功的 widen）→ `wait_controller` → `lock_kill_switch_with_retries`。F 对 reload 留下的任何半状态不敏感——它从零重建代与 core；屏障全程 armed。F 自身失败 = 普通连接失败 → `plan_failure` → Protected Offline + 2/5/10/20/30 s 退避（硬性要求 3：任何失败保持屏障）。

---

## 6. 意图持久化（intent_persistence，硬性要求 1）

**Schema**：`IntentRecord`（windows_kill_switch.rs:29）新增 `#[serde(default)] direct_endpoints: Vec<ProxyEndpoint>`。`Armed.direct_endpoints` 的模块注释（:62-68 "omission = clear … never written … never restored"）改写为新契约：**"活跃已验证会话持有期间持久化；restrict/stop/release 清空；每次 arm_bootstrap 全集替换"**。

**写入点**：
- (a) `widen_direct_permits`：live-first → persist → publish（§4 排序理由）。install 成功后 `atomic_write` 失败 → 返回错误：活体已加宽、盘上更窄，App 回退 F 由 StartClash 一致性重写两者。
- (b) `arm_bootstrap`（:375）：把 `config.direct_endpoints` 一并写入记录——**顺带修复 legacy 路径既存的重启缺口**（今天重启后 desired-state 恢复 DIRECT-enabled core 配置但 permits=∅，WeChat DIRECT 流量被黑洞），并使两条路径的重启行为一致（A/B 需要）。注：arm 的既有排序是 persist-first（收紧的 floor）；tuples 搭车导致"持久化先于活体证明"——可接受：已校验，且对应 desired-state 就是 DIRECT 配置；在注释中声明。
- (c) `restrict_bootstrap_unlocked`（:521）与 `transition_after_stop`（:605）：**内存 + 落盘同时清空**（收紧；采纳 operability/perf 的一致选择——Protected Offline 无 DIRECT selector 运行，permits 是无正当性孔洞。这是对 legacy 路径的小幅行为变更，changelog 显式声明）。
- (d) release/tombstone/emergency 路径：整记录删除或空集，如今日。

**恢复**（`restore_on_service_start`，:650）：对 valid + verified 的 wanted 意图，把持久化 tuples 重新过 `validate_direct_endpoints_against(intent.endpoints, intent.direct_endpoints)` + 256 上限（**硬性要求 7 在恢复处同样适用**）：通过 → 以之重建 Armed（tuples 随 floor 同一首事务安装，boot 屏障复现崩溃前策略；`relock_restored_tunnel` 随后恢复 Locked）；**任何**校验失败 → 整个 DIRECT 集丢弃 + LAST_ERROR 记录，恢复继续——损坏/篡改的 permit 数据降级为更严格，绝不把恢复推入 emergency。unverified 分支与 `emergency_armed` 保持空集，原逻辑不动。watchdog 零改动：它 reconcile `expected_filters(rule_config(armed))`，天然包含 tuples。

**双向降级安全**：legacy 记录缺字段 → serde default 空集 = 今日行为；rev-10 记录被回滚的 rev-9 服务读取 → 未知字段被忽略，恢复 permits=∅ —— 双向 fail-closed。迁移注释警告：未来若给 IntentRecord 上 `deny_unknown_fields`，rev-10 文件在 rev-9 上会变成 "corrupt = emergency armed"（仍 fail-closed 但对用户不友好）。

---

## 7. 失败矩阵（failure_matrix）

格式：故障点 → 屏障 / core+配置 / 用户可见。

| # | 故障点 | 屏障 | core/配置 | 结果 |
|---|---|---|---|---|
| 1 | 域名解析/plan 构建失败 | armed+Locked，无新 permits | 旧配置运行 | 连接失败 → plan_failure 保 WFP → Protected Offline+退避 |
| 2 | widen 校验拒绝（cap/端口/保护地址/owner/mode/not-armed） | 不变（校验先于 install） | 旧配置 | 回退 F；同集合在 arm_bootstrap 同样失败 → 普通失败 |
| 3 | widen WFP install 失败 | 单事务：旧 filter 集+旧意图原样，last_error 记录 | 旧配置 | 回退 F |
| 4 | widen install 成功、intent persist 失败 | 活体已宽、盘上更窄，路由返回错误 | 旧配置 | 回退 F 一致性重写；若崩溃则重启恢复更窄屏障（fail-closed） |
| 5 | widen 传输歧义（丢响应/超时） | armed，或旧或已宽（两态对隧道流量均 fail-closed；已宽仅多出已校验 tuples，无 selector） | 旧配置 | 回退 F，replace-set 收敛 |
| 6 | widen 提交后代际失效（releasing bump） | detached task 完成 → stale_after_widen：best-effort stop + owner-gated release 连 DIRECT 一并清扫；写屏障保证显式 release 事务不横穿 | — | 按用户请求断开 |
| 7 | 代际失效（节点切换） | 保留；后继事务 arm_bootstrap 全集替换 | 后继重建 | Stale 静默退出 |
| 8 | 回显断言不符（S3） | armed（已宽或未宽） | 旧配置 | 回退 F 权威重装 |
| 9 | StageRuntime 拒绝（CoreNotRunning/CorePathChanged/RuntimeUnwritable/CoreRestarted） | permits 已宽+已持久化 | 盘上代仍与运行中 core 一致（staging 原子排序） | 回退 F；今日成本连接成功 |
| 10 | StageRuntime 传输歧义 | 已宽 | 盘上代歧义 → **绝不 reload** | 回退 F 从零重建代 |
| 11 | reload PUT 非 2xx/超时 | 已宽 | core 或旧或新（版本相关） | 探针裁决；失败 → 回退 F（stop+start 消解歧义） |
| 12 | reload 200 但探针失败（PID 变/401/sentinel 缺失/LUID 死/未 Locked） | armed 全程（WFP 独立于 core 进程） | 不定 | 回退 F；若 mihomo 死亡，Service core watchdog 可能已从 DIRECT 代 respawn——无害，permits 已在位，F 全量替换 |
| 13 | 探针通过后 core 崩溃 | armed | watchdog 从 DIRECT 代 respawn | 与今日任何 mid-session core 崩溃同构 |
| 14 | Service 在 widen install 与 persist 之间崩溃 | 重启恢复**更窄**意图（Blocked 无 DIRECT） | desired-state 或恢复 DIRECT 代 → DIRECT 流量黑洞至下次连接（降级非泄漏） | App 重连补发 |
| 15 | persist 之后崩溃/整机重启（带策略 Connected 中） | restore 重新校验后携带 tuples 重 arm Blocked；relock_restored_tunnel 恢复 Locked | desired-state 恢复 DIRECT 代 | **同一屏障被复现（硬性要求 1）** |
| 16 | 恢复时持久化 tuples 校验失败（损坏/超限/撞保护地址） | 空集恢复，更窄 | — | WeChat 走隧道或阻塞至重连；fail-closed |
| 17 | 回退 F 自身失败 | armed | stop core、保 WFP、restrict | Protected Offline + 退避，与今日一致 |
| 18 | App 崩溃于任意中间点 | Service armed（Locked 或 Blocked），watchdog 维持 filters | 按 14/15 规则 | 启动 reconcile + 重连梯子 |

每行守恒：**除显式 release 路由外，无任何路径移除 WFP**。

---

## 8. 协议版本（protocol，硬性要求 4）

- `PROTOCOL_REVISION` 9 → **10**（lib.rs:102），doc 注释按 rev-7/8/9 风格：*"Revision 10 adds POST /kill-switch/widen-permits, persisted DIRECT intent, and the additive direct_endpoint_count status field. Pure latency optimisation: rev-9 pairing remains fully safe via the second-StartClash path. Two-stage plan: dark-ship in rev 10; a later release may raise MIN_REQUIRED_SERVICE_REVISION after Test 7 telemetry clears it."*
- 新增 `MIN_SERVICE_REVISION_FOR_KILL_SWITCH_WIDEN: u16 = 10` 与 `ProtocolInfo::supports_kill_switch_widen()`（structure.rs:89 `supports_kill_switch_release` 同形）。
- **裁决：feature-detect + 回退，不硬性要求 rev 10**。`MIN_REQUIRED_SERVICE_REVISION` 与 `MIN_SUPPORTED_CLIENT_REVISION` 均维持 9。理由：(a) rev-9 地板存在的理由是不可分割的**安全**语义（lib.rs:98-101）；widen 是纯优化，缺席时有已出货的完全正确行为；(b) legacy 路径必须**永久**编译在内（它同时是 reload 探针失败的运行时回退），硬性要求换不来任何代码删除，只把安装器偏斜变成断连；(c) 线上兼容真实成立：路由纯增量，意图字段服务内部且双向 serde 容忍，`direct_endpoint_count` additive。rev-9 服务上路由不存在 → 响亮报错 → S1 门本就不会走到这里（双保险）。最坏情形（门与路由同时误判）：DIRECT 流量撞未加宽屏障被**阻塞**——可用性损失，永不泄漏。

---

## 9. Controller Secret 姿态（secret_posture，硬性要求 5）

**现状（§5/architecture.md）**：secret 每次 core start 随机生成、不持久化；带策略连接因第二次 start 而在 mid-connect 轮换一次。

**变更声明**：fast path 下一次连接只有一次 core start，首次 start 铸造的 secret 存活整个会话——每会话 secret 数从 2 降为 1，pre-policy secret 寿命从数秒延展为会话全程。"random per core start" 不变式字面上仍成立（reload 不启动 core），但"策略阶段必然轮换"的 §5 记载性偏离消失，§5 与 architecture.md 须改写为 *"per core start; a widen-based policy connect performs one start"*。

**姿态评估**：per-start 轮换本是双启动的副产品而非设计控制——无策略连接（绝大多数）的首个 secret 今天就活满整个会话；fast path 只是让带策略连接与之对齐。暴露面不变：App 进程内存、SYSTEM-ACL 的服务侧 runtime 副本（用户侧落盘为 redacted）、loopback-only listener；能读第一阶段 secret 的本地攻击者同样能读轮换后的——变化的是时长，不是受众。

**缓解**：(1) 每次 StartClash（新连接、重连、节点切换、watchdog respawn、回退 F）仍铸造 fresh secret，寿命以会话为界；(2) **staged DIRECT runtime 必须嵌入同一 secret 与 external-controller 地址**——mihomo 各版本对 reload 是否热应用 secret/listener 变更不一致，同值使该问题失去意义，绝不尝试 rotation-via-reload；(3) 探针 P1 以原 secret 认证 `GET /version`，任何丢 auth/换配置重启的 core 会失败并触发回退 F（F 恢复 rotate-per-start 属性）；(4) `PUT /configs` 走 path-based，secret 不上 loopback HTTP 请求体；(5) 审计事件区分 fast/legacy，使 secret 寿命在支持日志中可观测。路线图（超出本设计）：连接稳定后经 PATCH /configs 择机轮换。

---

## 10. Reload 语义契约与运行时探针（reload_probe，硬性要求 6）

**`PUT /configs?force=true`（body `{"path": <Staged.config_path>}`，Bearer 原 secret）必须保全**（mihomo 语义跨版本漂移且 macOS 上不可验证，故契约显式声明、一律运行时证明）：
1. **core 进程本身**——不退出/不 respawn（respawn 重建 WinTUN → 新 LUID → Locked 的 tunnel permit 指向死适配器，且惊动 netmon M4）；
2. **TUN 适配器身份**——`Tono` 适配器保持 LUID（staged tun 段逐字节相同，规范实现无理由重建）；可容忍同名重建（探针 P4 re-lock 重新锚定）；
3. **external-controller listener**——同端口同 secret 继续认证；
4. **DNS/fake-ip 管线**——127.0.0.1:53 TCP+UDP listener 存活、fake-ip range/dns-hijack 配置相同；活体 fake-ip 映射的存续由紧随其后的 §6.7 `verify_fake_ip` 端到端证明（探针不重复该腿，此处显式声明覆盖论证闭合）；
5. **staged 规则真实生效**——不得静默 no-op（已知陷阱：path 与已加载 path 相同时部分版本 200 而不应用；`force=true` + P3 双保险）。
6. 既有连接**允许**掉线——此阶段仅存在 App 自身的 controller/DNS 探测流量，无用户流量。

**探针（S7，PUT 返回后顺序执行，各腿 3×500 ms 网格，总预算 ~6 s，腿间 `ensure_fresh`）**：
- **P1** `GET /version`（原 secret）→ 2xx：证明 (3)；401 = reload 动了 auth → 版本偏离，回退。
- **P2** Service `/status`（lock-free 快照）→ core PID 与 PUT 前快照一致：证明 (1)。
- **P3** `GET /rules` → 断言 plan 的 DIRECT sentinel 存在（首条 tcp_wechat 规则元组；UDP/hosts-only 计划时 DirectPlan builder 保证非空计划必发射至少一条可 grep 规则）：证明 (5)——reload 真应用了而非返回 204 保持旧规则集。
- **P4** `lock_kill_switch_with_retries()`（幂等，Service 侧重新解析 Tono 别名 → LUID 并验证 tunnel 设备）：证明适配器存活于 reload 后，或在同名重建情形下**重新锚定** tunnel permit，屏障留在 Locked（嫁接自 safety 设计——比只检测更进一步，可修复）。
- **P5** 路由响应/`GET /kill-switch/status` 断言 `wanted && live && mode==Locked && direct_endpoint_count == plan 数`（`live` 来自 1 s verify-by-key watchdog；缓存 TTL 1.5 s，等待 ≥2 s 再判失败）。
- **P6（顺延，既有）**：§6.7 `verify_fake_ip` 与 §6.8 `probe_exit` 完成 DNS 劫持与出口路径的端到端证据链。

**回退触发**：PUT 非 2xx、PUT 超时、P1–P5 任一腿在有界重试后失败、腿间代际失效 → 回退 F = 今天的完整第二次 StartClash（stop ≤3 s、re-arm、respawn、WinTUN 重建、wait_controller、relock）——F 对 reload 留下的任何半状态不敏感，屏障（已加宽）全程 armed。连续 2 次回退 → 粘性降级（§5 S1），把不兼容 core 版本的探针税封顶为每 App 运行两次。**core 版本升级必须重跑 Windows reload 行为矩阵（§13），探针是永久性运行时门而非仅发布期检查。**

---

## 11. 风险（risks）

- **R1 mihomo reload 语义漂移（中心未知）**：可能 no-op、部分应用、掉 controller、重建 TUN。缓解：非规则段逐字节相同 + P1–P5 + 无条件回退 F + 粘性降级 + core 版本 pin；残余风险仅为回退前 ~2 s 浪费，永不泄漏、永不断连。
- **R2 持久化 tuples 逆转 "omission = clear" 教义**：重启后、App 返回前，窄的 any-process permits 已存在于 Blocked 屏障。边界：≤256 条精确公网 IP:port、审批端口、verified-session-only 恢复、恢复时重校验、stop/restrict/release 清空；换来的是 DIRECT 策略不再在重启后静默失效（先前对抗性验证的硬性要求）。写入 SECURITY.md。
- **R3 widened-but-unstaged 窗口**：widen 提交后、reload 生效前，已校验 tuples 对任意进程可达而无 selector——与今日 legacy 路径 arm 与二次 start 之间的窗口同类，界于 120 s CONNECT_TRANSACTION_TIMEOUT 内，失败路径由 restrict 清空。
- **R4 双变更取代单 StartClash 的部分状态组合爆炸**：已在 §7 全表枚举；每个部分态都在 armed 屏障之后，每个传输歧义都有 no-replay + 修复故事。
- **R5 stale_after_widen 是最高评审注意力项**：widen 横穿 in-flight release 是先前评审标记的 P0 类；`begin_privileged_release` 写屏障 + detached task 代际检查 + ActiveSession 门三重闭合，并镜像既有 H-1 惯例。
- **R6 StageRuntime 在 Windows 上持续拒绝的可能**（RuntimeUnwritable：运行中 core 持有 provider 文件句柄）：Tono 的 bundle `assets: Vec::new()`，仅 config.yaml 原子替换（mihomo 不长期持有）；若实机证伪，优化静默蒸发为今日成本——由 `PolicyFastPathFallback{step}` 遥测度量真实命中率。
- **R7 legacy 路径行为的两处有意变更**（arm_bootstrap 持久化 tuples 修复重启缺口；restrict/stop 清空 in-memory 集）：均为收紧/修复方向，但必须在 changelog 与对抗性复审中显式声明，不得静默夹带。
- **R8 reload 路径跳过了二次 StartClash 附带的全量 re-arm**：Armed 与活体 filter 的潜在漂移现在仅由 1 s watchdog verify-by-key 纠正——这本就是常设不变式，可接受。
- **R9 文档债**：§5 secret 措辞、architecture.md 数据流、wfp-kill-switch.md 意图 schema、SECURITY.md 姿态，须与代码同 PR 修订以保持对抗性验证的书面轨迹一致。

---

## 12. 测试计划（test_plan）

**macOS 可运行（service `feature=test` 桩引擎；沿用 windows_kill_switch.rs 串行套件模板）**：
1. `widen_requires_armed_locked_and_matching_owner`：未 armed / Bootstrap / Blocked（独立 "not locked" 错误串）/ 错误 owner → 拒绝，零状态变更。
2. `widen_validates_cap_and_contract`：257 条、TCP 8000、UDP 80、1.1.1.1/8.8.8.8、armed 节点 IP 重复 → 错误，ARMED 与意图文件不变（证明校验以 **armed** endpoints 为基准，硬性要求 7）。
3. `widen_is_replacement_idempotent_and_can_narrow`：同集两次 → 相同 ARMED+intent；异集 → 替换非并集；空集 → 清空。
4. `widen_persists_and_restore_rearms`：widen → kill-switch.json 含 tuples → 清 ARMED → `restore_on_service_start` → Armed 携带 tuples、Blocked、RESTORE_WAS_LOCKED → relock 路径；status 报 `direct_endpoint_count`。
5. `restore_drops_invalid_persisted_direct_entirely`：篡改端口/超限/撞保护地址 → 空集 + LAST_ERROR，恢复继续。
6. legacy 记录缺字段 → 空集；rev-10 记录被无该字段的旧 schema 替身解析 → 忽略（双向降级 fail-closed）。unverified 恢复与 emergency/tombstone 保持空集。
7. `restrict_and_transition_after_stop_clear_direct`（内存+落盘）；`arm_bootstrap_replaces_widened_set` 与 `arm_bootstrap_persists_config_tuples`。
8. 崩溃排序：强制 install 后 `atomic_write` 失败 → 返回错误、盘上无 tuples（fail-closed 重启）。
9. **等价性证明（离 Windows 的关键结果，嫁接自 operability）**：`expected_filters(arm 携带集 → lock)` ≡ `expected_filters(arm 无集 → lock → widen 同集)`——FilterSpec 向量逐字节相同，fast/legacy 安装同一策略。
10. wfp_model：加宽后/恢复后配置在三种模式下的 permit-direct 发射；加宽前后差集恰为新增 permits。
11. server 路由测试（test IPC）：auth/session/协议头拒绝矩阵；与并发 StartClash 的生命周期锁串行化。
12. protocol：rev 9/10 与 epoch 失配下的 `supports_kill_switch_widen` 矩阵；`supports_client` 不回归。
13. App 侧纯函数：回退分类器（错误 → step 标签）全覆盖 {rev<10、echo 不符、stage 拒绝、stage 歧义、reload 失败、探针失败}→F；`stale_after_widen` 决策表（release_on_stale × committed）镜像 `stale_exit_needs_release` 测试；对 mock service 的时序状态机：证明 widen→stage→reload 顺序、各边界注入代际 bump、detached task 在父 stale 退出后仍完成；探针断言逻辑对 canned /rules //version //status fixtures；App/Service 的 MAX_DIRECT_ENDPOINTS=256 常量一致性测试。

**仅真实 Windows 可证明（windows-testing-runbook.md 增补，Test 7）**：
- (a) **pinned mihomo `PUT /configs?force=true` 行为矩阵**（探针的 ground truth，本设计的 go/no-go）：PID 稳定性、WinTUN 别名/LUID 稳定性、127.0.0.1:53 保持绑定、fake-ip 存续、secret 保持、既有连接处理、path 相同时的静默 no-op 检测。
- (b) 真实 BFE 事务加宽：延迟、widen 后 verify-by-key、swap 期间抓包证明无泄漏窗口、与 watchdog 并发。
- (c) 端到端带策略连接时钟：策略开销 5–15 s → **≤2 s** 断言；WeChat DIRECT 流量实际通行、未审批 DIRECT 尝试仍被阻（DIRECT_ATTEMPT 审计标记）、断开/restrict 后重新阻断。
- (d) 会话中硬重启：恢复的 filter 集含 DIRECT permits、恢复的 core 无需重连即按策略路由（硬性要求 1 端到端）。
- (e) install 与 persist 之间 `kill -9` 服务 → 更窄重 arm。
- (f) rev-9 服务 + rev-10 App：门选择 legacy 路径 e2e 成功；rev-10 意图文件被 rev-9 服务恢复（空集，fail-closed）。
- (g) 故障注入：stage 与 reload 之间杀 mihomo → 探针 PID 腿失败 → 回退 F 连接成功；锁定 provider 文件触发 RuntimeUnwritable → 回退成功。
- (h) A/B 本体：flag off/on 各 N 次带策略连接，比较 ConnectOk elapsed_ms 分布、Fallback 率、`PolicyActivated{fast_path}` 切分。

---

## 13. 实施前置条件

实现开始前必须为真：
1. **可用的真实 Windows 硬件 + pinned mihomo core build**，且 §12(a) reload 行为矩阵已排期为实现中段的 go/no-go 检查点——若矩阵证伪（listener/TUN/静默 no-op 不可接受），只落地持久化 + 协议 + 路由地基，App fast path 保持关闭直至 core 升级。
2. **确认 `apply_cloud_policy` 在连接流中严格位于首次 lock 之后**（`mode==Locked` 前置的依据；代码走读已支持，需在 PR 中以断言/注释固化）。
3. **确认 Tono 的 StageRuntime bundle 恒为 `assets: Vec::new()` + 仅 config.yaml**（connection.rs:1881 现状），即 Windows 上运行中 core 不持有被替换文件句柄的前提成立。
4. **对抗性复审签字**下列三项教义变更：意图记录持久化 DIRECT tuples（R2）、restrict/stop 清空（R7）、arm_bootstrap 持久化（R7）。
5. **审计事件 schema 冻结**：`PolicyFastPathStart` / `PolicyFastPathFallback{step,error}` / `PolicyActivated{fast_path}`，Test 7 读数管道就绪。
6. **文档修订清单确认**：product-contract §5、architecture.md（secret + 单启动数据流）、wfp-kill-switch.md（意图 schema）、SECURITY.md（R2 姿态）、windows-testing-runbook.md（§12 W 项）——与代码同 PR。
7. `validate_direct_endpoints` → `validate_direct_endpoints_against` 重构先行合入（零行为变更的独立小 PR，缩小主 PR 评审面）。

---

## 14. 发布计划（dark-ship + A/B）

1. **阶段 0（本次发布，rev 10）——dark-ship**：Service 路由 + 意图持久化 + status 字段随 rev 10 全量上线（live）；App fast path 受 `ProtocolInfo::supports_kill_switch_widen()` **与** app 侧 flag `cloud_policy_fast_path`（默认 **off**，debug 命令/配置可翻转）双门控。legacy 路径永久编译在内。
2. **阶段 1——同构 A/B（Test 7）**：单一安装构建上翻转 flag 跑两臂：比较 ConnectOk elapsed_ms 分布、`PolicyFastPathFallback` 率与 step 分布、reload 矩阵回归。通过标准：fallback 率 ≈ 0（RuntimeUnwritable 除外并单列）、无探针假阳性、无任何 fail-closed 回归、时钟节省达标（≤2 s）。
3. **阶段 2——默认开启**：flag 默认 on 随后续版本发布；粘性降级与探针保持为永久运行时护栏；core 版本升级触发 §12(a) 矩阵重跑，未通过前该 core 版本 flag 不得默认 on。
4. **阶段 3（可选，遥测清障后）**：评估将 `MIN_REQUIRED_SERVICE_REVISION` 提升至 10（lib.rs 注释中已预告两阶段计划）；即便提升，legacy 路径仍保留（reload 回退需要）。

---

## 15. 工作量估算（estimated_effort）

约 **1.5–2 engineer-weeks 到 merge-ready** + Windows 实机验证：
- Service（IpcCommand + 路由 + OperationKind + `widen_direct_permits` + 校验重构 + IntentRecord 字段 + arm/restrict/restore 变更 + status 字段 + client 包装 + 单测 ~300 LOC）：2.5–3 天。
- App（apply_cloud_policy 拆分 fast/legacy、widen/stage cancellation-safe 包装、`stale_after_widen`、reload 客户端 + 探针套件、回退 + 粘性 flag、feature-detect、flag 管道、审计事件 + 纯函数测试）：2.5–3 天。
- 协议/文档（rev 10、supports fn、§5/architecture/wfp/SECURITY/runbook）：0.5 天。
- 失败矩阵对抗性复审：1 天。
- Windows 实机（§12 a–h，两种硬件档案含冷 WinTUN 机器；**(a) reload 矩阵为进度关键未知与 go/no-go**）：2–3 天。
- 发布尾巴（flag 默认 on + 可选地板提升）：后续版本 ~0.5 天。

---

## 16. 不确定性（仅真实 Windows 能证明）

诚实清单——以下任何一条在实机证伪都会触发 §13.1 的降级出货决策，但**不会**造成泄漏或断连（探针 + 回退 F 把最坏情形界定为"今日成本"）：

1. **pinned mihomo build 的 `PUT /configs?force=true` 真实语义**：进程是否存活、`Tono` 适配器 LUID 是否稳定、external-controller listener 与 secret 是否保持、127.0.0.1:53 与 fake-ip 状态是否连续、path 相同时是否静默 no-op、`force=true` 在该 build 上的确切含义。这是整个设计的中心未知，macOS 上原理性不可验证。
2. **BFE 在负载下的加宽事务行为**：单事务全集置换期间既有隧道流是否零中断、verify-by-key 是否即刻看到新 permit、事务延迟是否如预期 ~100 ms 量级。
3. **StageRuntime 在 Windows 实机上的 RuntimeUnwritable 真实频率**（AV/索引器对 config.yaml 的瞬时句柄）：决定优化的实际命中率——只能由 A/B 遥测回答。
4. **真实端到端时钟节省**：~1–2 s 的估计建立在 reload 与探针的名义耗时上；实机分布（尤其 P4 re-lock 与 P5 watchdog 缓存等待）可能压缩或吞噬收益。
5. **同名重建 TUN 适配器（LUID 变化而进程未死）的实际可达性**：P4 re-lock 的修复腿是否会在真实驱动行为下被触发、触发后 relock 是否如预期重新锚定。
6. **重启恢复链路的端到端行为**：restore（携带 tuples 的 Blocked）→ desired-state core 恢复 → `relock_restored_tunnel` → watchdog verify 的完整序列，只有真实 SCM/BFE/WinTUN 环境能证明。
7. **Service core watchdog 与 reload 探针窗口的交互**：探针期间 watchdog 恰好 respawn core（P2 捕获 PID 变化 → 回退 F）的竞态频率与无害性，需故障注入 §12(g) 在实机确认。