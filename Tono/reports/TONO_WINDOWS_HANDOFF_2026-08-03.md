# Tono Windows — 完整 Handoff（2026-08-03）

**发布基线:** GitHub 仍是 0.0.5（`tono-windows-0.0.5`）；本地安装包已构建到 0.0.10（Service 2.6.3），但 0.0.10 尚未覆盖安装真机验证；Windows 接手基线 commit `0eb6879`
**当前工作树状态:** 0.0.8 曾在真 Windows、默认 1000ms 中国延迟档位完成连接、真实流量、速率显示和断开恢复闭环；随后客户网络暴露三来源 TUN 探测全部超时，0.0.9 增加本次 runtime 的独立 loopback proxy 交叉检查以区分节点/内核和 Windows TUN。0.0.9 覆盖安装又复现断开态 Service 重启误装 ownerless emergency WFP block、整机掉线；0.0.10 已修复状态迁移并通过完整非网络回归和生产 WFP 构建。修复仍在未提交工作树和本机构建物中，GitHub 0.0.5 不含这些改动，仍不能发正式客户。
**这份文档的目的:** 让接手的人（或换台机器的你）不用重走我踩过的路。

---

## 0A. 2026-08-03 Windows 真机续测更新

下面 §2 保留的是 **0.0.5 发布包的历史现象和当时的候选分析**。真机续测已经得到更强证据：

- P0-A 根因不是“监听器一定没绑上”，而是 Windows 系统解析器在 `strict-route` + `dns-hijack` + WFP 组合下查询 `127.0.0.1` 超时；同一时刻显式查询 Tono TUN DNS 端点 `198.18.0.2` 在几十毫秒内返回 fake IP。Service 现改为 IPv4 写 `198.18.0.2`、IPv6 写静态空列表，恢复同时识别当前端点与旧版 `127.0.0.1` / `::1`。
- 补了恢复链的下游缺口：PowerShell live read-back 也认识 `198.18.0.2`，不能出现“注册表看似恢复、运行中的 DNS 仍在 Tono 地址上”却拆 WFP。
- review 又发现并修了“快照文件丢失、网卡仍是 `198.18.0.2`”的变砖路径：现在 Connect 不会把 Tono 地址捕获成用户原始 DNS，Disconnect 也不会在缺证据时打开防火墙门；稳定标记是 `TONO_DNS_SNAPSHOT_MISSING`。
- 第一次装上修复版 Service 又抓到一个真机专属误判：Tono WinTUN 自己也合法持有 `198.18.0.2`。现在所有 DNS 收集入口都会排除当前 WFP 验证过的 tunnel LUID；该 LUID 还会重新对照当前 core 进程，避免接口号复用后错误豁免物理网卡。
- 当前固定 Mihomo 已移除带 `interface-name` 的 proxy-group。运行时配置改为真实 `type: direct` outbound 持有物理接口，`Tono-Exit` 只保留选择组；用本机固定内核 `-t` 校验已通过且无 group-removal 警告。
- 中国高延迟测试 feature 默认给明确的远程操作注入 1000ms 延迟；API 超时扩到 connect 30s / total 45s，云策略 DNS 全局并发 4、瞬时 5xx/429 重试 3 次、整段 35s。完整连接事务预算按真实下游总和从 260s 修到 360s。
- App 单元测试原来在 Windows 上链接成功却启动即死（缺 Common Controls v6 activation context）。修复后测试真正执行；同时修了一个 review 发现的正式构建重复 manifest（`CVT1100`）问题。正式 release EXE 已验证只含一份 v6 manifest。
- Dashboard 的流量原来永远为 0，因为复用了指向旧 LocalSocket 控制器的 Mihomo WebSocket，而 Tono 每次连接使用随机 loopback HTTP 端口和新 secret。现在后端在发布 Connected 前原子地把插件切到本次控制器（protocol 最后更新，secret 不进入前端）；Secure DNS 的硬编码显示也从错误的 `127.0.0.1` 改为 `198.18.0.2`。
- **续测又复现了一个新的 P0 出口泄漏：** Chromium 在 Disconnect 状态建立的 HTTP/3/QUIC 会话，在下一次界面显示 Connected 后仍从物理网卡发送；同一进程的新标签页也显示本地 IP，而新 `curl.exe` 显示 VPS IP，证明不是页面缓存而是浏览器连接池复用了旧流。根因是规则只在 `ALE_AUTH_CONNECT_V4/V6` 做新流授权，已存在的 UDP/TCP 流不会因策略切换自动重新授权。
- WFP 规则表已升级到 v7（namespace `…9e06…`）：保留 ALE app-id 边界，并在 `OUTBOUND_TRANSPORT_V4/V6` 增加逐包默认拒绝及配对许可。WinTUN LUID、核心精确 VPS tuple、Bootstrap API、批准的 DIRECT tuple、loopback/DHCP/NDP 都有对应传输层规则；transport 层不使用只在 ALE 可用的 `ALE_APP_ID` / loopback flag。这样旧物理流的下一包会被阻断，浏览器只能经 TUN 重连。
- **0.0.6 中国真机又复现一个 P0 误判：** 前置隧道、WFP、云策略和 DNS 已完成，但 Mihomo `/proxies/Tono-Exit/delay` 在 38 秒后返回 504，App 因而停在 `checkingExit`，没有执行更强的真实数据面验证。`unified-delay` 会做双请求，这个合成测量在中国到美国的高延迟/抖动链路上不能作为可用性的唯一证据。
- 0.0.7 将 controller delay 降为一次有界的 advisory：无论它成功还是 504，都必须继续执行 WFP live read-back + 一条全新的 App HTTPS 请求经系统 DNS/WinTUN 的验证。真实数据面通过即可 Connected，同时写 `controllerExitAdvisory` 审计；真实数据面失败仍然 fail-closed。120 秒周期健康监控也从 controller delay 改为 `tunDataPlane`，避免连接成功后因合成探针抖动被错误拆隧道。
- **0.0.7 中国真机继续失败的证据：** controller 504 后，App 请求 `https://www.gstatic.com/generate_204` 也在两轮 8 秒预算内失败。两种检查虽然走不同代码路径，却共享同一个 Google 目标，因此不能区分“隧道不可用”和“节点到单一站点不可用”。
- 0.0.8 的 App/TUN 验证并发竞速 Google 204、Cloudflare 204、Apple 200 三个独立 HTTPS 来源；WFP 已经 wanted/live/Locked，因此任一经过系统 DNS/WinTUN 的精确 TLS 响应即可证明普通 App 流量有隧道出口。只有三个来源全部失败才回滚，并逐来源保留 timeout/connect/TLS 底层错误。周期健康监控复用同一逻辑，避免连接后再被单站点波动拆除。
- 0.0.9 在最后一轮真实 TUN 验证旁边增加本次 owned Mihomo 的临时 loopback mixed-listener 交叉检查。它只负责诊断分类：proxy 成功而 TUN 失败是 `TONO_TUN_DATA_PLANE_BROKEN`；controller 成功但两条 App ingress 都失败是 `TONO_TUN_INGRESS_BROKEN`；三路均失败是 `TONO_NODE_OR_CORE_UNREACHABLE`。proxy 成功永远不能把 UI 标成 Connected。
- **0.0.9 覆盖安装真机复现了新的 P0 整机断网：** 23:05:50 旧 Service 正常停机，23:05:50.937 新 Service 启动时看见持久 WFP 对象，但正常 Disconnect 早已删除 `kill-switch.json`；旧逻辑把“无 intent + 有 filters”解释成损坏状态并安装 ownerless emergency block。网络监控从 23:05:51 起连续得到 socket access forbidden，直到 23:07:50 用户恢复触发 `/kill-switch/release` 才解除，证明是 WFP 而非 DNS/节点。
- 0.0.10 修复上述升级迁移：正常显式 release 在证明 WFP 已移除后保留一个 `wanted:false` 一次性墓碑；下次启动先清 provider-scoped 残留再消费它。安装 helper 在旧 Service 停止并取得 singleton owner lock 后也迁移 pre-fix 的“无 owner、无 wanted intent”断开状态。任何有效 wanted intent、active owner、损坏/不可读证据都保持 fail-closed。写墓碑失败会恢复旧 wanted intent 和旧 WFP policy，不能假成功。
- 0.0.10 的 Service crate 升为 2.6.3，协议仍为 2.9；这样诊断能确认客户机器是否真的替换了 Service。安装包已生成并通过稳定内核/三 helper/无 Unix payload 的解包门，但尚未做覆盖安装真机验证，**不能发客户**。

本机当前回归基线：`tono-core` 147/147、Service 233 个 lib 测试加全部 bin/integration target（`standalone,client,test` 桩；**仍不等于真引擎覆盖**）、App 433/433、前端 96/96、Windows 打包门 7/7。真实 Service 另以不带 `test` feature 的 release 构建通过，并核验固定内核 SHA 注入。0.0.10 NSIS payload 门通过，安装包 SHA-256 为 `ceff8ea5a2d8a8b4c76bad4d508018bde086169537478e52f4235d8a5cbd88b4`。

这组最后闭环已经在本机通过：

1. 安装不带 `feature=test` 的 release Service，并验证内嵌固定 core SHA；
2. 默认 1000ms 中国档位成功连到 Salt Lake City 节点，窗口全程 `Responding=true`；
3. 保护期间 Ethernet 与 Tono 网卡 DNS 为 `198.18.0.2`，显式和系统查询均返回 `198.18/16` fake-IP；
4. `generate_204` 返回 HTTP 204；20 MB 下载完整通过，另一次 8 MB 下载以 512 KB/s 限速持续 15.6 秒，Dashboard 同步显示 525–544 KB/s；
5. core PID 在整个连接和流量阶段保持不变，没有两秒重连循环；
6. 点击断开后 core 退出，Ethernet / Wi-Fi DNS 都恢复到本机原值 `192.168.31.1`，直连 HTTP 204 的远端重新变为真实公网 IP。
7. 旧 Chromium 流回归完成两轮：每轮 Disconnect 后同一标签页为本地 `172.83.4.82`；Connect/Locked 后，同一旧标签页、同一浏览器进程的第二标签页和新 `curl.exe` 都为 Buffalo · Niagara VPS `23.94.79.123`；再次 Disconnect 后三者恢复本地出口、core 退出、DNS 恢复。

旧闭环只说明 0.0.8 源码在这一台机器、这一张物理网卡和一个节点上可用。0.0.10 已打包但尚未安装；仍保持 pre-release 的理由是：新升级迁移必须先受控真机证明不会重新封网，且卸载、重启恢复、睡眠/唤醒、网卡切换、多用户、WSL/Hyper-V 绕过和第三方安全软件尚未做完整矩阵。

---

## 0. 先回答那个问题：要不要把源码搬到 Windows 上改

**要。而且这是目前最值得做的一件事。**

### 为什么

过去这一整轮的迭代循环是：mac 上改 → 交叉编译 → 传安装包 → 你装上测 → 截图 → 我**靠推理**猜根因 → 再改。一轮 30 分钟起，而且**我在这个循环里引入了两次回归**（IPv6 指向不存在的监听器、DNS 降级引发自我重连循环）。

根本原因不是水平问题，是**可达性**问题：

| 事实 | 后果 |
|---|---|
| `service/src/core/wfp.rs`（965 行 unsafe FFI）在**任何测试配置下都不编译** | 防火墙逻辑从未被测试执行过 |
| `dns::engine`、`netmon::imp`、`windows_security` 等模块是 `cfg(all(windows, not(feature="test")))` | 真机上跑的是 A 代码，测试跑的是永远成功的桩 B |
| macOS 上 `cargo xwin check` 只做类型检查 | 能编译 ≠ 能跑 |
| 统计下来约 **66%** 的测试在 CI 平台上真正验证了行为 | 其余是不编译、跑在桩上、或断言常量 |

**今晚找到的每一个真机 bug，都在这块"编译得过、测试全绿、第一次遇到真 Windows 就错"的区域里。**

### ⚠️ 但搬过去不够 —— 有个坑

**光把代码放到 Windows 上跑 `cargo test` 仍然测不到真实代码。** 因为测试要开 `--features test`，而真正的引擎模块正好被 `not(feature = "test")` 排除掉了。

也就是说：在 Windows 上跑单元测试，跑的还是那个"永远成功"的桩。

**搬过去之后必须补的是"真机集成测试"**：一组以管理员身份运行、直接调用真实 WFP/DNS/SCM 的测试。哪怕只有五六个（装规则→查 `netsh wfp show filters`→拆规则→确认干净；设 DNS→查 `Get-DnsClientServerAddress`→恢复→确认还原），也能在几秒内抓到今晚花了一整夜才定位的问题。

### 在 Windows 上你能立刻得到什么

- `netsh wfp show filters` 直接看规则装没装、什么条件、什么权重
- `Get-DnsClientServerAddress` 直接看 DNS 到底设成什么
- `netstat -ano | findstr :53` 直接看内核有没有在监听
- 附加调试器、看服务日志、改一行立刻验证
- **迭代从 30 分钟变成几秒**

---

## 1. Windows 开发环境需要什么

当前 macOS 侧用的是 `Tono-win/.toolchain` 里的交叉工具链（cargo-xwin + xwin SDK 缓存 + 一个 mac 版 pnpm + makensis.exe）。**那套东西在 Windows 上都不需要**，原生反而更简单。

| 组件 | 版本/说明 |
|---|---|
| Rust | `app/rust-toolchain.toml` 钉的是 **1.95.0**；实际编译用的是 1.97.1。工作区 `edition = 2024`，`rust-version = 1.85` |
| MSVC | Visual Studio Build Tools + "使用 C++ 的桌面开发" 工作负载（Rust 的 `x86_64-pc-windows-msvc` 需要链接器） |
| Node | 走 `app/package.json`；**pnpm 11.3.0**（`packageManager` 字段钉死，用 corepack 启用） |
| WebView2 | Win11 自带；Win10 需装 Runtime |
| NSIS | Tauri 打包时自带下载，不用手装 |
| 7-Zip | 载荷门要用（`7z`/`7zz` 任一在 PATH 里） |
| Git | — |

**注意 vendor 的 IPC 库**：`Tono-win/vendor/kode-bridge` 是我们自己维护的副本（原先依赖第三方仓库的移动分支），`edition = 2021`、有自己的 lint 表和工具链下限，在工作区里是 `exclude` 而不是 member。所有本地改动都带 `// Tono:` 注释标记，将来同步上游能一眼找出。

### Windows 原生构建脚本

仓库根目录已有 `scripts/build-windows-release.ps1`，用法：

```powershell
.\scripts\build-windows-release.ps1 -Version 0.0.10
```

它做的事按顺序是：

1. `pnpm release-version <ver>` —— 同步 package.json / tauri.conf.json / Cargo.toml 三处版本号
2. `pnpm release:preflight --config-only` —— 打包配置门（防止 Test 5 那种混入 alpha 内核和 Unix 脚本的事故）
3. 验证仓库中固定的稳定 Mihomo 二进制存在
4. **计算内核 SHA-256 并注入 `TONO_CORE_SHA256` 环境变量** ← 这一步不能漏，见 §4
5. 构建三个服务二进制，安装到 `app/src-tauri/resources/`
6. `cargo tauri build`
7. 7zz 载荷冒烟检查

第 4 步已由脚本实现且会再次扫描 Service 二进制确认摘要确实嵌入；任何失败都会停止打包。

---

## 2. 0.0.5 发布包的历史未解决问题（按优先级）

### P0-A：连接卡在 `securingDNS` —— fake-ip 校验超时

**现象**（0.0.5，真机）：`Total 9.8s`，`securingDNS` 失败于 6.6s，报 `fake-ip verification failed: system DNS lookup exceeded 2s`。

**已知**：DNS 配置**已经**指向 `127.0.0.1`（不再是配置失败），但那个地址上**没有应答**。三次 2 秒查询全部超时。

**两个候选，必须用数据区分**：
1. 内核的 DNS 监听没绑上 —— 53 端口被别的东西占了（我们在连接前做过预检，但预检和内核实际绑定之间有窗口）
2. 绑上了但答不了 —— 生成的配置里 `respect-rules: true`，DNS 查询要走规则引擎；上游 DoH 又被钉在 `#Tono-Exit` 走隧道。如果此刻隧道还不通，就形成**死锁**：解析要等隧道，隧道要等解析

**怎么分辨**（一条命令）：
```powershell
netstat -ano | Select-String ":53\s"      # 有没有人在听 127.0.0.1:53，是谁
Get-Process mihomo,verge-mihomo           # 内核在不在
```
再看服务端日志里内核启动那段有没有 bind 失败。

如果是第 2 种，方向是让 fake-ip 对目标域名**直接合成**而不走上游（检查 `fake-ip-filter` 和 `respect-rules` 的组合），或者给 DNS 上游一条不依赖隧道的引导路径。

### P0-B：窗口假死（"Tono is not responding"）

**0.0.5 里已埋好判定手段**：主线程泵探针每秒往主线程投递一次往返调用，往返只有在事件循环真正泵消息时才完成。所以**看应用日志就能定位**：

| 日志 | 结论 |
|---|---|
| 有 `Main thread pump STALLED` | 原生主线程卡住 |
| 没有停顿但有 `WebView STALLED` | 渲染进程卡住 |
| 两条都没有 | 泵是活的，假死来自进程之外 |

已排除：网格背景无动画帧、所有 effect 依赖数组正确、失败状态下每秒仅约 1 次 React 提交和 1 次 IPC、状态推送是转移驱动的。

已做的缓解（未证实是元凶）：连接/断开中关闭毛玻璃——一个永久旋转动画叠在 `backdrop-filter` 上会让 WebView2 每帧重新合成整个模糊区域，在无独显/远程桌面上是 60Hz 的软件高斯模糊。代码里**已经因为同样原因栽过一次**（背景组件注释有记录）。

已知但触发条件不同的残留：退出清理的 10 秒预算 > Windows 判定无响应的约 5 秒阈值，那条路必然显示"未响应"（仅 WM_ENDSESSION 路径）。

### P0-C：卸载受阻

0.0.5 已包含三档降级阶梯（精确恢复 → DHCP 兜底 → 拒绝），且硬不变式是"卸载绝不能在防火墙规则还装着时完成"。

**但仍然失败，我的怀疑是另一个原因**：卸载器有一步检查应用是否在运行，而应用正处于假死状态。**先强制结束 `Tono.exe` 再卸载**，看是否就能过。需要卸载器的确切报错文字才能定论。

### P1：诊断上报后端未部署

`cloudflare/` 里的接收端点已完成并与客户端契约对齐（有一个把真实载荷逐字段逐顺序钉死的测试），但**没有 `wrangler deploy`**。客户端那个"上报诊断"按钮在部署前点会报"服务不可用"，属预期。

---

## 3. 采集诊断（给用户/测试者的一条命令）

```powershell
$out = "$env:USERPROFILE\Desktop\tono-diag"
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $out | Out-Null
Copy-Item "C:\ProgramData\Tono\logs\*" $out -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item "$env:APPDATA\com.raydocs.tono\logs\*" "$out\app-logs\" -Recurse -Force -ErrorAction SilentlyContinue
netstat -ano | Select-String ":53\s" > "$out\port53.txt"
Get-Process mihomo,verge-mihomo -ErrorAction SilentlyContinue | Format-List * > "$out\mihomo-proc.txt"
Get-DnsClientServerAddress | Format-Table -AutoSize > "$out\dns-state.txt"
sc.exe query BFE > "$out\bfe.txt"; sc.exe query TonoService >> "$out\bfe.txt"
netsh wfp show filters file="$out\wfp-filters.xml" | Out-Null
Get-NetAdapter | Format-Table Name,InterfaceDescription,InterfaceType,Status -AutoSize > "$out\adapters.txt"
Compress-Archive -Path $out -DestinationPath "$env:USERPROFILE\Desktop\tono-diag.zip" -Force
```

### 恢复网络的三条路（按顺序）

1. 界面里点「断开连接」——**已确认可用**：应用与服务走 Windows 命名管道（本地进程通信，不经过 TCP/IP），本规则集管的是 IP 流量路径且明确放行环回。全网被拦死时这个按钮照样能用。
2. 开始菜单 →「Tono — 恢复网络 (Restore Network)」，点一下弹 UAC。
3. 管理员 PowerShell：
   ```powershell
   taskkill /F /IM Tono.exe
   sc stop TonoService
   & "C:\ProgramData\Tono\bin\tono-service.exe" --emergency-disarm
   ```

**重启电脑救不了网络**——拦截规则是持久化、开机自恢复的，这是"断线绝不漏流量"的设计。

---

## 4. 几个不能漏的构建约束

1. **内核摘要必须注入**。服务会校验 mihomo 的 SHA-256 才肯启动。构建脚本用**本次实际打包的**内核算摘要并编译期注入（`TONO_CORE_SHA256`）。漏了的话表现是"连接直接失败并提示内核校验不通过"——方向安全，但产品不可用。
2. **载荷门必须过**。恰好一个稳定 `verge-mihomo.exe`，无 alpha，无 `clash-verge-service*` / `set_dns.sh` / `unset_dns.sh`，四个必需二进制齐全。Test 5 就是因为混入了这些才作废。
3. **打 tag 前工作树必须干净**，preflight 会检查 tag == commit 以及三处版本号一致。
4. `pnpm release-version` 会重排 JSON 格式，构建后记得 `git checkout --` 掉那些纯格式变更。

---

## 5. 代码导航（关键文件）

| 领域 | 路径 |
|---|---|
| 连接状态机 | `app/src-tauri/src/tono/connection.rs`（~2900 行，核心） |
| 产品状态/任务注册 | `app/src-tauri/src/tono/state.rs` |
| Tauri 命令 | `app/src-tauri/src/tono/commands.rs` |
| 诊断上报 | `app/src-tauri/src/tono/diagnostics.rs` |
| 服务 IPC 客户端 | `service/src/client/mod.rs` |
| 服务路由 | `service/src/core/server.rs` |
| WFP 门面 | `service/src/core/windows_kill_switch.rs` |
| WFP 规则模型（纯计算，最好测） | `service/src/core/wfp_model.rs` |
| WFP FFI（**测试不编译**） | `service/src/core/wfp.rs` |
| DNS（今晚绝大多数问题的来源） | `service/src/core/dns.rs`（~3800 行） |
| 网络变化监听 | `service/src/core/netmon.rs` |
| 内核进程管理 | `service/src/core/manager.rs` |
| 安装/卸载 helper | `service/src/bin/{install,uninstall}_service.rs` |
| NSIS | `app/src-tauri/packages/windows/installer.nsi` |
| 运行时配置生成 | `crates/tono-core/src/config.rs` |
| vendor 的 IPC 库 | `vendor/kode-bridge/`（我们自己维护，改动带 `// Tono:`） |

---

## 6. 我踩过的坑（别重走）

1. **"证明"一个 Windows 不让你观测的状态。** 注册表无法区分"静态空列表"和"用 DHCP"，所以 IPv6 的受保护状态**原理上证不出来**。曾经把它当作连接门槛，结果 1.1 秒直接失败。
2. **弱证明拦住了强证明。** 施加后读回注册表是弱的、不可靠的；fake-ip 校验是强的、端到端的。曾经让弱的那个把关，强的那个根本没机会跑。
3. **修复引入回归的典型路径**：修 IPv6 泄漏 → 把 v6 DNS 设成 `::1` → 但内核只监听 IPv4 → 解析全超时。而那个"泄漏"本来就被防火墙拦着，属于过度设计。
4. **降级会连锁**。DNS 降级让连接带警告成功 → 警告触发后台每 2 秒重写 DNS → 改 DNS 触发网卡变更通知 → 应用拆隧道重连 → 无限循环。**修一个 bug 前先想它下游还有谁在读这个信号。**
5. **"永远不会失败的测试比没有测试更糟"**，因为它被当成了覆盖率。已加两处测试接缝（环回 DNS 探测、内核终止未确认），让原本结构上不可达的 fail-closed 分支变得可测。
6. **别把"拒绝服务"当成 fail-closed。** 曾经的规则是"除非能证明网络已恢复，否则不许卸载"——结果造出一个卸不掉的软件，而它要防的那个危险（拆了防火墙却留着规则）在拒绝发生之前就已经发生了。
7. **并行改动要对齐契约**。诊断上报的前后端并行开发，字段集完全不同，上传会被 400 拒绝。已加逐字段逐顺序钉死的测试。
8. **ALE 全阻断不等于切换时无泄漏。** ALE 主要决定新连接是否获准；浏览器的长寿命 HTTP/3/QUIC 流可以在 Connect 前完成授权，然后跨过 Locked。安全切换还需要 outbound-transport 逐包默认拒绝。测试不能只启动一个新 `curl.exe`，必须保留同一个浏览器进程和旧标签页跨越 Disconnect → Connect。

---

## 7. 已确定的产品决策（别重新讨论）

- **多用户机器上任何本地用户可接管防火墙所有权** —— 这是现有设计，仓库里有测试明确断言。而且这个无条件接管正是被顶掉的用户能靠重连自救的机制；禁止覆盖反而会造出新的变砖场景。**保持现状**。
- **不禁用 IPv6 协议栈** —— 连接状态下 IPv6 在流量层已经等于关掉（隧道 `ipv6: false` + 防火墙 v6 全阻断）。禁用协议栈买不到额外保护，却会在纯 IPv6 网络上直接断网，且是对用户系统的持久性修改。
- **诊断上报只做用户主动触发**，不做静默自动上报。字段用白名单，不用黑名单。

---

## 8. 只有真机能证明的事（测试时盯这些）

1. 内核完整性校验的接线是否正确（第一个要确认的）
2. 每块网卡的 DNS 施加真实结果（CIM 返回值、netsh 退出码）
3. `TerminateProcess` 后 SCM 是否及时报告已停止
4. 强制停止卡死服务的升级路径是否奏效
5. **虚拟交换机绕过**：连接状态下执行 `wsl -e curl -s -m 5 https://ifconfig.me`，若返回真实公网 IP 即为泄漏。WSL2/Docker/Hyper-V 的流量在 NDIS 层桥接，不经过主机 WFP 连接层。**这不是本轮引入的缺陷，是 WFP 方案的固有边界**，但如果客户机器上装了 WSL 或 Docker，这是最可能的实际泄漏来源
6. 主机普通出站 TCP/UDP 的旧流切换：现在由 `OUTBOUND_TRANSPORT_V4/V6` 逐包覆盖，必须保留同一 Chromium 进程跨越 Connect 并确认旧标签页改为 VPS IP；本机已通过两轮，但要固化为管理员真机集成测试
7. Transport 规则在睡眠/唤醒、网卡切换和接口 LUID 变化后是否仍精确放行 WinTUN、阻断物理旧流
8. 第三方安全软件若使用 WFP 的否决标志，可以压过我们的拦截（我们没用该标志）

---

## 9. 从 Test 6 到 0.0.5 修了什么（25 个提交）

**永久变砖类**：`stop_core` 自死锁（tokio 锁不可重入，持锁作用域内再次加锁，单进程必然触发）；开机时 WFP 看门狗 `Instant` 下溢 panic；状态文件损坏永久拒绝服务；文档承诺的降级出口不存在。

**产品对用户撒谎类**：开机探测把任何 IPC 失败当成"确认已解除"（界面说没保护、断开静默成功、退出把拦截留在机器上）；用户点断开后台任务又装回防火墙；保持拦截的清理路径却跑了释放决策表。

**泄漏与提权类**：暂存资产可命名为 `.exe` 并落入内核路径白名单目录，两次 IPC 即以 SYSTEM 执行且开机重放；身份认证的防护函数写好了却零调用；"停止内核"缺失字段默认解除防火墙；DIRECT 放行在无隧道状态下仍对全机敞开；隧道放行规则可能比它服务的内核活得久。

**连接后半程**（0.0.5，那部分代码真机上从没执行过）：自我触发的重连循环；三处"看起来有实际没有"的阈值；三处与服务端现实不符的预算；出口检查失败的死胡同（隧道已建好却被完全拆除且无法重连）；`lock()` 双读导致"全绿但所有流量被丢弃"。

**基础设施**：服务端终于会写日志了（此前只往 stdout 写，而 Windows 服务没有 stdout——这是我们对客户机器完全瞎的原因）；IPC 库收进自建仓库并加了对端身份验证；管道权限从"所有已认证用户"收紧到仅交互式登录。

**历史测试增长**：service lib 160 起、app 388 起、前端 83 起、打包门 4 起。Windows 续测后的当前可执行基线见 §0A（228 / 432 / 96 / 6）；不要只抄计数，确认测试确实运行且所需 feature 正确。

---

## 10. 建议的下一步顺序

1. 整理并 review 当前未提交工作树，确认只带入本轮 Windows 修复；再提交到 main。不要覆盖用户已有改动。
2. **补真机集成测试**——注意 §0 那个坑，`--features test` 会把真实引擎排除掉，需要单独的、以管理员运行的 WFP/DNS/SCM 测试。第一条固定回归应保留 Chromium 旧 HTTP/3/QUIC 会话跨越 Disconnect → Connect，并检查同一旧标签页、新标签页和新进程出口全部为 VPS；只测新 `curl` 会漏掉本轮 P0。
3. 把 Windows release 流程改写成 PowerShell，保留固定内核 SHA-256 注入和 7-Zip 载荷门；产出新版本安装包后重新跑本节闭环。
4. 优先完成 P0-C：正常卸载、应用被杀后的卸载、覆盖升级、旧 0.0.5 升级到修复版，并证明 WFP/DNS/服务/文件全部收敛。
5. 继续压测 P0-B：睡眠/唤醒、Ethernet/Wi-Fi 切换、断网恢复、WM_ENDSESSION 和长时间连接；一旦出现未响应，按 §2 的泵探针分类。
6. 测 WSL2/Docker/Hyper-V 边界、多用户接管和常见第三方安全软件；这些结果决定客户范围与发布说明。
7. 上述稳定后，再考虑部署诊断上报后端。
