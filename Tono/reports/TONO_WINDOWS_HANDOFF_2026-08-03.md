# Tono Windows — 完整 Handoff（2026-08-03）

**当前版本:** 0.0.5（`tono-windows-0.0.5`，commit `69746a2`）
**状态:** 真机上仍然连不上，卡在 `securingDNS` 的 fake-ip 校验；窗口会假死；卸载受阻。
**这份文档的目的:** 让接手的人（或换台机器的你）不用重走我踩过的路。

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

### 构建脚本要重写

`scripts/build-windows-release.sh` 是 zsh + `cargo xwin`，Windows 上跑不了。它做的事按顺序是：

1. `pnpm release-version <ver>` —— 同步 package.json / tauri.conf.json / Cargo.toml 三处版本号
2. `pnpm release:preflight --config-only` —— 打包配置门（防止 Test 5 那种混入 alpha 内核和 Unix 脚本的事故）
3. 构建 mihomo（`build-mihomo-adaptive.sh --install-adaptive-windows`）
4. **计算内核 SHA-256 并注入 `TONO_CORE_SHA256` 环境变量** ← 这一步不能漏，见 §4
5. 构建三个服务二进制，安装到 `app/src-tauri/resources/`
6. `cargo tauri build`
7. 7zz 载荷冒烟检查

Windows 上写个 PowerShell 等价物即可，第 4 步务必保留。

---

## 2. 当前未解决的问题（按优先级）

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

1. 界面里点「断开连接」——**已确认可用**：应用与服务走 Windows 命名管道（本地进程通信，不经过 TCP/IP），防火墙只作用在网络连接层，且持久化兜底规则明确放行环回。全网被拦死时这个按钮照样能用。
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
6. 入站已建立连接的出站数据不受管辖（只在连接层拦截）
7. 上防火墙那一刻已存在的连接不会被重置
8. 第三方安全软件若使用 WFP 的否决标志，可以压过我们的拦截（我们没用该标志）

---

## 9. 从 Test 6 到 0.0.5 修了什么（25 个提交）

**永久变砖类**：`stop_core` 自死锁（tokio 锁不可重入，持锁作用域内再次加锁，单进程必然触发）；开机时 WFP 看门狗 `Instant` 下溢 panic；状态文件损坏永久拒绝服务；文档承诺的降级出口不存在。

**产品对用户撒谎类**：开机探测把任何 IPC 失败当成"确认已解除"（界面说没保护、断开静默成功、退出把拦截留在机器上）；用户点断开后台任务又装回防火墙；保持拦截的清理路径却跑了释放决策表。

**泄漏与提权类**：暂存资产可命名为 `.exe` 并落入内核路径白名单目录，两次 IPC 即以 SYSTEM 执行且开机重放；身份认证的防护函数写好了却零调用；"停止内核"缺失字段默认解除防火墙；DIRECT 放行在无隧道状态下仍对全机敞开；隧道放行规则可能比它服务的内核活得久。

**连接后半程**（0.0.5，那部分代码真机上从没执行过）：自我触发的重连循环；三处"看起来有实际没有"的阈值；三处与服务端现实不符的预算；出口检查失败的死胡同（隧道已建好却被完全拆除且无法重连）；`lock()` 双读导致"全绿但所有流量被丢弃"。

**基础设施**：服务端终于会写日志了（此前只往 stdout 写，而 Windows 服务没有 stdout——这是我们对客户机器完全瞎的原因）；IPC 库收进自建仓库并加了对端身份验证；管道权限从"所有已认证用户"收紧到仅交互式登录。

**测试基线**：service lib 160 → **238**；app 388 → **428**；前端 83 → **96**；打包门 4 → **5**。

---

## 10. 建议的下一步顺序

1. **搬到 Windows**，装齐 §1 的环境，把构建脚本改写成 PowerShell（保留内核摘要注入）
2. **补真机集成测试**——注意 §0 那个坑，`--features test` 会把真实引擎排除掉，需要单独的、以管理员运行的集成测试
3. **拿 §3 的诊断数据定位 P0-A**（`port53.txt` + `mihomo-proc.txt` 能直接分辨两个候选）
4. **看应用日志判定 P0-B 假死在哪一侧**（探针已就位）
5. 强制结束进程后再试卸载，确认 P0-C 是不是被假死连累
6. 上述稳定后，再考虑部署诊断上报后端

搬过去之后，前四步很可能一个下午就能全部定位——而在 macOS 上，它们花了我一整夜还没收敛。
