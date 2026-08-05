# 新 Agent 上手说明 — Tono Windows

你接手的是一个 Windows VPN 客户端。**先读这份，再读 [`TONO_WINDOWS_HANDOFF_2026-08-03.md`](./TONO_WINDOWS_HANDOFF_2026-08-03.md)**（同目录，那份是完整技术交接：当前真机结论、历史问题分析、踩过的坑、产品决策）。

**你应该在一台真实的 Windows 机器上工作。** 原因见下面第 0 节——这不是偏好问题。

> **2026-08-03 续测状态：** 当前未提交工作树已经生成本地安装包 0.0.10（Service 2.6.3），但尚未用它覆盖当前安装，不能发客户。0.0.6 的中国真机曾在 `checkingExit` 收到 Mihomo `/delay` 的 504；0.0.7 又证明 controller 和 App 验证同时依赖同一个 Google URL。现在合成 delay 只作提示，App/TUN 验证并发竞速 Google、Cloudflare、Apple 三个独立 TLS 来源；最后一轮还并行经过本次 Mihomo 的临时 loopback mixed listener，只用于把“节点/内核不可达”和“Windows TUN 路由坏”分开，绝不以代理成功冒充 Connected。0.0.9 覆盖安装另复现了一个更危险的 P0：断开状态下 Service 重启把晚出现的持久 WFP 残留误判为 ownerless emergency block，整机被封网。0.0.10 通过 `wanted:false` 一次性墓碑和安装前状态迁移修复；真实 WFP release 编译与非网络回归已通过，仍需受控覆盖安装真机验证。GitHub 上的 `tono-windows-0.0.5` 仍是旧发布包，继续保持 pre-release、不要发给客户。完整证据与剩余范围见 handoff §0A。

---

## 0. 为什么必须在 Windows 上，以及一个不明显的坑

上一轮开发在 macOS 上交叉编译，五个版本（0.0.1 → 0.0.5）没能让产品在真机上连上一次，而且**在盲改的循环里引入了两次回归**。原因不是水平，是可达性：

| 事实 | 后果 |
|---|---|
| `service/src/core/wfp.rs`（965 行 unsafe FFI）在**任何测试配置下都不编译** | 防火墙逻辑从未被测试执行过 |
| `dns::engine`、`netmon::imp` 等是 `cfg(all(windows, not(feature="test")))` | **真机跑 A 代码，测试跑永远成功的桩 B** |
| `cargo xwin check` 只做类型检查 | 能编译 ≠ 能跑 |

**⚠️ 坑：光把代码放到 Windows 上跑 `cargo test` 仍然测不到真实代码。** 测试要开 `--features test`，而真正的引擎模块正好被 `not(feature = "test")` 排除。

所以**你要做的第一件有价值的事，是补真机集成测试**：以管理员身份运行、直接调用真实 WFP/DNS/SCM。哪怕只有五六个（装规则 → `netsh wfp show filters` 查 → 拆 → 确认干净；设 DNS → `Get-DnsClientServerAddress` 查 → 恢复 → 确认还原），也能在几秒内抓到上一轮花一整夜才定位的问题。

---

## 1. 拿到代码

```powershell
git clone https://github.com/raydocs/liquidclash.git
cd liquidclash
git checkout main          # 交接基线 HEAD: 0eb6879
```

产品在 **`Tono-win/`** 目录下，自成一体。仓库里还有 macOS 的东西（`LiquidClash/` 的 Xcode 工程、`Tono/` 的 macOS 应用），**跟你无关，别动**。

`Tono/reports/` 是文档目录，值得看的：

| 文件 | 内容 |
|---|---|
| `TONO_WINDOWS_HANDOFF_2026-08-03.md` | **完整交接，先读这个** |
| `TONO_WINDOWS_0_0_3_AUDIT_AND_FIX_REPORT_2026-08-03.md` | 五轮审计的完整结论 + 覆盖率证明 |
| `TONO_WINDOWS_WIDEN_PERMITS_DESIGN_2026-08-02.md` | 一个还没实施的性能改造设计（连接提速 5~15 秒） |

---

## 2. 装环境

| 组件 | 说明 |
|---|---|
| **Rust** | `Tono-win/app/rust-toolchain.toml` 钉的是 `1.95.0`；实际用 1.97.1 编译过。工作区 `edition = 2024`、`rust-version = 1.85` |
| **MSVC** | Visual Studio Build Tools + "使用 C++ 的桌面开发" 工作负载（链接器） |
| **Node + pnpm** | `pnpm@11.3.0`（`app/package.json` 的 `packageManager` 钉死）。用 `corepack enable` |
| **WebView2** | Win11 自带；Win10 需装 Runtime |
| **7-Zip** | 载荷门要用，`7z` 或 `7zz` 在 PATH 里 |
| **NSIS** | 不用手装，Tauri 打包时自带 |

`Tono-win/.toolchain/` 是 **macOS 的交叉编译工具链**（cargo-xwin + xwin SDK 缓存 + mac 版 pnpm），**你在 Windows 上不需要它，原生工具链更简单**。

### vendor 的 IPC 库

`Tono-win/vendor/kode-bridge` 是我们自己维护的副本（原先依赖第三方仓库的移动分支，上游随时可能改动地基）。它 `edition = 2021`、有自己的 lint 表，在工作区里是 `exclude` 而不是 member。**所有本地改动都带 `// Tono:` 注释标记**，将来同步上游能一眼找出来。

---

## 3. 先跑通验证

```powershell
cd Tono-win

# 三个 Rust 套件
cargo test --manifest-path crates/tono-core/Cargo.toml --lib                             # 当前 147
cargo test --manifest-path service/Cargo.toml --features "standalone,client,test" --all-targets -- --test-threads=1 # 当前 233 lib + bin/integration
cargo test --manifest-path app/src-tauri/Cargo.toml --lib `
  --features windows-integration-test                                                   # 当前 433

# 前端
cd app
pnpm install
pnpm vitest run          # 应为 96
pnpm tsc --noEmit        # 应无输出
node --test scripts/windows-packaging.test.mjs   # 当前 7 pass
cd ..
```

全绿说明环境没问题。**注意：全绿不代表产品能用**——见第 0 节。

### 中国高延迟真机档位

真机 App 必须用 `windows-integration-test` feature 构建。这个 feature **默认给每个明确标记的远程操作注入 1000ms 延迟**，覆盖账号/目录 API、云策略 DNS、出口探测和最终 TUN 数据面；生产构建编译成 no-op，不受影响。这样美国测试机不会只验证低延迟快乐路径。

```powershell
cargo build --release --manifest-path app/src-tauri/Cargo.toml `
  --features windows-integration-test --bin Tono

# 诊断时可关闭；也可设为 0–5000ms 的其他档位
$env:TONO_WINDOWS_INTEGRATION_LATENCY_MS = "0"
```

默认档位下还必须跑完整连接 → 实际网页流量 → 断开 → DNS 恢复闭环。云策略域名查询最多 4 个并发、瞬时错误重试 3 次、解析总阶段 35 秒；不要为了让测试变绿而放宽生产安全判定。

出口验证的判定顺序不能倒置：Mihomo `/proxies/Tono-Exit/delay` 在 `unified-delay` 下会做双请求，跨境链路可能返回 504；它只能作为辅助测量。真正决定是否允许 Connected 的是 WFP live 状态加全新的 App HTTPS 请求经系统 DNS/WinTUN 成功。该请求不能再绑定一个公共站点：当前竞速 Google 204、Cloudflare 204、Apple 200 三个独立 TLS 来源，任一精确响应即是正证据，全部失败才判失败，并在诊断里逐来源保留 timeout/connect/TLS 原因。后台周期健康检查沿用同一多来源真实 TUN 数据面，不能因为合成 `/delay` 或单一站点抖动而拆隧道。

---

## 4. 构建安装包

Windows 原生构建入口已经是仓库根目录的 `scripts/build-windows-release.ps1`：

```powershell
.\scripts\build-windows-release.ps1 -Version 0.0.10
```

它按顺序做的事：

1. `pnpm release-version <版本号>` — 同步 `package.json` / `tauri.conf.json` / `Cargo.toml` 三处版本
2. `pnpm release:preflight --config-only` — 打包配置门
3. 验证仓库中固定的稳定 Mihomo 内核存在
4. **⚠️ 对本次实际打包的内核计算 SHA-256，并注入 `TONO_CORE_SHA256` 环境变量**
5. 构建三个服务二进制 → 安装到 `app/src-tauri/resources/`
6. `cargo tauri build`
7. 7zz 载荷冒烟检查

**第 4 步绝对不能漏。** 服务会校验 mihomo 的摘要才肯启动，漏了的话表现是"连接直接失败并提示内核校验不通过"——方向是安全的（fail-closed），但产品直接不可用。摘要必须来自**本次实际打包的那个二进制**。

### 载荷门必须过

恰好一个稳定 `verge-mihomo.exe`；无 `verge-mihomo-alpha`；无 `clash-verge-service*` / `set_dns.sh` / `unset_dns.sh`；`Tono.exe` + `tono-service{,-install,-uninstall}.exe` 齐全。历史上有一版就是因为混入这些而作废。

打 tag 前工作树必须干净（preflight 会检查 tag == commit + 三处版本号一致）。`pnpm release-version` 会重排 JSON 格式，构建后记得 `git checkout --` 掉纯格式变更。

---

## 5. 你的前几件事（建议顺序）

### 第一步：拿数据，别猜

在测试机上以管理员身份跑（完整版在 handoff §3）：

```powershell
netstat -ano | Select-String ":53\s"       # 谁在听 127.0.0.1:53
Get-Process mihomo,verge-mihomo            # 内核在不在
Get-DnsClientServerAddress                 # DNS 实际设成什么
Get-Content C:\ProgramData\Tono\logs\tono-service.log -Tail 200
Get-Content "$env:APPDATA\com.raydocs.tono\logs\latest.log" -Tail 200
```

### 第二步：复现已通过的 P0-A 闭环（不要再按 0.0.5 的旧假设排查）

0.0.5 的现象是卡在 `securingDNS`，`fake-ip verification failed: system DNS lookup exceeded 2s`。真机已经把根因收敛：在 `strict-route` + `dns-hijack` + WFP 下，系统解析器打到 `127.0.0.1:53` 会超时；同一时刻显式查询 Tono TUN 端点 `198.18.0.2` 会在几十毫秒内返回 fake IP。

当前工作树的 Service 已改为：IPv4 网卡 DNS 指向 `198.18.0.2`，IPv6 使用静态空列表；恢复路径同时识别当前端点和旧版 `127.0.0.1` / `::1`。真机验证必须看到：

1. 连接保护阶段 `Get-DnsClientServerAddress` 显示 `198.18.0.2`；
2. `Resolve-DnsName -Server 198.18.0.2` 返回 `198.18/16`；
3. 断开后物理网卡恢复原始 DNS（本机基线是 `192.168.31.1`）；
4. `protected-dns.json` 缺失但网卡仍含 `198.18.0.2` 时，连接和拆 WFP 都必须拒绝，绝不能把 Tono 地址存成“用户原始 DNS”。

本机已实际看到前三项，并完成 8 MB、512 KB/s 的持续下载；界面同步显示 525–544 KB/s，core PID 未变化。第 4 项由 Service 测试覆盖，但仍需要补成不带 `feature=test` 的管理员真机集成测试。另一个已修复的真机坑是：Tono 自己的 WinTUN 网卡也合法持有 `198.18.0.2`，DNS 安全检查必须按当前 WFP 验证过的 tunnel LUID 排除它，不能把它误判成丢失快照的物理网卡。

### 第三步：固定复测“第二次连接仍是本地 IP”

旧 WFP 规则只装在 `ALE_AUTH_CONNECT_V4/V6`，只会审查新流。Chromium 在断开状态建立的 HTTP/3/QUIC UDP 会话可跨过下一次 Connect：界面、fake-IP 和新进程 curl 都显示已保护，但同一浏览器连接仍从物理网卡发包，真实出口 IP 仍是本地 IP。这不是页面缓存；同一浏览器进程的新标签页也会复用连接池。

当前规则表 v7（namespace `…9e06…`）在保留 ALE app-id 授权的同时增加 `OUTBOUND_TRANSPORT_V4/V6`：物理接口逐包默认拒绝，WinTUN LUID、核心的精确 VPS tuple、启动 API 和批准的 DIRECT tuple 才有对应许可。每次真机回归都必须按这个顺序：

1. Disconnect 后在 Chromium 打开 IP 检测页，确认本地 IP；
2. Connect 到 Locked，**不关闭浏览器进程**，刷新同一标签页；
3. 同一旧标签页、同进程新标签页和新 `curl.exe` 必须全部显示 VPS IP；
4. Disconnect 后三者恢复本地 IP，DNS 恢复且 core 退出；
5. 再完整重复一次，专门覆盖第二次连接。

本机基线：本地 `172.83.4.82`，Buffalo · Niagara VPS `23.94.79.123`；两轮都通过。单元测试 `outbound_transport_terminates_preexisting_physical_flows` 只钉规则模型，不能替代上面的真实 Chromium 回归。

### 第四步：继续压测 P0-B（本轮未复现假死）

0.0.5 已埋主线程泵探针，**看应用日志就能判定**：

| 日志 | 结论 |
|---|---|
| `Main thread pump STALLED` | 原生主线程卡住 |
| 无停顿但有 `WebView STALLED` | 渲染进程卡住 |
| 两条都没有 | 泵是活的，假死来自进程之外 |

当前工作树在连接、两次持续下载和断开期间均保持 `Responding=true`，但睡眠/唤醒、切换网卡、WM_ENDSESSION 和长时间运行还没完成，因此不能删掉这些探针。

### 第五步：P0-C（卸载）

先强制结束 `Tono.exe` 再卸载，确认是不是被假死连累。如果还不行，要卸载器的确切报错文字。

### 第六步：补真机集成测试

见第 0 节。这是让后续所有工作提速的基础设施。

---

## 6. 恢复被拦死的机器（你和测试者都会用到）

这是 fail-closed 产品，防火墙规则**持久化、开机自恢复**，**重启电脑救不了网络**。三条路，按顺序：

1. **界面里点「断开连接」** — 已确认可用：应用与服务走 Windows 命名管道（本地进程通信，不经过 TCP/IP），本规则集管的是 IP 流量路径且明确放行环回。**全网被拦死时这个按钮照样能用。**
2. **开始菜单 →「Tono — 恢复网络 (Restore Network)」**，点一下弹 UAC
3. **管理员 PowerShell**：
   ```powershell
   taskkill /F /IM Tono.exe
   sc stop TonoService
   & "C:\ProgramData\Tono\bin\tono-service.exe" --emergency-disarm
   ```

---

## 7. 改代码前必须知道的规矩

这些是产品的硬约束，**违反了会造成用户断网或泄漏**：

1. **Fail-closed**：防火墙装上之后，只有「断开 / 登出 / 退出」能解除。崩溃、被杀、睡眠、网络变化、目录问题、API 故障，**一律不解除**。
2. **绝不取消可能已提交的变更请求**：变更类 IPC 只发一次、不重放；响应丢失靠代际号 + 事后修复收敛。
3. **DNS 必须先证明恢复，才能拆防火墙**（唯一例外是卸载路径的降级阶梯，见 handoff）。
   如果恢复快照丢失而网卡仍含 `198.18.0.2`，必须报 `TONO_DNS_SNAPSHOT_MISSING` 并保持门关闭；否则断开会把机器留在死 DNS。
4. **卸载绝不能在防火墙规则还装着时完成**。"拆了防火墙继续卸载"可以；"卸掉应用留着防火墙"绝对不行。
5. **别把"拒绝服务"当成 fail-closed**。曾经的规则是"除非能证明网络已恢复，否则不许卸载"——结果造出一个卸不掉的软件，而它要防的危险在拒绝发生之前就已经发生了。
6. **不能只在 ALE 层做切换安全**。ALE 是新流授权面，不会保证已建立 TCP/QUIC 流在 Connect 后重新分类。所有“从物理出口切到 TUN”的安全边界都必须同时有 outbound-transport 逐包默认拒绝；否则 Connected 只对新进程成立。

### 上一轮踩的坑（handoff §6 有完整版，这里挑最容易重犯的）

- **别去"证明"一个 Windows 不让你观测的状态**。注册表无法区分"静态空列表"和"用 DHCP"，所以 IPv6 的受保护状态原理上证不出来。曾经把它当连接门槛，1.1 秒直接失败。
- **弱证明别拦住强证明**。读回注册表是弱的；fake-ip 校验是端到端的强证明。曾经让弱的把关，强的根本没机会跑。
- **降级会连锁**。DNS 降级让连接带警告成功 → 警告触发后台每 2 秒重写 DNS → 改 DNS 触发网卡变更通知 → 应用拆隧道重连 → **无限循环**。**修一个 bug 前先想它下游还有谁在读这个信号。**
- **"永远不会失败的测试比没有测试更糟"**，因为它被当成了覆盖率。

---

## 8. 已定的产品决策（别重新讨论）

- **多用户机器上任何本地用户可接管防火墙所有权** — 现有设计，仓库里有测试明确断言；而且这个无条件接管正是被顶掉的用户能靠重连自救的机制。保持现状。
- **不禁用 IPv6 协议栈** — 连接状态下 IPv6 在流量层已等于关闭（隧道 `ipv6: false` + 防火墙 v6 全阻断）。禁用协议栈买不到额外保护，却会在纯 IPv6 网络上直接断网。
- **诊断上报只做用户主动触发**，不做静默自动上报；字段用白名单不用黑名单。

---

## 9. 已知的产品边界（不是 bug，但要知道）

- **WSL2 / Docker / Hyper-V 的流量在 NDIS 层桥接，不经过主机的 WFP 连接层** —— 很可能完全绕过隧道。验证：连接状态下 `wsl -e curl -s -m 5 https://ifconfig.me`，返回真实公网 IP 即为泄漏。**这是 WFP 方案的固有边界**，但如果目标用户装了 WSL 或 Docker，这是最可能的实际泄漏来源。
- Windows 主机自身的普通出站流量现由 ALE + outbound-transport 双层覆盖；已建立 TCP/QUIC 的物理包会被逐包阻断并迫使客户端经 TUN 重连。**不要把这个结论外推到 WSL/Hyper-V 虚拟交换机路径**。
- 第三方安全软件若使用 WFP 的否决标志，可以压过我们的拦截（我们没用该标志）。

---

## 10. 下载已构建的安装包

如果只想先跑一下当前版本：

**https://github.com/raydocs/liquidclash/releases/tag/tono-windows-0.0.5**

`Tono_0.0.5_x64-setup.exe`，SHA-256 `e131bc53de08a9eac81db482d165f4476cf2b06874152729983e5f7e7faaf47f`。

**这一版有已知未解决问题，不要发给客户。**
