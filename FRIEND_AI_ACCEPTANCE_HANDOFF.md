# Tono 0.0.1 build 3（r4）独立 Mac 测试 handoff

## 目标与已知故障

这是 Apple Silicon/macOS 26.3+ 的 staging 测试，不是生产发布。

r2 已在两台 Mac 稳定复现同一故障：邮件登录、Tailscale enrollment 和
服务端 confirm 均成功，但 `Home-US` 数据面无法完成 SOCKS5 CONNECT，
界面显示：

```text
Tono SOCKS endpoint did not become healthy.
```

Kill Switch 随后正确保持 fail-closed，所以整台 Mac 无法联网。r3 build 2
修复的是错误的产品门控：Home-US 失败不能阻塞独立的 US/Japan 云节点。
r3 会在设备 confirm 后先同步经过验证的托管目录；若 Home-US 不健康，
它会停止该 sidecar，生成不包含 Home-US 的 owned Mihomo 配置，并只允许
选中的托管云节点通过 PF。绝不允许 `DIRECT` 用户流量兜底。
同样的降级也适用于 Home-US 在运行期间失去健康状态：先撤掉旧 TUN
例外并保持 PF 阻断，再用已验证的托管目录建立 cloud-only TUN。

r3 随后证明新 Mac 上第一次目录请求可能在 PF 刷新旧连接状态后失败；
客户端把请求/校验错误吞掉，最终只显示没有云节点。r4 build 3 会在
Home-US 停止后安全重试经过认证的目录，并显示持续失败的真实原因。

## 安全边界

- 不要在无人能操作这台 Mac 时测试。
- 不要索取、读取或记录邮件验证码、管理员密码、Keychain 内容或节点凭据。
- 不要运行 `security dump-keychain`，不要打印 Tono 配置 YAML 或 Tailscale
  state 文件。
- 不要部署 Worker、修改 D1、ACL、服务器目录或撤销其他设备。
- 不要运行 `pfctl -d`，不要清空系统 PF，不要删除 helper/state/Keychain。
- 不要启动仓库、DerivedData 或旧 r2 中的第二份 Tono；只允许
  `/Applications/Tono.app`。
- 发生网络锁定时先恢复，不要反复点击 Retry 或重复登录。

## 0. 首先恢复当前旧版本锁网

在 Terminal 执行：

```sh
pkill -x Tono 2>/dev/null || true
sudo /Library/PrivilegedHelperTools/tono-core-helper --emergency-disarm
```

管理员本人输入密码。成功输出必须是：

```text
Tono network protection is disarmed.
```

然后确认：

```sh
pgrep -x Tono || true
pgrep -x mihomo || true
ifconfig utun199 >/dev/null 2>&1; echo "utun199=$?"
scutil --proxy | egrep 'HTTPEnable|HTTPSEnable|SOCKSEnable'
curl --fail --max-time 15 \
  https://tono-control-plane-staging.xwwelsamqg.workers.dev/api/v1/health
```

预期：Tono/Mihomo 不运行、`utun199` 不存在、三项代理 enable 都为 `0`，
health 返回 `{"ok":true,"version":"0.0.1"}`。若恢复命令失败，立即停止，
只报告原始错误，不要尝试全局关闭 PF。

## 1. 安装与静态验签

退出旧 Tono 后，用
`Tono-0.0.1-build3-Staging-Notarized-Test-20260729-r4.zip` 中的
`Tono.app` 覆盖
`/Applications/Tono.app`。不要从 DMG、Downloads、DerivedData 或 archive
直接启动。

执行：

```sh
codesign --verify --deep --strict --all-architectures \
  /Applications/Tono.app
xcrun stapler validate /Applications/Tono.app
spctl -a -t exec -vv /Applications/Tono.app
/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
  /Applications/Tono.app/Contents/Info.plist
/usr/libexec/PlistBuddy -c 'Print :TonoAPIBaseURL' \
  /Applications/Tono.app/Contents/Info.plist
```

必须满足：

- Gatekeeper 为 `accepted` / `Notarized Developer ID`
- `CFBundleVersion` 为 `3`
- API URL 是固定 staging Worker
- 只存在一个将被启动的 `/Applications/Tono.app`

## 2. 登录与 r3 回归测试

测试邮箱已加入 staging 白名单。验证码和管理员密码由用户本人输入，AI
不得读取。现有 refresh token 可能让它自动恢复，无需再次验证码。

首次启动或恢复后：

1. enrollment/confirm 成功时不得再次停留在 Welcome 页面并报 SOCKS 错误。
2. 如果 Home-US 仍不健康，应用应进入主界面并自动选中一个托管云节点。
3. owned TUN `utun199` 建立后状态应显示已连接。
4. 节点列表应看到 US 与 Japan；Home-US 可显示，但在本次 cloud-only
   session 中选择它必须被拒绝，不能停止云节点后静默直连。

若任何一步再次导致全机断网，立即执行第 0 节恢复命令，保持 Tono 关闭，
记录失败发生在 enrollment、目录同步、Mihomo 启动还是 TUN 建立阶段。

## 3. 每个云节点的最小验收

先测一个节点，确认稳定后再切换另一个。每次选择后等待 UI 明确显示连接
成功，再检查：

```sh
curl --fail --max-time 20 https://api.ipify.org
curl -6 --max-time 10 https://api64.ipify.org || true
ifconfig utun199
pgrep -lf '/Applications/Tono.app|tono-mihomo|mihomo'
scutil --proxy | egrep 'HTTPEnable|HTTPSEnable|SOCKSEnable'
```

验收要求：

- IPv4 出口随 US/Japan 选择发生预期变化。
- 外部 IPv6 不得从本地 ISP 直接成功；失败是允许的。
- `utun199` 存在。
- TUN 模式下 macOS HTTP/HTTPS/SOCKS 系统代理仍为关闭，不依赖应用代理。
- 切换失败时网络应保持阻断，绝不能恢复本地直连。

不要在这一轮停止 VPS 服务或修改服务端配置。节点故障矩阵等基本连接通过
后再单独安排。

## 4. 正常退出与异常恢复

正常测试完成，优先使用菜单栏 Quit。然后确认 `utun199` 消失、系统代理
为 0、普通网络恢复。

只有当 GUI 无法退出时才使用：

```sh
pkill -x Tono 2>/dev/null || true
sudo /Library/PrivilegedHelperTools/tono-core-helper --emergency-disarm
```

不要只 `pkill` 后离开；强制结束 GUI 时 PF 按设计会继续锁网，必须紧接着
运行 emergency-disarm。

## 5. 返回报告格式

只返回以下非敏感信息：

```text
Mac 型号/芯片：
macOS 版本：
Tono CFBundleVersion：
Gatekeeper：
r2 锁网恢复：PASS/FAIL
登录或 session restore：PASS/FAIL
设备 enrollment/confirm：PASS/FAIL
Home-US 失败后进入 cloud-only：PASS/FAIL
US 节点：PASS/FAIL（仅国家/城市，不报告凭据）
Japan 节点：PASS/FAIL（仅国家/城市，不报告凭据）
IPv6 防泄漏：PASS/FAIL
节点切换：PASS/FAIL
正常 Quit 后网络恢复：PASS/FAIL
异常与精确错误信息（先移除邮箱、token、key、UUID）：
```

任何 FAIL 都先恢复网络并停止 Tono；不要自行扩大测试范围。
