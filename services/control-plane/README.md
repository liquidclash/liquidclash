# Tono Cloudflare control plane 0.0.1

完全独立的 Cloudflare Worker + Static Assets + D1 子项目。所有 API 位于 `/api/v1`，管理页面位于 `/`。没有 secret 会被发送到客户端或写入日志。

## 部署

```sh
npm install
npx wrangler d1 create tono-control-plane
# 将输出的 database_id 写入 wrangler.jsonc
npx wrangler d1 migrations apply tono-control-plane --remote
npx wrangler secret put JWT_SECRET
npx wrangler secret put ADMIN_API_TOKEN
npx wrangler secret put HOME_AGENT_TOKEN
npx wrangler secret put TAILSCALE_OAUTH_CLIENT_ID
npx wrangler secret put TAILSCALE_OAUTH_CLIENT_SECRET
npx wrangler secret put CATALOG_ENCRYPTION_KEY
# 启用邮件验证码时：
npx wrangler secret put RESEND_API_KEY
npm run deploy
```

本地开发：复制 `.dev.vars.example` 为 `.dev.vars`（不可提交），创建本地数据库后运行 `npx wrangler d1 migrations apply tono-control-plane --local && npm run dev`。部署前修改 `ALLOWED_ORIGIN`、`TAILSCALE_TAILNET` 和 `EMAIL_FROM`。`DIRECT_SIGNUP_ALLOWLIST` 只作为初始管理员的兼容启动配置；日常添加精确邮箱应使用 `/api/v1/admin/signup-allowlist`，避免修改配置并重新部署 Worker。测试仍可用 `@example.com` 配置允许一个完整域，但管理员 API 只接受精确邮箱。`APPLE_CLIENT_ID`、`GOOGLE_CLIENT_ID` 是公开的 OAuth client ID，不是 secret；留空时对应按钮会从 `/auth/methods` 隐藏。建议对管理页面及 `/api/v1/admin/*` **额外配置 Cloudflare Access**；Worker 内的 `ADMIN_API_TOKEN` 仍为第二层鉴权。

## 安全与行为决策

- 账号认证为无密码模式：邮件一次性验证码、Sign in with Apple、Google OIDC。迁移 `0009` 会销毁旧的可复用密码 verifier，旧 `/auth/login`、`/auth/redeem` 固定返回 `410 PASSWORD_AUTH_DISABLED`。
- 邮件验证码固定 6 位、默认 10 分钟、最多 5 次、原子单次消费，并绑定 `installationId` 与 device name。D1 只保存由 `JWT_SECRET` 加 HMAC pepper 的 challenge hash；allowlist 中的邮箱验证成功后可直接创建测试账号，不需要邀请码。开始接口统一返回 `202`，不会泄露 allowlist 成员资格；Resend delivery 在 `waitUntil` 中执行。发送失败会使 challenge 失效；代码和邮件正文不写日志。
- Apple/Google 每次登录先创建 256-bit nonce challenge。Worker 从固定 HTTPS JWKS endpoint 验证 RS256 签名、`iss`、`aud`、`exp`、`iat`、`nonce`、`sub` 和 verified email；token 只用于当次验证，不保存。原生 Apple AuthenticationServices 与 Google 桌面 loopback/state/S256-PKCE 实现仅保留在 Debug；Developer ID Release 为邮件验证码登录，未来如需 Apple/Google 应使用网页流程。
- access token 是 15 分钟 HS256 JWT；refresh token 仅以 SHA-256 hash 保存并原子轮换。`POST /auth/logout` 必须带 access Bearer，可选正文 `{refreshToken}`，只撤销该 access token 对应 session（不会登出其他设备）。禁用用户立即撤销全部 session，access/refresh 都会再次检查用户状态。
- 旧 invitations 表和管理 API 暂时保留以避免破坏性迁移，但测试阶段的邮件/OIDC 登录路径不会读取或消费邀请。
- 迁移 `0012` 增加精确邮箱 signup allowlist。管理员可用 `GET/POST/DELETE /admin/signup-allowlist` 查询、授权或撤销未来注册；授权邮箱仍必须完成一次性验证码，撤销注册资格不会隐式禁用已经存在的账号。配置 allowlist 继续作为升级兼容的启动入口。
- D1 trigger 在数据库层保证每用户 `pending + active <= 2`，并发插入也无法越限。登录先回收超时 pending；相同 `installationId` 返回原设备且不占名额。默认 pending 30 分钟。
- access JWT 只提供 session 定位信息；每次鉴权都从 D1 重读 user/session/device/installation、账号期限和 quota。即使攻击者拿到签名能力并伪造 JWT 中的 device/install claim，也不能跨设备操作。
- enrollment key 由 Worker 使用 Tailscale OAuth secret 服务端签发：10 分钟、preauthorized、non-reusable、ephemeral，初始只有**无联网 grant** 的 `tag:pending-tunnel-client`。每次签发还生成不可猜测的 `tono-<32 hex>` hostname；客户端将它传给 `tailscale up --hostname`，confirm 必须在服务端 inventory 中看到同一 hostname。同设备签发有 60 秒 D1 原子冷却；上游签发失败会释放该租约。
- confirm 要求客户端的 stable ID、public key 和完整 IP 集合（可附 `nodeId`），并绑定上述服务端签发 hostname，只通过 tailnet inventory 解析。Worker 分开保存管理 `id`、API `nodeId`、stable ID 和 public key；以短租约 + ownership generation 抢占、在 promotion 前写 durable guard，并仅用管理 `id` 调 Tailscale tag/DELETE API。撤销先关闭 D1 session/device，再由持久 outbox 重试；Tailscale API 临时故障不会丢失删除任务。被禁用用户仍有 live device 或未完成 job 时不能重新启用。
- `/home/inventory` 与 `/home/usage` 都使用 `HOME_AGENT_TOKEN`。inventory 只返回 confirm 时已经过服务端 inventory 验证的 public key、stable node ID 审计字段、Tono user ID、device status 与已有 usage floor；家庭 exit agent 以 public key 对照 `tailscale status --json` 的 per-peer rx/tx，不把可能仅由客户端上报的 stable ID 当作归属边界。响应不返回邮箱、installation ID 或 Tailscale 管理/API ID。usage 接收 `{reports:[{reportId,userId,totalBytes,observedAt}]}`，选择**单调绝对计数**：相同 `reportId` 的完全一致重放成功，不同内容重用返回 `409 USAGE_REPORT_CONFLICT`；用户计数取 `MAX`，乱序不会倒退。每批 1–500 条、最多 100 个不同用户。家庭代理必须先持久化完整 pending batch，超时/崩溃后原样重放，且不能在重启时清零累计值。
- 邮件 start/verify 与 OIDC challenge/verify 分别按哈希后的 IP、email、installation 或 challenge 做 D1 原子窗口限流；失败验证同样消耗配额。challenge 由 cron 清理。
- 登录后的 `GET /exit-catalog` 返回带单调 revision 和 SHA-256 的完整节点
  YAML；未认证请求不能读取。管理员 `PUT /admin/exit-catalog` 必须提交
  完整 YAML，可带 `expectedRevision` 防止并发覆盖；经 admin token 鉴权的
  `GET /admin/exit-catalog` 返回当前明文供私有运维工具做安全增量合并。D1 只保存
  AES-256-GCM 密文、随机 nonce 和摘要；32-byte base64url
  `CATALOG_ENCRYPTION_KEY` 只存在于 Worker secret。目录最大 1 MiB。
  删除目录项不会远程抹除已授权客户端曾经获得的凭据；需要强制失效时
  必须同时轮换对应 VPS 凭据。
- CORS 只接受精确的 `ALLOWED_ORIGIN`；无 Origin 的原生客户端允许。错误统一为 `{"error":{"code","message"}}`。实现不记录请求正文、验证码、ID token、refresh token 或 key。

## Tailscale ACL 示例

OAuth client 只授予上述 scopes；tailnet policy 中声明标签所有者并限制客户端：

```json
{
  "tagOwners": {
    "tag:tono-controller": ["group:tono-admins"],
    "tag:pending-tunnel-client": ["tag:tono-controller"],
    "tag:tunnel-client": ["tag:tono-controller"],
    "tag:exit-home": ["group:tono-admins"]
  },
  "autoApprovers": {
    "exitNode": ["tag:exit-home"]
  },
  "grants": [{
    "src": ["tag:tunnel-client"],
    "dst": ["autogroup:internet"],
    "via": ["tag:exit-home"],
    "ip": ["*"]
  }]
}
```

这是需在目标 tailnet 中用 Tailscale policy tester 验证的最小示例（当前 HuJSON policy `grants` 语法）：只有已 promotion 的 `tag:tunnel-client` 能经 `tag:exit-home` 广告的 exit node 前往 `autogroup:internet`；**不得**给 `tag:tono-controller`、`tag:pending-tunnel-client`、`*` 或 `autogroup:tagged` 任何 Internet grant。不要增加面向家庭 LAN、NAS、SSH 或 exit host 本身的 grant。repository 内的 artifact 不会自动修改 tailnet；staging tailnet 已由管理员应用并通过 policy tests，但仍需添加真实 `tag:exit-home` 设备并验证 exit route。其他环境必须分别应用和验证。为 Worker 创建 OAuth client 时，只授予 `auth_keys` 与 `devices:core` scopes，并只选择 grantless 的 `tag:tono-controller`；该 tag 通过所有权层级管理 pending/active 客户端 tag。不要把 `tag:exit-home` 的所有权交给 Worker。

## 客户端合同（v1）

- 远程诊断为设备本地明确 opt-in 的 15 秒 pull。管理员只能排队四个无参数固定动作：`diagnostic_snapshot`、`claude_traffic_snapshot`、`refresh_catalog`、`retry_protection`；服务端拒绝额外字段、代码和通用参数。`GET device-actions` 只返回当前 access session 设备的未过期 pending/delivered 动作并重复 delivered 直到终态；`POST device-actions/:id/result` 只接受固定、受限的 succeeded/failed 结果与已知紧凑状态字段。普通诊断快照不上传日志正文、原始错误、域名、IP、路径、进程、凭据或内部节点 ID，只用白名单错误类别标记失败阶段。Claude 流量研究需要设备用户第二次单独 opt-in，只从内存返回官方 `claude.ai` / `anthropic.com` endpoint 与可明确归因给 Claude App/Code 的非官方 destination host 前四组聚合，并报告全局代理/直连/阻断计数、进程识别覆盖率、Mihomo DIRECT 尝试、受控国内直连计数和 TUN/Kill Switch/DNS 状态。快照还执行两个无参数固定探针：比较普通系统 TUN 与 Mihomo 显式代理出口是否一致，以及在基准 HTTPS 目标确认可达后强制绑定物理网卡是否被 PF 阻断；云端只接收枚举判定，原始出口 IP 仅写入设备本地 mode-0600 audit。浏览器非官方请求、无法识别进程的非官方请求和相似第三方域名不会被猜测为 Claude 流量；客户端不读取 audit 文件，也不上传 URL、IP、进程名、路径或内容。所有结果上限 2 KiB。默认 TTL 5 分钟，最大 1 小时。

- `GET auth/methods` 返回 `{email,apple,google:{enabled,clientId?}}`；只有服务端配置完整的方法为 enabled。
- `GET exit-catalog` 需要 access Bearer，返回
  `{revision,yaml,sha256,updatedAt?}`。revision 只递增；无目录时返回
  revision `0` 与 `proxies: []`。客户端必须验证摘要、节点策略和本地
  anti-rollback，不能把源 YAML 的 TUN/DNS/rules/controller 直接交给
  Mihomo。
- 邮件：`POST auth/email/start` 接收 `{email,deviceName,installationId}`，总是以通用 `202` 返回 `{challengeId,expiresIn,message}`；`POST auth/email/verify` 接收 `{challengeId,code}`。
- Apple/Google：`POST auth/oidc/challenge` 接收 `{provider,deviceName,installationId}`，返回 `{challengeId,nonce,expiresIn,audience}`；客户端获得 provider ID token 后向 `POST auth/oidc/verify` 发送 `{provider,challengeId,idToken}`。
- 三种 verify 的成功 envelope 都是 `{accessToken,refreshToken,user,device,enrollment?}`。pending 设备必有 `enrollment:{id?,authKey,hostname,expiresAt,state:"pending"}`，active 设备没有 enrollment。
- `POST devices/:id/enrollment` 请求体固定为 `{installationId}`，返回 `{enrollment:{id?,authKey,hostname,expiresAt,state}}`，且只允许 D1 session 绑定的同一 device/installation。active 设备借此替换丢失的本地 sidecar identity 时，旧 identity 会先进入 durable revocation 流程；只要该设备仍有未完成的 revocation job，就返回 `409 REVOCATION_PENDING`，不会签发 replacement key。
- `POST devices/:id/confirm` 请求固定为 `{stableNodeId,publicKey,tailscaleIPs,nodeId?}`；成功 promotion 后返回 `{device}`。`stableNodeId` 是本地 status 的审计身份，`publicKey`/`nodeId` 用于 inventory 可验证匹配，Tailscale 管理 `id` 只来自服务端 inventory。
- `user` 固定包含 `id,email,deviceLimit:2,quotaBytes,usageBytes,suspended,status,createdAt`，可选 `name,plan,expiresAt`。`device` 包含 `id,name,installationId,current,status,pendingExpiresAt,tailscaleNodeId,tailscaleIPs,lastSeenAt,confirmedAt,createdAt`；`current` 由 access token session 的 device id 判定，而不是由列表顺序推断。
- 所有时间是 Unix 秒（Tailscale 返回的 key `expiresAt` 保持其 API 值）；所有失败均为 `{error:{code,message}}`。原生客户端不发送 Origin；浏览器 Origin 必须精确匹配 `ALLOWED_ORIGIN`，preflight 与错误响应同样带 CORS headers。

## 检查

```sh
npm test
npm run typecheck
```

当前本地基线：Vitest 4.1.10 / Workers pool 0.18.8 测试与
typecheck 通过。测试覆盖邮件验证码 hash/单次
消费/并发/限流、OIDC 签名/audience/nonce/replay、Apple email linking，
home inventory 最小披露、目录 AES-GCM 篡改检测/加密存储/并发 revision，
以及原有 control-plane 状态机。迁移必须按 `0001` 到 `0012` 顺序应用。
`0010`、目录 secret、目录 API 已部署到 staging，初始美国/日本双节点
目录为 revision 1；production 仍未部署。
