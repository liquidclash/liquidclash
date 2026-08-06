# Tono home usage agent

The Cloudflare Worker accepts monotonic usage reports at `POST /api/v1/home/usage`.
This directory is the Mac Studio side agent that attributes exit-node traffic to
Tono user IDs and reports totals.

## Status

Verified-public-key attribution is implemented and covered by local tests, but
it is not deployed. The Worker supplies a token-protected
`GET /api/v1/home/inventory` mapping containing the public key already matched
against server inventory during confirm. The reporter reads
`tailscale status --json`, attributes each peer's `RxBytes + TxBytes` by that
key, retains the actual status stable ID for reset continuity/audit, turns
counter resets into monotonic deltas, and durably reports per-user lifetime
totals. Quota enforcement on the Worker is real only after this service is
installed and validated on the exit node.

## Contract

```http
POST /api/v1/home/usage
Authorization: Bearer <HOME_AGENT_TOKEN>
Content-Type: application/json

{
  "reports": [
    {
      "reportId": "uuid-or-dedupe-key",
      "userId": "tono-user-id",
      "totalBytes": 123456789,
      "observedAt": 1710000000
    }
  ]
}
```

Rules:

- `totalBytes` is a **monotonic lifetime total** per user, not a delta.
- `reportId` is an immutable idempotency key. An exact replay is accepted;
  reusing it with a different user, total, or timestamp returns
  `409 USAGE_REPORT_CONFLICT`.
- Out-of-order lower totals must not decrease `users.usage_bytes` (Worker uses `MAX`).
- Persist the complete pending batch before sending it. After a timeout or
  crash, retry that exact batch before generating any new report IDs.
- Keep state in a service-owned `0700` directory and a `0600` regular file.

## Deployment work remaining

1. Deploy the Worker version containing `/api/v1/home/inventory`.
2. Configure an absolute, protected `TAILSCALE_CLI` path that can read the
   Mac Studio daemon; set `TAILSCALE_SOCKET` only for a non-default LocalAPI
   socket.
3. Run every 60 seconds under launchd with a protected service identity and
   secret storage; add exponential retry scheduling around process invocations.
4. Generate traffic from two real Tono clients, verify peer/user attribution,
   then test daemon reset, revocation, and quota enforcement. The counters are
   encrypted Tailscale peer bytes (including protocol overhead), not an
   application-payload meter.

## Environment

```bash
export TONO_API_BASE_URL="https://api.example.com"
export HOME_AGENT_TOKEN_FILE="/absolute/service-owned/mode-0600/token"
export STATE_PATH="/Library/Application Support/Tono/HomeAgent/state.json"
export TAILSCALE_CLI="/absolute/protected/path/to/tailscale"
# export TAILSCALE_SOCKET="/absolute/path/to/tailscaled.sock"
```

`HOME_AGENT_TOKEN` is accepted for local/manual testing, but a launchd service
should use the protected token-file path so the secret is not embedded in a
world-readable plist. The file contents are the same value stored as the
Worker's `HOME_AGENT_TOKEN` secret; never commit it.

The reporter refuses ambiguous verified-key mappings, cross-user stable-ID
reuse, unsafe CLI paths, malformed/unbounded status, invalid counters, and
totals outside the safe-integer range. Its HTTPS-only delivery, no-redirect
behavior, response bounds, private atomic state, and exact-replay logic are
part of the contract.
