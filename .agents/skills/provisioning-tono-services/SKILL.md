---
name: provisioning-tono-services
description: "Provisions, names, tunes, rotates, and diagnoses Tono VLESS Reality VPS nodes over SSH; validates Google/YouTube and egress without changing the Mac network; publishes the encrypted catalog; and manages Tono users. Use when adding or operating a Tono server or user."
compatibility: "Requires macOS with ssh/scp, Ruby, Xcode, the project Mihomo binary, and the Tono admin token in Keychain. Fresh-node automation supports Ubuntu 22.04/24.04 or Debian 12 with systemd and root/passwordless sudo."
argument-hint: "SSH alias and node name, or exact user email and requested entitlement change"
---

# Provisioning Tono Services

Operate Tono infrastructure as a staged transaction: inspect, plan, apply, verify end to end, then publish. A reachable TCP port alone is never proof that a node works.

## Non-negotiable safety rules

- Start with read-only preflight and a concrete plan. Obtain explicit approval immediately before remote mutation, firewall changes, D1 migration, Worker deployment, catalog publication, credential rotation, or user disablement.
- Prefer an SSH alias from `~/.ssh/config` that references an existing private-key path. Never ask the user to paste a private key or password into chat, a command argument, the repository, or a log. If a fresh VPS has only password authentication, have the user copy the password to the local clipboard and use the bounded bootstrap below.
- Never use `StrictHostKeyChecking=no`. For a new host, compare its key fingerprint with the VPS provider console before accepting it.
- Never print or log VLESS UUIDs, Reality private keys, public keys, short IDs, admin tokens, full node YAML, authorization headers, or remote configuration bodies.
- Do not modify `/Applications/Tono.app`, macOS routes, PF, TUN, system DNS, or the currently running VPN while provisioning. Use the isolated data-plane test described below.
- Keep node source YAML outside the repository under `~/Library/Application Support/Tono/Operations/catalog.d/`. Require directory mode `0700` and file mode `0600`; reject symlinks.
- Preserve the last working VPS configuration and catalog until the replacement has passed an authenticated Reality handshake. Roll back on any failed step; never publish a partially configured node.
- Try catalog append for a new uniquely named node. Full replacement is destructive and is allowed only when every authoritative catalog source is present, the removal set is empty and reviewed, and optimistic revision control is enabled.

## Add or replace a VPS node

### 1. Collect the bounded input

Require or establish:

- SSH config alias or bounded `root@IPv4` target, independently recorded host-key fingerprint, and whether sudo is available.
- Unique stable node name in `City · Codename` form, transport endpoint IPv4/DNS, expected final egress IPv4 when known, and TCP port (normally 443). Confirm the city using provider/looking-glass evidence, route evidence, and at least one current GeoIP source; do not name from one database alone. Never assume the VPS transport endpoint and final egress are identical.
- Reality server name/destination approved by the operator.
- Path to the authoritative private `catalog.d` directory and whether this is add, replace, or rotate.

Do not silently rename an existing catalog identity. A raw-name change can look like revocation to deployed clients; use a display alias until a stable node-ID migration exists.

### Password-only bootstrap

Use this only when the user explicitly asks to operate a fresh VPS and no key works:

1. Require the password in the macOS clipboard, never in a shell argument. Check only that the clipboard contains one bounded line; never print it.
2. Scan the host key twice, show its SHA-256 fingerprint, and pin the exact accepted key in a mode-`0600` known-hosts file. Stop on a key change.
3. Use a mode-`0700` temporary `SSH_ASKPASS` helper whose only action is `exec /usr/bin/pbpaste`, with `SSH_ASKPASS_REQUIRE=force`. Do not use `sshpass` or place the password in an environment value.
4. Generate a unique temporary Ed25519 deployment key, install only that public key after password authentication, and use key-only `BatchMode=yes` for automation.
5. At the end, remove the exact public-key line remotely, prove that key authentication now fails, delete the local temporary directory, and clear the clipboard. Retain the verified host key, not the deployment credential.

### 2. Run read-only preflight

Use the private provisioner for a fresh supported VPS. It performs this bounded preflight by default and makes no remote changes:

```sh
ruby scripts/provision-reality-node.rb \
  --ssh SSH_ALIAS \
  --name 'UNIQUE NAME' \
  --server PUBLIC_ENDPOINT \
  --expected-exit-ipv4 EXPECTED_EGRESS_IPV4
```

It checks OS/version, CPU architecture, free disk, systemd, passwordless privilege, TCP port occupancy, an existing Tono service, UFW state, and a verified TLS 1.3 handshake from the VPS to the Reality target. Do not read or print existing secret configuration. Omit `--expected-exit-ipv4` only when no authoritative final-egress value exists; the isolated test still records the observed egress.

From the Mac, verify the host key, TCP/443 reachability, and that the expected IPv4 is public. Report conflicts such as nginx already owning 443 before proposing changes.

### 3. Produce an apply and rollback plan

The automated installer intentionally refuses an existing Tono service or occupied port; replacement/rotation needs a separately reviewed rollback plan. For a fresh installation:

- Use an official Xray release pinned to an explicit version and verified SHA-256. Never execute `curl | sh` or an unpinned container tag.
- Run it as a dedicated unprivileged systemd user where the platform permits; grant only the bind capability needed for TCP/443.
- Configure VLESS over TCP Reality with `decryption: none`, `flow: xtls-rprx-vision`, a bounded approved `target/serverNames`, and no unauthenticated fallback listener.
- Generate a fresh UUID, X25519 Reality keypair, and random 8-byte short ID using the installed Xray/OpenSSL CSPRNG. Keep the Reality private key only on the VPS.
- Restrict ingress to the existing management SSH port and the selected Reality TCP port. Do not enable a UDP listener for this Reality-only product.
- Back up the current service/config with owner-only permissions and record the exact rollback command before replacement.

### 4. Apply without exposing credentials

After the dry-run plan and explicit remote-mutation approval, add `--apply` to the exact reviewed provisioner command. The provisioner downloads the pinned official archive on the Mac, verifies its embedded SHA-256, uploads only the verified binary over strict host-key-checked SSH, generates secrets on the VPS, config-tests before activation, and runs Xray as an unprivileged hardened systemd service. It writes the client source directly as a local mode-`0600` file without printing it. Any failed post-install test triggers an exact deployment-ID rollback. It never changes a firewall rule.

Write one private Clash source file locally with this contract:

```yaml
proxies:
  - name: UNIQUE NAME
    type: vless
    server: PUBLIC IPV4
    port: 443
    uuid: GENERATED UUID
    network: tcp
    tls: true
    udp: true
    servername: APPROVED REALITY SERVER NAME
    client-fingerprint: chrome
    flow: xtls-rprx-vision
    reality-opts:
      public-key: GENERATED REALITY PUBLIC KEY
      short-id: GENERATED SHORT ID
```

Set mode `0600` immediately. Never show this completed file in the response.

### 5. Require real client-side verification

The provisioner automatically runs the new node's policy/config validation and isolated data-plane test. Before catalog publication, also validate all authoritative private sources when doing a full replacement:

```sh
scripts/test-multi-exit-policy.sh /absolute/private/catalog.d/*.yaml
scripts/test-isolated-data-plane.sh /absolute/private/catalog.d/new-node.yaml 'UNIQUE NAME' EXPECTED_EGRESS_IPV4
ruby scripts/publish-managed-catalog.rb --dry-run /absolute/private/catalog.d/*.yaml
```

The isolated test starts a temporary loopback-only Mihomo process and changes no TUN, PF, route, or system DNS. Require its authenticated Reality handshake, protected fake-IP DNS, Google/YouTube HTTPS, and proxied public egress-IP checks to pass. Do not treat ping or an open port as success.

### 6. Tune TCP only from measured evidence

Treat a Reality node as a TCP landing/exit server. Before tuning, record OS/kernel, CPU/memory, interface/MTU/routes, socket summary, congestion controls, qdisc/class/filter state, TCP buffers, forwarding/TFO/ECN/syncookies/MTU probing, softnet counters, offloads, running proxy services, and every existing persistent sysctl file.

Run a DF-ping ladder to relevant reachable peers. Do not lower MTU when IPv4 payload 1472 succeeds on the real public path. Compare qdisc drop/backlog and retransmission counters as deltas; never add TBF/HTB or large buffers merely because a generic tutorial recommends them.

When the operator explicitly requests BBR and the kernel exposes `tcp_bbr`, a conservative Tono profile changes only:

```text
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

Before applying:

- Back up `/etc/sysctl.conf`, `/etc/sysctl.d`, and `/etc/modules-load.d` under a timestamped owner-only `/root/tono-network-backups/` directory.
- Refuse to overwrite an existing Tono tuning profile.
- Write `/etc/sysctl.d/99-tono-landing.conf`, `/etc/modules-load.d/99-tono-bbr.conf`, a human-readable `99-tono-landing.profile.md`, and an executable rollback script in the backup directory.
- Record baseline congestion control and both default and live qdisc for exact rollback.

Apply with `modprobe tcp_bbr` and `sysctl --system`. Because `default_qdisc` does not replace an already attached root qdisc, apply `tc qdisc replace dev MAIN_INTERFACE root fq` and automatically restore the previous live qdisc on failure. Verify a fresh SSH connection, `bbr` availability and selection, default/live `fq`, zero new qdisc drops/backlog, active Xray, and TCP/443. Run the isolated data-plane test again after tuning. Do not attribute a one-sample latency improvement to BBR; mainland-client A/B evidence is still required.

### 7. Publish as the final commit point

Summarize the node name, pinned server version, non-secret config digest, health results, old/new catalog membership, and rollback plan. Ask for explicit publication approval.

For a newly added uniquely named node, preserve the deployed catalog and append only the tested source:

```sh
ruby scripts/publish-managed-catalog.rb --append /absolute/private/catalog.d/new-node.yaml
```

`--append` needs the matching Worker, whose authenticated admin GET returns the encrypted catalog only after server-side decryption. It rejects a duplicate name and publishes with optimistic revision control. To deliberately replace the entire catalog, use `--publish` with every authoritative source only after reviewing the removal set.

If `--append` reports that the deployed Worker lacks safe append support, do not redeploy shared infrastructure automatically. Proceed with `--publish` only when every authoritative current source plus the new source is available, a dry-run validates unique names, the expected old/new membership has no unintended removal, and the operator approved publication. The publisher's `expectedRevision` must reject concurrent catalog changes.

The publisher reads the admin token from Keychain, uses `https://api.afk.ccwu.cc`, and performs optimistic revision control. If publication conflicts, stop and reconcile the authoritative catalog; never blindly retry a stale replacement.

After publication, verify the returned revision and perform an authenticated catalog refresh/test without displaying YAML. Keep the prior VPS/config available until a real client confirms the new revision.

## Remove or rotate a node

Deleting a catalog entry does not erase credentials already delivered to clients. For removal, first provision a replacement if needed, publish the catalog without the old node, confirm clients have moved, then rotate or disable the old VPS UUID/Reality key. For suspected compromise, disable the old credential immediately and accept the availability impact. Never reuse a Reality private key or UUID across VPS hosts.

## Authorize and manage users

Users are created only after verified email OTP. Do not insert directly into D1 and do not use the legacy invitation API.

The local helper defaults to dry-run for mutations:

```sh
ruby scripts/manage-tono-user.rb allow person@example.com
ruby scripts/manage-tono-user.rb allow person@example.com --apply
```

Then have the user complete email OTP in Tono. Once the account exists:

```sh
ruby scripts/manage-tono-user.rb show person@example.com
ruby scripts/manage-tono-user.rb set person@example.com --device-limit 2 --quota-bytes unlimited
ruby scripts/manage-tono-user.rb set person@example.com --device-limit 2 --quota-bytes unlimited --apply
```

Disabling a user revokes sessions/devices and can require asynchronous cleanup. Show the planned effect and obtain explicit approval before `--status disabled --apply`. Removing signup authorization does not disable an existing account.

The managed signup API requires migration `0012_signup_allowlist.sql` and the matching Worker version. If they are not deployed, stop and request approval for this shared-infrastructure sequence:

```sh
cd cloudflare
npm test && npm run typecheck
npx wrangler d1 migrations apply tono-control-plane --remote
npx wrangler deploy
```

Never deploy merely because the skill loaded.

## Audit result

Report only non-secret evidence: timestamp, SSH alias, node name/region, software version and checksum, service state, TCP and authenticated handshake results, expected/observed exit country/IP when approved, catalog revision, and rollback status. For users, report the exact requested state transition and API result, not tokens or authentication material.
