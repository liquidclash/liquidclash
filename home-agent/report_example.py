#!/usr/bin/env python3
"""Durable Tono home-exit usage reporter.

The reporter maps Tailscale status peer IDs to Tono users through an
authenticated control-plane inventory and turns per-peer rx/tx counters into
monotonic per-user lifetime totals.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

MAX_STATE_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_INVENTORY_RESPONSE_BYTES = 512 * 1024
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_REPORTS_PER_REQUEST = 500
MAX_USERS_PER_REQUEST = 100
MAX_INVENTORY_DEVICES = 2_000
MAX_TAILSCALE_STATUS_BYTES = 4 * 1024 * 1024
DEFAULT_STATE = "/Library/Application Support/Tono/HomeAgent/state.json"
DEFAULT_TAILSCALE_CLI = "/usr/local/bin/tailscale"
DEFAULT_TOKEN_FILE = "/Library/Application Support/Tono/HomeAgent/token"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise urllib.error.HTTPError(req.full_url, code, "redirects are disabled", headers, fp)


def api_base() -> str:
    raw = os.environ.get("TONO_API_BASE_URL", "https://api.tono.invalid").rstrip("/")
    parsed = urllib.parse.urlsplit(raw)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("TONO_API_BASE_URL must be an HTTPS origin on port 443")
    return raw


def state_path() -> Path:
    value = Path(os.environ.get("STATE_PATH", DEFAULT_STATE))
    if not value.is_absolute():
        raise RuntimeError("STATE_PATH must be absolute")
    return value


def home_agent_token() -> str:
    inline = os.environ.get("HOME_AGENT_TOKEN")
    if inline is not None:
        token = inline
    else:
        path = Path(os.environ.get("HOME_AGENT_TOKEN_FILE", DEFAULT_TOKEN_FILE))
        if not path.is_absolute():
            raise RuntimeError("HOME_AGENT_TOKEN_FILE must be absolute")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or not 1 <= info.st_size <= 4_096
            ):
                raise RuntimeError("home-agent token file must be owned by the service and mode 0600")
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                token = handle.read(4_097).strip()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    if len(token) < 32 or len(token) > 4_096 or any(character.isspace() for character in token):
        raise RuntimeError("HOME_AGENT_TOKEN is invalid")
    return token


def ensure_private_parent(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"state directory is not a real directory: {path}")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RuntimeError(f"state directory must be owned by this service and mode 0700: {path}")


def validate_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("state must be a JSON object")
    totals = value.get("totals", {})
    pending = value.get("pendingReports", [])
    peer_counters = value.get("peerCounters", {})
    if (
        not isinstance(totals, dict)
        or not isinstance(pending, list)
        or not isinstance(peer_counters, dict)
        or len(peer_counters) > MAX_INVENTORY_DEVICES
    ):
        raise RuntimeError("invalid state schema")
    for user_id, total in totals.items():
        if (
            not isinstance(user_id, str)
            or not 1 <= len(user_id) <= 100
            or type(total) is not int
            or not 0 <= total <= MAX_SAFE_INTEGER
        ):
            raise RuntimeError("invalid persisted total")
    report_ids: set[str] = set()
    for report in pending:
        if (
            not isinstance(report, dict)
            or not isinstance(report.get("reportId"), str)
            or not 1 <= len(report["reportId"]) <= 100
            or not isinstance(report.get("userId"), str)
            or not 1 <= len(report["userId"]) <= 100
            or type(report.get("totalBytes")) is not int
            or not 0 <= report["totalBytes"] <= MAX_SAFE_INTEGER
            or type(report.get("observedAt")) is not int
            or not 0 <= report["observedAt"] <= MAX_SAFE_INTEGER
        ):
            raise RuntimeError("invalid pending report")
        if report["reportId"] in report_ids:
            raise RuntimeError("duplicate pending report ID")
        report_ids.add(report["reportId"])
    for stable_id, counter in peer_counters.items():
        if (
            not isinstance(stable_id, str)
            or not 1 <= len(stable_id) <= 200
            or not isinstance(counter, dict)
            or not isinstance(counter.get("userId"), str)
            or not 1 <= len(counter["userId"]) <= 100
            or type(counter.get("lastRawBytes")) is not int
            or not 0 <= counter["lastRawBytes"] <= MAX_SAFE_INTEGER
        ):
            raise RuntimeError("invalid persisted peer counter")
    return {
        "totals": totals,
        "pendingReports": pending,
        "peerCounters": peer_counters,
    }


def load_state(path: Path) -> dict[str, Any]:
    ensure_private_parent(path.parent)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return {"totals": {}, "pendingReports": [], "peerCounters": {}}
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_size > MAX_STATE_BYTES
        ):
            raise RuntimeError("state file must be owned by this service, mode 0600, and at most 1 MiB")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            return validate_state(json.load(handle))
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def save_state(path: Path, state: dict[str, Any]) -> None:
    ensure_private_parent(path.parent)
    payload = json.dumps(validate_state(state), indent=2, sort_keys=True).encode("utf-8")
    if len(payload) > MAX_STATE_BYTES:
        raise RuntimeError("state exceeds 1 MiB")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def read_bounded_json_response(
    response: Any,
    maximum_bytes: int = MAX_RESPONSE_BYTES,
) -> Any:
    response_body = response.read(maximum_bytes + 1)
    if len(response_body) > maximum_bytes:
        raise RuntimeError("control-plane response is too large")
    if not 200 <= response.status < 300:
        raise RuntimeError(f"control plane returned HTTP {response.status}")
    return json.loads(response_body)


def normalized_public_key(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if normalized.startswith("nodekey:"):
        normalized = normalized[len("nodekey:") :]
    if (
        not 1 <= len(normalized) <= 500
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in normalized)
    ):
        return None
    return normalized


def fetch_inventory(base: str, token: str) -> tuple[dict[str, str], dict[str, int]]:
    request = urllib.request.Request(
        f"{base}/api/v1/home/inventory",
        method="GET",
        headers={
            "authorization": f"Bearer {token}",
            "accept": "application/json",
        },
    )
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(request, timeout=20) as response:
        decoded = read_bounded_json_response(
            response,
            MAX_INVENTORY_RESPONSE_BYTES,
        )
    devices = decoded.get("devices") if isinstance(decoded, dict) else None
    if not isinstance(devices, list) or len(devices) > MAX_INVENTORY_DEVICES:
        raise RuntimeError("control-plane inventory is invalid")

    # Confirm verifies this public key against Tailscale's server inventory.
    # Stable ID remains audit metadata, but older Device API responses may not
    # expose it, so it cannot be the authorization root for usage attribution.
    mapping: dict[str, str] = {}
    server_totals: dict[str, int] = {}
    for device in devices:
        if not isinstance(device, dict):
            raise RuntimeError("control-plane inventory is invalid")
        stable_id = device.get("stableNodeId")
        public_key = normalized_public_key(device.get("publicKey"))
        user_id = device.get("userId")
        status_value = device.get("status")
        usage_bytes = device.get("usageBytes")
        if (
            not isinstance(stable_id, str)
            or not 1 <= len(stable_id) <= 200
            or public_key is None
            or not isinstance(user_id, str)
            or not 1 <= len(user_id) <= 100
            or status_value not in ("pending", "active", "revoked")
            or type(usage_bytes) is not int
            or not 0 <= usage_bytes <= MAX_SAFE_INTEGER
        ):
            raise RuntimeError("control-plane inventory is invalid")
        previous_user = mapping.get(public_key)
        if previous_user is not None and previous_user != user_id:
            raise RuntimeError("a verified public key maps to multiple users")
        mapping[public_key] = user_id
        server_totals[user_id] = max(server_totals.get(user_id, 0), usage_bytes)
    return mapping, server_totals


def parse_tailscale_status(value: Any) -> dict[str, tuple[str, int]]:
    peers = value.get("Peer") if isinstance(value, dict) else None
    if peers is None:
        peers = {}
    if not isinstance(peers, dict) or len(peers) > MAX_INVENTORY_DEVICES:
        raise RuntimeError("Tailscale status peer inventory is invalid")

    counters: dict[str, tuple[str, int]] = {}
    for peer_map_key, peer in peers.items():
        if not isinstance(peer, dict):
            raise RuntimeError("Tailscale status peer inventory is invalid")
        stable_id = peer.get("ID")
        public_key = normalized_public_key(peer.get("PublicKey") or peer_map_key)
        rx_bytes = peer.get("RxBytes", 0)
        tx_bytes = peer.get("TxBytes", 0)
        if (
            not isinstance(stable_id, str)
            or not 1 <= len(stable_id) <= 200
            or public_key is None
            or type(rx_bytes) is not int
            or type(tx_bytes) is not int
            or rx_bytes < 0
            or tx_bytes < 0
            or rx_bytes > MAX_SAFE_INTEGER
            or tx_bytes > MAX_SAFE_INTEGER
            or rx_bytes + tx_bytes > MAX_SAFE_INTEGER
            or stable_id in counters
        ):
            raise RuntimeError("Tailscale status peer counter is invalid")
        counters[stable_id] = (public_key, rx_bytes + tx_bytes)
    return counters


def tailscale_cli_path() -> Path:
    configured = Path(os.environ.get("TAILSCALE_CLI", DEFAULT_TAILSCALE_CLI))
    if not configured.is_absolute():
        raise RuntimeError("TAILSCALE_CLI must be absolute")
    resolved = configured.resolve(strict=True)
    info = resolved.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid not in (0, os.geteuid())
        or info.st_mode & 0o022
        or not os.access(resolved, os.X_OK)
    ):
        raise RuntimeError("TAILSCALE_CLI must be a protected executable")
    return resolved


def read_tailscale_peer_counters() -> dict[str, tuple[str, int]]:
    arguments = [str(tailscale_cli_path())]
    socket_path = os.environ.get("TAILSCALE_SOCKET")
    if socket_path:
        socket = Path(socket_path)
        if not socket.is_absolute() or len(socket_path) > 1_024:
            raise RuntimeError("TAILSCALE_SOCKET must be an absolute path")
        arguments.append(f"--socket={socket_path}")
    arguments.extend(["status", "--json"])
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    if len(result.stdout) > MAX_TAILSCALE_STATUS_BYTES:
        raise RuntimeError("Tailscale status is too large")
    if result.returncode != 0:
        message = result.stderr[:500].decode("utf-8", errors="replace").strip()
        raise RuntimeError(message or "Tailscale status failed")
    try:
        decoded = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Tailscale status is not valid JSON") from error
    return parse_tailscale_status(decoded)


def attribute_peer_counters(
    state: dict[str, Any],
    mapping: dict[str, str],
    server_totals: dict[str, int],
    raw_counters: dict[str, tuple[str, int]],
) -> dict[str, int]:
    observed = {
        user_id: max(total, server_totals.get(user_id, 0))
        for user_id, total in state["totals"].items()
    }
    for user_id, total in server_totals.items():
        observed[user_id] = max(observed.get(user_id, 0), total)

    persisted = state["peerCounters"]
    for stable_id, (public_key, raw_total) in raw_counters.items():
        user_id = mapping.get(public_key)
        if user_id is None:
            continue
        previous = persisted.get(stable_id)
        if previous is not None and previous["userId"] != user_id:
            raise RuntimeError("a persisted stable node ID changed users")
        last_raw = int(previous["lastRawBytes"]) if previous is not None else 0
        delta = raw_total - last_raw if raw_total >= last_raw else raw_total
        next_total = observed.get(user_id, 0) + delta
        if next_total > MAX_SAFE_INTEGER:
            raise RuntimeError("attributed user counter exceeds the safe integer range")
        observed[user_id] = next_total
        persisted[stable_id] = {
            "userId": user_id,
            "lastRawBytes": raw_total,
        }
    return observed


def observe_totals(
    state: dict[str, Any],
    base: str,
    token: str,
) -> dict[str, int]:
    mapping, server_totals = fetch_inventory(base, token)
    raw_counters = read_tailscale_peer_counters()
    return attribute_peer_counters(
        state,
        mapping,
        server_totals,
        raw_counters,
    )


def post_reports(base: str, token: str, reports: list[dict[str, Any]]) -> None:
    body = json.dumps({"reports": reports}, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        f"{base}/api/v1/home/usage",
        data=body,
        method="POST",
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "accept": "application/json",
        },
    )
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(request, timeout=20) as response:
        decoded = read_bounded_json_response(response)
        if not isinstance(decoded, dict) or decoded.get("uniqueReports") != len(reports):
            raise RuntimeError("control plane returned an unexpected acknowledgement")


def next_pending_batch(state: dict[str, Any]) -> list[dict[str, Any]]:
    batch: list[dict[str, Any]] = []
    users: set[str] = set()
    for report in state["pendingReports"]:
        user_id = report["userId"]
        if user_id not in users and len(users) >= MAX_USERS_PER_REQUEST:
            break
        if len(batch) >= MAX_REPORTS_PER_REQUEST:
            break
        users.add(user_id)
        batch.append(report)
    return batch


def acknowledge(state: dict[str, Any], reports: list[dict[str, Any]]) -> None:
    if state["pendingReports"][: len(reports)] != reports:
        raise RuntimeError("acknowledgement does not match the pending prefix")
    for report in reports:
        user_id = report["userId"]
        state["totals"][user_id] = max(
            int(state["totals"].get(user_id, 0)),
            int(report["totalBytes"]),
        )
    del state["pendingReports"][: len(reports)]


def deliver_pending(base: str, token: str, path: Path, state: dict[str, Any]) -> int:
    delivered = 0
    while state["pendingReports"]:
        batch = next_pending_batch(state)
        if not batch:
            raise RuntimeError("could not form a valid pending report batch")
        post_reports(base, token, batch)
        acknowledge(state, batch)
        # Persist after every accepted chunk. A crash before this write replays
        # the same immutable IDs; a crash after it proceeds with the remainder.
        save_state(path, state)
        delivered += len(batch)
    return delivered


def main() -> None:
    base = api_base()
    token = home_agent_token()
    path = state_path()
    state = load_state(path)

    # A crash after server acceptance but before local acknowledgement leaves
    # this exact immutable batch on disk. Replaying it is safe and required.
    if state["pendingReports"]:
        delivered = deliver_pending(base, token, path, state)
        print(f"replayed and acknowledged {delivered} pending usage reports")
        return

    observed = observe_totals(state, base, token)
    if not isinstance(observed, dict):
        raise RuntimeError("counter source must return a dictionary")
    timestamp = int(time.time())
    reports: list[dict[str, Any]] = []
    observed_items = list(observed.items())
    for user_id, total in observed_items:
        if (
            not isinstance(user_id, str)
            or not 1 <= len(user_id) <= 100
            or type(total) is not int
            or not 0 <= total <= MAX_SAFE_INTEGER
        ):
            raise RuntimeError("counter source returned invalid data")
    for user_id, total in sorted(observed_items, key=lambda item: item[0]):
        prior = int(state["totals"].get(user_id, 0))
        if total < prior:
            raise RuntimeError(f"counter for {user_id} moved backwards")
        if total > prior:
            reports.append(
                {
                    "reportId": str(uuid.uuid4()),
                    "userId": user_id,
                    "totalBytes": total,
                    "observedAt": timestamp,
                }
            )

    if not reports:
        # Persist new peer baselines even when every observed counter is zero.
        save_state(path, state)
        print("no new usage to report")
        return

    state["pendingReports"] = reports
    save_state(path, state)
    delivered = deliver_pending(base, token, path, state)
    print(f"acknowledged {delivered} usage reports")


if __name__ == "__main__":
    main()
