from __future__ import annotations

import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("report_example.py")
SPEC = importlib.util.spec_from_file_location("tono_home_reporter", MODULE_PATH)
assert SPEC and SPEC.loader
reporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reporter)


class ReporterTests(unittest.TestCase):
    def test_api_origin_is_https_only_and_has_no_credentials_or_custom_port(self) -> None:
        for invalid in (
            "http://api.example.com",
            "https://user:password@api.example.com",
            "https://api.example.com:8443",
            "https://api.example.com/prefix",
        ):
            with self.subTest(invalid=invalid), mock.patch.dict(
                os.environ, {"TONO_API_BASE_URL": invalid}, clear=False
            ):
                with self.assertRaises(RuntimeError):
                    reporter.api_base()

    def test_token_file_must_be_private_and_is_never_a_plist_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / "token"
            token = "test-home-agent-token-with-32-characters"
            token_path.write_text(token, encoding="utf-8")
            token_path.chmod(0o600)
            with mock.patch.dict(
                os.environ,
                {"HOME_AGENT_TOKEN_FILE": str(token_path)},
                clear=True,
            ):
                self.assertEqual(reporter.home_agent_token(), token)

            token_path.chmod(0o644)
            with mock.patch.dict(
                os.environ,
                {"HOME_AGENT_TOKEN_FILE": str(token_path)},
                clear=True,
            ):
                with self.assertRaisesRegex(RuntimeError, "mode 0600"):
                    reporter.home_agent_token()

    def test_state_is_atomic_private_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "private"
            path = parent / "state.json"
            state = {"totals": {"user-one": 12}, "pendingReports": []}
            reporter.save_state(path, state)
            self.assertEqual(
                reporter.load_state(path),
                {
                    **state,
                    "peerCounters": {},
                },
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)

            target = parent / "target.json"
            path.replace(target)
            path.symlink_to(target)
            with self.assertRaises(OSError):
                reporter.load_state(path)

    def test_failed_delivery_is_replayed_with_the_exact_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state" / "state.json"
            environment = {
                "TONO_API_BASE_URL": "https://api.example.com",
                "HOME_AGENT_TOKEN": "test-home-agent-token-with-32-characters",
                "STATE_PATH": str(path),
            }
            with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
                reporter, "observe_totals", return_value={"user-one": 100}
            ), mock.patch.object(
                reporter, "post_reports", side_effect=TimeoutError("simulated timeout")
            ):
                with self.assertRaises(TimeoutError):
                    reporter.main()

            pending_state = reporter.load_state(path)
            self.assertEqual(len(pending_state["pendingReports"]), 1)
            original = pending_state["pendingReports"][0].copy()

            delivered: list[dict] = []

            def accept(_base: str, _token: str, reports: list[dict]) -> None:
                delivered.extend(report.copy() for report in reports)

            with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
                reporter, "observe_totals", side_effect=AssertionError("must replay first")
            ), mock.patch.object(reporter, "post_reports", side_effect=accept):
                reporter.main()

            self.assertEqual(delivered, [original])
            acknowledged = reporter.load_state(path)
            self.assertEqual(acknowledged["pendingReports"], [])
            self.assertEqual(acknowledged["totals"], {"user-one": 100})

    def test_delivery_chunks_at_the_worker_distinct_user_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state" / "state.json"
            reports = [
                {
                    "reportId": f"report-{index}",
                    "userId": f"user-{index}",
                    "totalBytes": index + 1,
                    "observedAt": 1_700_000_000,
                }
                for index in range(101)
            ]
            state = {"totals": {}, "pendingReports": reports.copy()}
            reporter.save_state(path, state)
            batches: list[list[dict]] = []

            def accept(_base: str, _token: str, batch: list[dict]) -> None:
                batches.append([report.copy() for report in batch])

            with mock.patch.object(reporter, "post_reports", side_effect=accept):
                delivered = reporter.deliver_pending(
                    "https://api.example.com", "test-token", path, state
                )

            self.assertEqual(delivered, 101)
            self.assertEqual([len(batch) for batch in batches], [100, 1])
            self.assertEqual(reporter.load_state(path)["pendingReports"], [])

    def test_peer_counters_are_attributed_by_verified_key_and_survive_reset(self) -> None:
        state = {
            "totals": {"user-one": 1_000},
            "pendingReports": [],
            "peerCounters": {},
        }
        mapping = {
            "public-one": "user-one",
            "public-two": "user-one",
        }
        first = reporter.attribute_peer_counters(
            state,
            mapping,
            {"user-one": 1_000},
            {
                "stable-one": ("public-one", 100),
                "stable-two": ("public-two", 50),
                "unmanaged-peer": ("unmanaged-key", 9_999),
            },
        )
        self.assertEqual(first, {"user-one": 1_150})
        state["totals"] = first

        second = reporter.attribute_peer_counters(
            state,
            mapping,
            {"user-one": 1_150},
            {
                "stable-one": ("public-one", 125),
                "stable-two": ("public-two", 10),
            },
        )
        # stable-one advanced by 25; stable-two reset and contributed its new 10.
        self.assertEqual(second, {"user-one": 1_185})

    def test_stable_id_cannot_move_between_users(self) -> None:
        state = {
            "totals": {},
            "pendingReports": [],
            "peerCounters": {
                "stable-one": {
                    "userId": "original-user",
                    "lastRawBytes": 10,
                },
            },
        }
        with self.assertRaisesRegex(RuntimeError, "changed users"):
            reporter.attribute_peer_counters(
                state,
                {"public-one": "different-user"},
                {},
                {"stable-one": ("public-one", 20)},
            )

    def test_tailscale_status_requires_unique_bounded_integer_peer_counters(self) -> None:
        parsed = reporter.parse_tailscale_status({
            "Peer": {
                "nodekey:one": {
                    "ID": "stable-one",
                    "PublicKey": "nodekey:public-one",
                    "RxBytes": 123,
                    "TxBytes": 456,
                },
            },
        })
        self.assertEqual(parsed, {"stable-one": ("public-one", 579)})

        with self.assertRaisesRegex(RuntimeError, "invalid"):
            reporter.parse_tailscale_status({
                "Peer": {
                    "nodekey:one": {
                        "ID": "stable-one",
                        "PublicKey": "nodekey:public-one",
                        "RxBytes": True,
                        "TxBytes": 0,
                    },
                },
            })

    def test_counter_source_types_are_rejected_before_sorting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state" / "state.json"
            environment = {
                "TONO_API_BASE_URL": "https://api.example.com",
                "HOME_AGENT_TOKEN": "test-home-agent-token-with-32-characters",
                "STATE_PATH": str(path),
            }
            with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
                reporter, "observe_totals", return_value={"valid-user": 1, 7: 2}
            ):
                with self.assertRaisesRegex(RuntimeError, "counter source returned invalid data"):
                    reporter.main()

    def test_duplicate_pending_report_ids_are_rejected(self) -> None:
        report = {
            "reportId": "same-report",
            "userId": "user-one",
            "totalBytes": 42,
            "observedAt": 1_700_000_000,
        }
        with self.assertRaisesRegex(RuntimeError, "duplicate pending report ID"):
            reporter.validate_state(
                {"totals": {}, "pendingReports": [report, report.copy()]}
            )


if __name__ == "__main__":
    unittest.main()
