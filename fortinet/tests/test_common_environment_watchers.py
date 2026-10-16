"""Environment lookup, file events, and health probe behavior."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO_ROOT), str(REPO_ROOT / "common")]

from fortinet.common.env import get_env, has_env  # noqa: E402
from fortinet.common.file_watcher import FeatureFileWatcher, FileSnapshot  # noqa: E402
from fortinet.common.fos_healthcheck import _heartbeat_size, _read_health, run  # noqa: E402
from fortinet.common.net_mgmt_strategy import NetMgmtStrategy  # noqa: E402


class EnvironmentTests(unittest.TestCase):
    def test_alias_order_dedup_and_legacy_priority(self):
        with patch.dict(os.environ, {
            "FTNT_NEW": "ftnt", "FOS_NEW": "fos", "OLD": "legacy",
        }, clear=True):
            self.assertEqual(get_env("FOS_NEW", "default"), "ftnt")
            self.assertEqual(get_env("FOS_NEW", aliases=("FTNT_NEW",)), "ftnt")
            self.assertTrue(has_env("FOS_NEW"))
        with patch.dict(os.environ, {"FOS_X": "canonical", "OLD_X": "old"}, clear=True):
            self.assertEqual(get_env("FOS_X", legacy_aliases=("OLD_X",)), "canonical")
            self.assertTrue(has_env("ABSENT", aliases=("OLD_X",)))
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(get_env("FOS_X", "fallback", aliases=("X", "X"), legacy_aliases=("FOS_X",)), "fallback")
            self.assertFalse(has_env("FOS_X"))


class FileWatcherTests(unittest.TestCase):
    def test_detect_modify_delete_and_shared_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trigger"
            first, second = MagicMock(), MagicMock()
            first.file_path = second.file_path = path
            first.name, second.name = "first", "second"
            watcher = FeatureFileWatcher([first, second, SimpleNamespace(file_path=None)], MagicMock())
            watcher.poll()
            path.write_text("one")
            watcher.poll()
            first.on_file_detected.assert_called_once_with(path)
            second.on_file_detected.assert_called_once_with(path)
            path.write_text("a longer value")
            watcher.poll()
            first.on_file_modified.assert_called_once_with(path)
            path.unlink()
            watcher.poll()
            first.on_file_deleted.assert_called_once_with(path)
            self.assertEqual(FeatureFileWatcher._event(FileSnapshot(False), FileSnapshot(False)), None)
        logger = MagicMock()
        feature = MagicMock(file_path="/missing")
        feature.name = "broken"
        feature.on_file_detected.side_effect = RuntimeError("callback")
        watcher = FeatureFileWatcher([feature], logger)
        with patch.object(watcher, "_snapshot", return_value=FileSnapshot(True, (1, 2, 3, 4))):
            watcher.poll()
        logger.exception.assert_called_once()

    def test_snapshot_handles_filesystem_errors(self):
        with patch("fortinet.common.file_watcher.Path.stat", side_effect=PermissionError):
            self.assertEqual(FeatureFileWatcher._snapshot(Path("/no-access")), FileSnapshot(False))


class HealthcheckTests(unittest.TestCase):
    def test_health_file_parsing_and_immediate_statuses(self):
        with tempfile.TemporaryDirectory() as directory:
            health = Path(directory) / "health"
            heartbeat = Path(directory) / "beat"
            self.assertIsNone(_read_health(health))
            self.assertEqual(_heartbeat_size(heartbeat), 0)
            health.write_text("invalid")
            self.assertIsNone(_read_health(health))
            health.write_text("bad starting")
            self.assertIsNone(_read_health(health))
            health.write_text("0 healthy")
            self.assertEqual(_read_health(health), (0, "healthy"))
            self.assertEqual(run(health, heartbeat, 1), 0)
            health.write_text("1 VM failed - restarting")
            self.assertEqual(run(health, heartbeat, 1), 1)

    def test_waits_for_heartbeat_then_fails_only_after_stall(self):
        with tempfile.TemporaryDirectory() as directory:
            health, beat = Path(directory) / "health", Path(directory) / "beat"
            health.write_text("1 starting")
            beat.write_bytes(b"1")
            now = [0]
            def sleep(_):
                beat.write_bytes(b"12")
                health.write_text("0 healthy")
                now[0] += 0.5
            self.assertEqual(run(health, beat, 1, sleep=sleep, monotonic=lambda: now[0]), 0)
            health.write_text("1 starting")
            beat.write_bytes(b"12")
            def advance(_):
                now[0] += 0.5
            self.assertEqual(run(health, beat, 1, sleep=advance, monotonic=lambda: now[0]), 1)


class NetMgmtStrategyTests(unittest.TestCase):
    def test_uses_snapshot_mac_and_logs_invalid_address_spacing(self):
        vm = MagicMock()
        vm.mgmt_host_ip = 10
        vm.mgmt_guest_ip = 11
        vm.snapshot_metadata = {"mac_addresses": ["aa:bb"]}
        vm.nic_type = "virtio-net-pci"
        strategy = NetMgmtStrategy()
        strategy.gen_mgmt_netdev = lambda _: "bridge,id=p00"
        self.assertEqual(strategy.gen_mgmt(vm), ["-device", "virtio-net-pci,netdev=p00,mac=aa:bb", "-netdev", "bridge,id=p00"])
        vm.logger.error.assert_called_once()
        vm.snapshot_metadata = {}
        vm.get_mgmt_mac.return_value = "cc:dd"
        self.assertIn("cc:dd", strategy.gen_mgmt(vm)[1])


if __name__ == "__main__":
    unittest.main()
