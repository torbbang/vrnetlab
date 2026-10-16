"""License restore and validation feature state transitions."""

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from fortinet.common.cli_commands import CommandAttempt, CommandSpec, SessionLossAction  # noqa: E402
from fortinet.common.common import FOSCliState  # noqa: E402
from fortinet.common.features.license import (  # noqa: E402
    DEFAULT_LICENSE_STATUS_TIMEOUT_SECONDS,
    LICENSE_SETTLE_SECONDS,
    SetLicense,
    WaitForLicenseValidation,
    license_status_timeout_seconds,
    wait_for_valid_license,
)
from fortinet.common.terminal import Data  # noqa: E402


def command(line="get system status", output=b""):
    item = CommandAttempt(CommandSpec(line, capture_output=True), 1, 0)
    item.output.extend(output)
    return item


class SetLicenseTests(unittest.TestCase):
    def test_disabled_install_and_failed_restore(self):
        cmd = MagicMock()
        owner = SimpleNamespace(mgmt_gw_ipv4="192.0.2.1", driver=MagicMock())
        with patch("fortinet.common.features.license.os.path.exists", return_value=False):
            feature = SetLicense(owner, cmd)
        feature.activate()
        cmd.feature_complete.assert_called_with(feature)
        cmd.submit_block.reset_mock()
        with patch("fortinet.common.features.license.os.path.exists", return_value=True):
            feature = SetLicense(owner, cmd)
        feature.activate()
        owner.driver.set_prompt_patterns.assert_called_once()
        self.assertEqual(cmd.submit_block.call_args.args[1].children[0].session_loss, SessionLossAction.CONTINUE)
        with self.assertRaisesRegex(RuntimeError, "install failed"):
            feature.on_output(Data(b"VM license install failed"))
        with self.assertRaisesRegex(RuntimeError, "install failed"):
            feature.on_command_executed(command("restore", b"license install failed"), FOSCliState.CMD_PROMPT)
        feature._phase = "restore"
        feature.on_command_executed(command("restore"), FOSCliState.CMD_PROMPT)
        self.assertEqual(feature._phase, "wait-prompt")
        feature.on_block_complete()
        self.assertFalse(feature._wait_for_prompt)
        feature.on_block_complete()
        cmd.feature_complete.assert_called_with(feature)

    def test_confirmation_reboot_and_session_loss(self):
        cmd = MagicMock()
        owner = SimpleNamespace(mgmt_gw_ipv4="gw", driver=MagicMock())
        with patch("fortinet.common.features.license.os.path.exists", return_value=True):
            feature = SetLicense(owner, cmd)
        feature._phase = "restore"
        feature.on_command_executed(command("restore"), FOSCliState.CONFIRMATION)
        self.assertEqual(feature._phase, "restore-confirmed")
        self.assertEqual(cmd.submit_block.call_args.args[1].children[0].line, "y")
        feature.on_command_executed(command("y"), FOSCliState.REBOOTING)
        self.assertTrue(feature._wait_for_prompt)
        attempt = command("restore")
        attempt.spec = CommandSpec("restore", session_loss=SessionLossAction.CONTINUE)
        self.assertEqual(feature.on_session_loss(attempt), SessionLossAction.CONTINUE)
        self.assertEqual(feature._phase, "wait-prompt")
        feature._phase = "done"
        feature.on_block_complete()
        cmd.feature_complete.assert_called_with(feature)


class LicenseValidationTests(unittest.TestCase):
    def setUp(self):
        self.commander = MagicMock()
        self.commander.logger = MagicMock()
        self.vm = SimpleNamespace()

    def test_disabled_settings_status_parsing_and_valid_completion(self):
        with patch("fortinet.common.features.license.os.path.exists", return_value=False):
            feature = WaitForLicenseValidation(self.vm, self.commander)
        feature.activate()
        self.commander.feature_complete.assert_called_with(feature)
        with patch.dict(os.environ, {"FOS_LICENSE_STATUS_TIMEOUT_SECONDS": "17"}, clear=True):
            self.assertEqual(license_status_timeout_seconds(), 17)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(license_status_timeout_seconds(), DEFAULT_LICENSE_STATUS_TIMEOUT_SECONDS)
            self.assertFalse(wait_for_valid_license())
        with patch.dict(os.environ, {"FOS_WAIT_FOR_VALID_LICENSE": " TRUE "}, clear=True):
            self.assertTrue(wait_for_valid_license())
        self.assertEqual(WaitForLicenseValidation._license_status(b"License Status: Valid\n"), "Valid")
        self.assertEqual(WaitForLicenseValidation._license_status(b"License: Grace period\n"), "Grace period")
        self.assertIsNone(WaitForLicenseValidation._license_status(b"unknown"))
        with patch("fortinet.common.features.license.os.path.exists", return_value=True):
            with patch("fortinet.common.features.license.time.monotonic", return_value=10):
                feature = WaitForLicenseValidation(self.vm, self.commander)
                feature.activate()
        self.assertEqual(feature._deadline, 10 + DEFAULT_LICENSE_STATUS_TIMEOUT_SECONDS)
        with patch("fortinet.common.features.license.time.monotonic", return_value=11):
            feature.on_command_executed(command(output=b"License Status: Valid"), FOSCliState.CMD_PROMPT)
        self.assertTrue(feature.valid)
        self.assertEqual(feature._phase, "done")
        self.assertEqual(feature._settle_until, 11 + LICENSE_SETTLE_SECONDS)
        with patch("fortinet.common.features.license.time.monotonic", return_value=20):
            feature.on_block_complete()
        self.commander.feature_complete.assert_called_with(feature)

    def test_polling_grace_pending_timeout_and_logging_dedup(self):
        with patch("fortinet.common.features.license.os.path.exists", return_value=True):
            feature = WaitForLicenseValidation(self.vm, self.commander)
        with patch.dict(os.environ, {"FOS_LOG_LICENSE_STATUS_OUTPUT": "true"}, clear=True):
            feature._deadline = 100
            feature._phase = "polling"
            with patch("fortinet.common.features.license.time.monotonic", side_effect=[10, 11, 11, 12, 12]):
                feature.on_command_executed(command(output=b"status unavailable"), FOSCliState.CMD_PROMPT)
                feature.on_command_executed(command(output=b"status unavailable"), FOSCliState.CMD_PROMPT)
            self.assertEqual(feature._status, None)
            self.assertEqual(feature._next_poll, 14)
            self.commander.logger.info.assert_any_call(
                "Captured get system status output for license status %s:\n%s",
                "unavailable",
                "status unavailable",
            )
            with patch.dict(os.environ, {"FOS_WAIT_FOR_VALID_LICENSE": "false"}, clear=True):
                with patch("fortinet.common.features.license.time.monotonic", side_effect=[20, 21, 21]):
                    feature.on_command_executed(command(output=b"License Status: Grace period"), FOSCliState.CMD_PROMPT)
            self.assertEqual(feature._phase, "done")

        feature = WaitForLicenseValidation(self.vm, self.commander)
        feature._phase = "polling"
        feature._deadline = 5
        with patch("fortinet.common.features.license.time.monotonic", return_value=5):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                feature.on_command_executed(command(output=b"License Status: Pending"), FOSCliState.CMD_PROMPT)
        feature._phase = "polling"
        feature._deadline = 99
        with self.assertRaisesRegex(RuntimeError, "validation failed"):
            feature.on_command_executed(command(output=b"License Status: Invalid"), FOSCliState.CMD_PROMPT)

    def test_tick_requests_standard_output_and_settles(self):
        feature = WaitForLicenseValidation(self.vm, self.commander)
        feature._phase = "polling"
        feature._deadline = 100
        feature._next_poll = 10
        self.commander.busy = True
        with patch("fortinet.common.features.license.time.monotonic", return_value=10):
            feature.tick()
        self.commander.with_standard_output.assert_not_called()
        self.commander.busy = False
        with patch("fortinet.common.features.license.time.monotonic", return_value=10):
            feature.tick()
        self.commander.with_standard_output.assert_called_once()
        self.assertTrue(feature._standard_output_active)
        callback = self.commander.with_standard_output.call_args.args[1]
        callback()
        self.assertEqual(self.commander.submit_block.call_args.args[1].children[0].line, "get system status")
        feature._next_poll = 11
        with patch("fortinet.common.features.license.time.monotonic", return_value=11):
            feature.tick()
        self.commander.submit_block.assert_called()
        feature._phase = "done"
        feature._settle_until = 15
        with patch("fortinet.common.features.license.time.monotonic", return_value=14):
            feature.tick()
        self.commander.feature_complete.assert_not_called()
        with patch("fortinet.common.features.license.time.monotonic", return_value=15):
            feature.tick()
        self.commander.feature_complete.assert_called_with(feature)
        feature._phase = "idle"
        feature._next_poll = None
        with patch("fortinet.common.features.license.time.monotonic", return_value=16):
            feature.tick()


if __name__ == "__main__":
    unittest.main()
