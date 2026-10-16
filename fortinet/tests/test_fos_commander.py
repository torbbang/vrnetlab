"""Regression tests for FortiOS bootstrap feature error recovery."""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from fortinet.common.cli_commands import CommandAttempt, CommandSequence, CommandSpec
from fortinet.common.common import FOSCliState
from fortinet.common.features.base import Feature
from fortinet.common.features.license import WaitForLicenseValidation
from fortinet.common.fos_commander import FOSCommander
from fortinet.common.terminal import Data


class TestLicenseTimeoutRecovery(unittest.TestCase):
    def setUp(self):
        self.terminal = MagicMock()
        self.logger = MagicMock()
        self.commander = FOSCommander(
            self.terminal, self.logger, continue_on_error=True
        )
        with patch("fortinet.common.features.license.os.path.exists", return_value=True):
            self.license = WaitForLicenseValidation(None, self.commander)
        self.following = Feature(None, self.commander, "following")
        self.commander.start([self.license, self.following])
        with patch("fortinet.common.features.license.time.monotonic", return_value=0):
            self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b""))
            status = CommandAttempt(CommandSpec("get system status"), 1, 0)
            status.output.extend(b"License Status: Pending\r\n")
            self.license.on_command_executed(status, FOSCliState.CMD_PROMPT)

    def test_idle_prompt_recovers_once_after_license_timeout(self):
        with patch("fortinet.common.features.license.time.monotonic", return_value=121):
            self.commander.on_state(FOSCliState.TN_TIMEOUT, Data(b""))
            self.commander.tick()
            self.commander.tick()
            self.commander.on_idle_prompt()

        self.assertTrue(self.following.completed)
        self.assertTrue(self.commander.startup_complete)
        self.assertEqual(
            self.commander.feature_errors,
            ((
                "license-validation",
                "VM license validation timed out with status Pending",
            ),),
        )
        self.logger.exception.assert_called_once_with(
            "Bootstrap feature callback failed"
        )


class _FailingTickWithCommand(Feature):
    def activate(self):
        self.commander.submit_block(
            self, CommandSequence("slow-command", ["get system status"])
        )

    def tick(self):
        raise RuntimeError("tick failed while command was running")


class TestBusyTickErrorRecovery(unittest.TestCase):
    def test_waits_for_real_prompt_before_skipping_inflight_work(self):
        logger = MagicMock()
        commander = FOSCommander(MagicMock(), logger, continue_on_error=True)
        following = Feature(None, commander, "following")
        commander.start([_FailingTickWithCommand(None, commander, "failing"), following])
        commander.on_state(FOSCliState.CMD_PROMPT, Data(b""))
        self.assertTrue(commander.busy)

        commander.on_state(FOSCliState.TN_TIMEOUT, Data(b""))
        commander.tick()
        commander.on_idle_prompt()
        commander.tick()

        self.assertFalse(following.completed)
        logger.exception.assert_called_once()

        commander.on_state(FOSCliState.CMD_PROMPT, Data(b""))
        self.assertTrue(following.completed)
        self.assertEqual(
            commander.feature_errors,
            (("failing", "tick failed while command was running"),),
        )


if __name__ == "__main__":
    unittest.main()
