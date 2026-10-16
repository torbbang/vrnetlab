"""Scheduler dispatch, cleanup, output mode, and recovery tests."""

import sys
import unittest
from unittest.mock import MagicMock

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from fortinet.common.cli_commands import (  # noqa: E402
    CleanupAction, CommandAttempt, CommandSequence, CommandSpec, ConfigBlock,
    SessionLossAction,
)
from fortinet.common.common import FOSCliState  # noqa: E402
from fortinet.common.fos_commander import FOSCommander  # noqa: E402
from fortinet.common.terminal import Data  # noqa: E402
from fortinet.common.features.base import Feature  # noqa: E402


class CommandFeature(Feature):
    def __init__(self, commander, name="cmd", lines=("one", "two"), action=SessionLossAction.RESTART_BLOCK):
        super().__init__(None, commander, name)
        self.lines = lines
        self.action = action
        self.executed = []
        self.dispatched = []
        self.output_calls = 0

    def activate(self):
        self.commander.submit_block(self, CommandSequence(self.name, self.lines))

    def on_command_dispatched(self, attempt):
        super().on_command_dispatched(attempt)
        self.dispatched.append(attempt)

    def on_command_executed(self, command, state):
        self.executed.append((command.spec.line, state))

    def on_output(self, output):
        self.output_calls += 1
        return False

    def on_session_loss(self, attempt):
        return self.action


class CommanderSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.terminal = MagicMock()
        self.logger = MagicMock()
        self.commander = FOSCommander(self.terminal, self.logger)

    def test_dispatch_complete_features_and_cleanup(self):
        first = CommandFeature(self.commander, "first", ("get a",))
        second = CommandFeature(self.commander, "second", ("get b",))
        self.commander.register_cleanup(first, CleanupAction("undo", CommandSequence("undo", ["unset a"])))
        self.commander.start([first, second])
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"fw #"))
        self.assertEqual(self.terminal.write.call_args.args[0], "get a\r")
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"fw #"))
        self.assertEqual(self.terminal.write.call_args.args[0], "unset a\r")
        self.assertTrue(self.commander.busy)
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"fw #"))
        self.assertEqual(self.terminal.write.call_args.args[0], "get b\r")
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"fw #"))
        self.assertTrue(second.completed)
        self.assertTrue(self.commander.ready)
        self.assertTrue(self.commander.startup_complete)
        self.terminal.close.assert_called_once()
        self.assertEqual(first.executed, [("get a", FOSCliState.CMD_PROMPT)])

    def test_output_validation_callbacks_and_inactive_submissions(self):
        feature = CommandFeature(self.commander, lines=(CommandSpec("must work", capture_output=True, fail_on_error=True),))
        self.commander.start([feature])
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"fw #"))
        output = Data(b"Command fail. Return code -5")
        self.commander.on_output(output)
        self.assertEqual(feature.output_calls, 0)
        feature.dispatched[0].output.extend(bytes(output))
        with self.assertRaisesRegex(RuntimeError, "return code -5"):
            self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"fw #"))
        with self.assertRaisesRegex(TypeError, "terminal.Data"):
            self.commander.on_output(b"bad")
        self.assertEqual(self.commander.on_output(Data(b"")), b"")
        with self.assertRaisesRegex(RuntimeError, "Inactive feature"):
            self.commander.submit_block(Feature(None, self.commander, "inactive"), ["x"])

    def test_session_loss_restarts_or_continues_commands(self):
        restart = CommandFeature(self.commander, "restart", ("first", "second"))
        self.commander.start([restart])
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.commander.on_state(FOSCliState.SESSION_LOST, Data(b"lost"))
        self.assertTrue(self.commander._recovering)
        self.assertEqual(self.commander._session_epoch, 1)
        self.commander.on_state(FOSCliState.CREDENTIAL_ACCEPTED, Data(b"Welcome"))
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.assertEqual(self.terminal.write.call_args.args[0], "first\r")
        self.assertEqual(restart.dispatched[-1].number, 2)

        terminal = MagicMock()
        continuation_commander = FOSCommander(terminal, self.logger)
        continuation = CommandFeature(continuation_commander, "continue", ("password", "next"), SessionLossAction.CONTINUE)
        continuation_commander.start([continuation])
        continuation_commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        continuation_commander.on_state(FOSCliState.SESSION_LOST, Data(b"lost"))
        continuation_commander.on_state(FOSCliState.CREDENTIAL_ACCEPTED, Data(b"Welcome"))
        continuation_commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.assertEqual(terminal.write.call_args.args[0], "password\r")
        self.assertEqual(continuation.dispatched[-1].spec.line, "password")
        self.assertTrue(continuation.completed)

    def test_session_loss_during_cleanup_and_action_fail(self):
        feature = CommandFeature(self.commander, "cleanup", ("go",))
        self.commander.register_cleanup(feature, CleanupAction("undo", CommandSequence("u", ["undo"])))
        self.commander.start([feature])
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.assertTrue(self.commander._in_cleanup)
        self.commander.on_state(FOSCliState.SESSION_LOST, Data(b"lost"))
        self.assertFalse(self.commander._in_cleanup)
        self.assertEqual(self.commander._cleanup[0].line, "undo")

        terminal = MagicMock()
        failing_commander = FOSCommander(terminal, self.logger)
        fail = CommandFeature(failing_commander, "fatal", ("fatal command",), SessionLossAction.FAIL)
        failing_commander.start([fail])
        failing_commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        with self.assertRaisesRegex(RuntimeError, "Session lost"):
            failing_commander.on_state(FOSCliState.SESSION_LOST, Data(b"lost"))

    def test_standard_output_inspection_callback_and_restore(self):
        feature = CommandFeature(self.commander, "capture", ())
        callback = MagicMock()
        self.commander.start([feature])
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        # The empty static block completes immediately; instead use a live feature.
        feature = CommandFeature(self.commander, "capture", ("placeholder",))
        callback.side_effect = lambda: self.commander.submit_block(
            feature, CommandSequence("capture", ["placeholder"])
        )
        feature.activate = lambda: self.commander.with_standard_output(feature, callback)
        self.commander.enqueue_runtime_feature(feature)
        self.commander.on_idle_prompt()
        self.assertEqual(self.terminal.write.call_args.args[0], "show full-configuration system console\r")
        self.commander._inflight.output.extend(b"set output more\n")
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.assertEqual(self.terminal.write.call_args.args[0], "config system console\r")
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.assertEqual(self.terminal.write.call_args.args[0], "set output standard\r")
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.assertEqual(self.terminal.write.call_args.args[0], "end\r")
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        callback.assert_called_once()
        self.assertEqual(self.terminal.write.call_args.args[0], "placeholder\r")
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.assertEqual(self.terminal.write.call_args.args[0], "config system console\r")
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.assertEqual(self.terminal.write.call_args.args[0], "set output more\r")
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.assertEqual(self.terminal.write.call_args.args[0], "end\r")
        self.commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))

    def test_best_effort_error_cleanup_and_runtime_enqueue(self):
        commander = FOSCommander(self.terminal, self.logger, continue_on_error=True)
        feature = CommandFeature(commander, "bad", ("slow",))
        feature.on_command_executed = MagicMock(side_effect=RuntimeError("broken"))
        following = CommandFeature(commander, "following", ("next",))
        commander.start([feature, following])
        commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        commander.on_state(FOSCliState.CMD_PROMPT, Data(b"#"))
        self.assertEqual(commander.feature_errors, (("bad", "broken"),))
        commander.on_idle_prompt()
        self.assertEqual(self.terminal.write.call_args.args[0], "next\r")
        commander.record_feature_error("license", "pending")
        commander.resolve_feature_error("license", "valid")
        self.assertNotIn("license", [name for name, _ in commander.feature_errors])
        self.assertFalse(commander.enqueue_runtime_feature(CommandFeature(commander, "too-early")))
        self.assertFalse(commander.continue_after_error(RuntimeError("x"), at_command_prompt=False))


if __name__ == "__main__":
    unittest.main()
