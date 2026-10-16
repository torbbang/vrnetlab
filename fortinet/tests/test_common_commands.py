"""Tests for command construction and FortiOS configuration deltas."""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from fortinet.common.cli_commands import (  # noqa: E402
    CleanupAction,
    CommandAttempt,
    CommandSequence,
    CommandSpec,
    ConfigBlock,
    EditBlock,
    Scope,
    SessionLossAction,
    SetValue,
    flatten_commands,
)
from fortinet.common.common import FOSCliState, Credentials, timed  # noqa: E402
from fortinet.common.config_diff import (  # noqa: E402
    ConfigNode,
    diff_config,
    literal_line,
    normalize_line,
    parse_config,
)
from fortinet.common.terminal import Data  # noqa: E402


class CommandModelTests(unittest.TestCase):
    def test_specs_attempt_capture_and_line_validation(self):
        with self.assertRaisesRegex(ValueError, "exactly one line"):
            CommandSpec("get system\nstatus")
        spec = CommandSpec("show", capture_output=True)
        attempt = CommandAttempt(spec, 2, 4)
        chunk = Data(b"result")
        self.assertTrue(attempt.on_output(chunk))
        self.assertEqual(bytes(attempt.output), b"result")
        self.assertTrue(chunk.discarded)
        ignored = Data(b"ignored")
        self.assertFalse(CommandAttempt(CommandSpec("x"), 1, 0).on_output(ignored))
        self.assertFalse(ignored.discarded)
        self.assertEqual(SessionLossAction.CONTINUE.name, "CONTINUE")
        self.assertEqual(CleanupAction("cleanup", "block").name, "cleanup")

    def test_scope_sequence_and_plain_command_flattening(self):
        commands = flatten_commands(ConfigBlock("system dns", [
            EditBlock("port1", ["set mode static", ConfigBlock("ipv6", ["set ip6-mode static"])]),
        ]))
        self.assertEqual([item.line for item in commands], [
            "config system dns", "edit port1", "set mode static",
            "config ipv6", "set ip6-mode static", "end", "next", "end",
        ])
        self.assertEqual([item.line for item in flatten_commands(CommandSequence("s", ["a", CommandSpec("b")]))], ["a", "b"])
        self.assertEqual(flatten_commands("exec reboot")[0].line, "exec reboot")
        with self.assertRaises(TypeError):
            flatten_commands(object())
        with self.assertRaises(NotImplementedError):
            Scope("abstract").flatten()

    def test_set_value_single_multiline_empty_and_unvalidated(self):
        one = SetValue("comment", "hello", fail_on_error=False).flatten()[0]
        self.assertEqual(one.line, 'set comment "hello"')
        self.assertTrue(one.capture_output)
        self.assertFalse(one.fail_on_error)
        self.assertEqual(one.expected_completion_state, FOSCliState.CMD_PROMPT)
        multiline = SetValue("comment", " first\nsecond\nthird ").flatten()
        self.assertEqual([c.line for c in multiline], [
            'set comment "first', "second", 'third"',
        ])
        self.assertEqual(multiline[0].completion_states, (FOSCliState.MULTILINE_PROMPT, FOSCliState.CMD_PROMPT))
        self.assertIsNone(SetValue("comment", "line", validate_prompt=False).flatten()[0].expected_completion_state)
        self.assertEqual(SetValue("comment", "\n").flatten()[0].line, 'set comment ""')


class ConfigDiffTests(unittest.TestCase):
    def test_normalization_parser_and_empty_block_pruning(self):
        self.assertEqual(normalize_line("  set   password ENC abc  "), "set password ENC <encrypted>")
        self.assertEqual(literal_line("  set   password ENC abc  "), "set password ENC abc")
        root = parse_config("# comment\n\nconfig empty\nend\nconfig system dns\n set   primary 1.1.1.1  \nend\n")
        self.assertEqual(len(root.children), 1)
        self.assertEqual(root.children[0].kind, "config")
        self.assertEqual(root.children[0].children[0].original, " set   primary 1.1.1.1")
        self.assertEqual(root.children[0].render()[-1], "end")
        self.assertFalse(ConfigNode("x", "x", "leaf").is_block)

    def test_diff_added_removed_edit_encrypted_and_duplicate_lines(self):
        baseline = '''config system interface
 edit port1
  set ip 1.1.1.1
  set password ENC old
 next
 edit port2
  set ip 2.2.2.2
 next
end
'''
        current = '''config system interface
 edit port1
  set ip 1.1.1.1
  set password ENC new
 next
 edit port2
  set ip 2.2.2.3
 next
 edit port3
  set ip 3.3.3.3
 next
end
'''
        delta = diff_config(baseline, current)
        self.assertIn("edit port1\n  set ip 1.1.1.1\n  set password ENC new\n next", delta)
        self.assertIn("edit port2\n  set ip 2.2.2.3", delta)
        self.assertIn("edit port3", delta)
        self.assertNotIn("port1\n  set ip 1.1.1.1\n  set password ENC old", delta)
        self.assertEqual(diff_config("set x 1", "set x 1"), "")
        self.assertEqual(diff_config("set pw ENC old", "set pw ENC new", False), "")
        self.assertIn("ENC new", diff_config("set pw ENC old", "set pw ENC new", True))
        duplicate = diff_config("set x 1\nset x 1", "set x 1")
        self.assertEqual(duplicate, "")


class CommonUtilityTests(unittest.TestCase):
    def test_credentials_and_timed_decorator_returns_value(self):
        credentials = Credentials("admin", "secret")
        self.assertEqual((credentials.username, credentials.password), ("admin", "secret"))
        @timed
        def calculate(value):
            return value + 1
        self.assertEqual(calculate(4), 5)


if __name__ == "__main__":
    unittest.main()
