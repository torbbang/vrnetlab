"""Unit coverage for FortiOS bootstrap feature command generation and callbacks."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from fortinet.common.cli_commands import CommandAttempt, CommandSpec  # noqa: E402
from fortinet.common.common import FOSCliState  # noqa: E402
from fortinet.common.features.base import Feature, StaticFeature  # noqa: E402
from fortinet.common.features.credentials import CredentialsFeature  # noqa: E402
from fortinet.common.features.default_config import DefaultConfig, onboarding_enabled  # noqa: E402
from fortinet.common.features.disks import FormatDisks  # noqa: E402
from fortinet.common.features.fortiguard_hooks import (  # noqa: E402
    ConfigureFortiGuardHooks, ReapplyFortiGuardHooks, fortiguard_hooks_enabled,
)
from fortinet.common.features.fortitoken import WaitForFortiTokens  # noqa: E402
from fortinet.common.features.image_info import (  # noqa: E402
    FortiOSVersion, ImageInfo, product_from_system_status,
)
from fortinet.common.features.license import WaitForLicenseValidation  # noqa: E402
from fortinet.common.features.mgmt_dns import ConfigureMgmtDns  # noqa: E402
from fortinet.common.features.mgmt_net import (  # noqa: E402
    ConfigureMgmtNetwork, MoveMgmtToVrf1, ReconfigureMgmtNetwork,
)
from fortinet.common.features.product import (  # noqa: E402
    ValidateProduct, VersionBound, parse_version_constraint,
)
from fortinet.common.features.startup_config import (  # noqa: E402
    filter_startup_config_blocks, parse_startup_config,
)


def vm(**overrides):
    values = dict(
        hostname="test-fw", desired_credentials=SimpleNamespace(username="admin", password="secret"),
        mgmt_address_ipv4="192.0.2.2/24", mgmt_gw_ipv4="192.0.2.1",
        mgmt_address_ipv6="2001:db8::2/64", mgmt_dns_protocol="cleartext",
        mgmt_dns_primary="1.1.1.1", mgmt_dns_secondary="8.8.8.8",
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def commander():
    result = MagicMock()
    result.logger = MagicMock()
    return result


def attempt(line, output=b""):
    value = CommandAttempt(CommandSpec(line, capture_output=True), 1, 0)
    value.output.extend(output)
    return value


def line_of(command):
    return command.line if isinstance(command, CommandSpec) else command


class BaseFeatureTests(unittest.TestCase):
    def test_lifecycle_and_static_sequence(self):
        cmd = commander()
        feature = Feature(None, cmd, "base")
        self.assertFalse(feature.completed)
        self.assertIsNone(feature.current_command)
        self.assertEqual(feature.command_output, b"")
        feature.mark_completed()
        feature.begin_activation()
        self.assertFalse(feature.completed)
        feature.activate()
        cmd.feature_complete.assert_called_once_with(feature)
        feature.on_block_complete()
        self.assertEqual(feature.on_output(b"data"), False)
        self.assertEqual(feature.reversal_blocks(), [])
        undo = feature.undo()
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            undo.activate()

        done = []
        static = StaticFeature(None, cmd, "static", ["one", "two"], lambda: done.append(True))
        static.activate()
        self.assertEqual(cmd.submit_block.call_args.args[1], "one")
        static.on_block_complete()
        self.assertEqual(cmd.submit_block.call_args.args[1], "two")
        static.on_block_complete()
        self.assertEqual(done, [True])
        cmd.feature_complete.assert_called_with(static)


class BasicFeatureTests(unittest.TestCase):
    def test_credentials_builds_password_or_unset_and_tracks_commit(self):
        owner, cmd = vm(), commander()
        owner.activate_desired_credentials = MagicMock()
        feature = CredentialsFeature(owner, cmd)
        lines = [line_of(spec) for spec in feature._blocks[1].children[0].children]
        self.assertEqual(lines, ["set accprofile super_admin", "set password secret"])
        password = attempt("set password secret")
        self.assertEqual(feature.on_session_loss(password).name, "CONTINUE")
        owner.activate_desired_credentials.assert_called_once()
        feature.on_command_executed(password, FOSCliState.CMD_PROMPT)
        feature.on_command_executed(attempt("next"), FOSCliState.CMD_PROMPT)
        self.assertTrue(feature._password_change_committed)
        self.assertEqual(feature.on_session_loss(attempt("other")).name, "CONTINUE")
        feature._activate_desired_credentials()
        self.assertEqual(owner.activate_desired_credentials.call_count, 1)
        owner.desired_credentials = SimpleNamespace(username="admin", password="")
        unset = CredentialsFeature(owner, cmd)
        self.assertIn("unset password", [line_of(s) for s in unset._blocks[1].children[0].children])

    def test_default_config_onboarding_and_prompt_update(self):
        owner, cmd = vm(), commander()
        owner.driver = MagicMock()
        with patch.dict(os.environ, {"FOS_ONBOARDING": "true"}):
            self.assertTrue(onboarding_enabled())
            feature = DefaultConfig(owner, cmd)
        lines = [line_of(s) for s in feature._blocks[0].children]
        self.assertIn("set admin-https-redirect disable", lines)
        feature.on_command_executed(attempt("set hostname test-fw"), FOSCliState.CMD_PROMPT)
        owner.driver.set_prompt_patterns.assert_called_once_with("test-fw")
        with patch.dict(os.environ, {"FOS_ONBOARDING": "no"}):
            self.assertFalse(onboarding_enabled())
            self.assertNotIn("set admin-https-redirect disable", [line_of(s) for s in DefaultConfig(owner, cmd)._blocks[0].children])

    def test_management_dns_inspection_apply_and_undo(self):
        owner, cmd = vm(), commander()
        feature = ConfigureMgmtDns(owner, cmd)
        feature.activate()
        self.assertEqual(cmd.with_standard_output.call_count, 1)
        feature.on_command_executed(attempt("show", b"set protocol dot"), FOSCliState.CMD_PROMPT)
        feature.on_block_complete()
        self.assertEqual(feature._previous_protocol, "dot")
        self.assertEqual([line_of(s) for s in cmd.submit_block.call_args.args[1].children], [
            "set protocol cleartext", "set primary 1.1.1.1", "set secondary 8.8.8.8",
        ])
        self.assertEqual(feature.reversal_blocks()[0].children[0], "set protocol dot")
        feature._previous_protocol = None
        self.assertEqual(feature.reversal_blocks()[0].children[0], "unset protocol")
        self.assertIsNone(ConfigureMgmtDns._protocol_from(b"no protocol"))
        feature.on_block_complete()
        cmd.feature_complete.assert_called_with(feature)

    def test_management_blocks_and_license_reconfiguration(self):
        owner, cmd = vm(), commander()
        blocks = ConfigureMgmtNetwork._blocks_for(owner)
        self.assertEqual(len(blocks), 2)
        ipv6 = next(block for block in blocks[0].children[0].children if not isinstance(block, str))
        self.assertIn("set ip6-address 2001:db8::2/64", [line_of(c) for c in ipv6.children])
        self.assertEqual(ConfigureMgmtNetwork._blocks_for(vm(mgmt_address_ipv4="dhcp")), [])
        feature = ReconfigureMgmtNetwork(owner, cmd)
        with patch("fortinet.common.features.mgmt_net.os.path.exists", return_value=True):
            feature.activate()
        self.assertEqual(cmd.submit_block.call_count, 1)
        feature.on_block_complete()
        feature.on_block_complete()
        cmd.feature_complete.assert_called_with(feature)
        skipped = ReconfigureMgmtNetwork(vm(mgmt_address_ipv4="dhcp"), cmd)
        with patch("fortinet.common.features.mgmt_net.os.path.exists", return_value=False):
            skipped.activate()

    def test_move_management_vrf_fallback(self):
        owner, cmd = vm(), commander()
        owner.mgmt_gateway_destination = MagicMock(return_value="192.0.2.0/24")
        feature = MoveMgmtToVrf1(owner, cmd)
        with patch("fortinet.common.features.mgmt_net.os.path.exists", return_value=True):
            feature.activate()
        feature.on_command_executed(attempt("set vrf 1", b"Command parse error"), FOSCliState.CMD_PROMPT)
        feature.on_block_complete()
        route = cmd.submit_block.call_args.args[1]
        self.assertEqual(route.children[0].children[0], "set dst 192.0.2.0/24")
        feature.on_block_complete()
        cmd.feature_complete.assert_called_with(feature)
        skipped = MoveMgmtToVrf1(vm(mgmt_address_ipv4="dhcp"), cmd)
        with patch("fortinet.common.features.mgmt_net.os.path.exists", return_value=True):
            skipped.activate()


class ProductAndImageTests(unittest.TestCase):
    def test_version_parsing_and_constraints(self):
        version = FortiOSVersion.from_system_status(b"Version: FortiGate-VM64 v7.2.4,build1396\n")
        self.assertEqual(version, FortiOSVersion(7, 2, 4, 1396, "FortiGate-VM64"))
        self.assertEqual(str(version), "FortiGate-VM64 v7.2.4,build1396")
        self.assertIsNone(FortiOSVersion.from_system_status(b"bad"))
        self.assertEqual(product_from_system_status(b"Version: FortiProxy-VM v7.0.0,build1"), "FortiProxy")
        self.assertIsNone(product_from_system_status(b"bad"))
        prefix = parse_version_constraint(" 7.2 ")
        self.assertTrue(prefix.matches(FortiOSVersion(7, 2, 99, 9000)))
        build = parse_version_constraint("7.2.4.b1396")
        self.assertTrue(build.matches(version))
        span = parse_version_constraint("7.0-7.2.4")
        self.assertTrue(span.matches(version))
        self.assertFalse(span.matches(FortiOSVersion(8, 0, 0, 1)))
        self.assertIsNone(parse_version_constraint(""))
        with self.assertRaises(ValueError):
            parse_version_constraint("8.0-7.0")
        with self.assertRaises(ValueError):
            parse_version_constraint("latest")
        self.assertTrue(VersionBound((7, 2), True).matches(version))

    def test_image_info_and_product_validation(self):
        owner, cmd = vm(), commander()
        feature = ImageInfo(owner, cmd)
        feature.activate()
        request = attempt("get system status", b"Version: FortiGate-VM64 v7.2.4,build1396\n")
        feature.on_command_executed(request, FOSCliState.CMD_PROMPT)
        self.assertEqual(owner.fos_product, "FortiGate")
        feature.on_block_complete()
        with self.assertRaisesRegex(RuntimeError, "Could not determine"):
            feature.on_command_executed(attempt("get system status", b"bad"), FOSCliState.CMD_PROMPT)
        owner.fos_version = FortiOSVersion(7, 2, 4, 1396)
        with patch.dict(os.environ, {"FOS_PRODUCT_VERSION": "7.2"}, clear=False):
            check = ValidateProduct(owner, cmd, "FortiGate")
            check.activate()
        with self.assertRaisesRegex(RuntimeError, "product mismatch"):
            ValidateProduct(owner, cmd, "FortiProxy").activate()
        with patch.dict(os.environ, {"FOS_PRODUCT_VERSION": "8"}, clear=False):
            with self.assertRaisesRegex(RuntimeError, "version mismatch"):
                ValidateProduct(owner, cmd, "FortiGate").activate()
        with patch.dict(os.environ, {"FOS_SKIP_PRODUCT_CHECK": "true"}, clear=False):
            ValidateProduct(owner, cmd, "other").activate()


class DiskTokenAndGuardTests(unittest.TestCase):
    def test_disk_list_confirmation_and_session_recovery(self):
        with patch.dict(os.environ, {"FOS_DISK_SPECS": "disk0,disk1"}, clear=False):
            feature = FormatDisks(None, commander())
        feature.activate()
        self.assertEqual(feature._count, 1)
        self.assertEqual(feature._disk_ref(b"Disk Virtual-Disk2 ref: 42\n"), "42")
        self.assertEqual(feature._disk_ref(b"Disk HD2 ref: 43\n"), "43")
        with self.assertRaisesRegex(RuntimeError, "disk #2"):
            feature._disk_ref(b"no disks")
        listed = attempt("exe disk list", b"Disk HD2 ref: 43")
        feature.on_command_executed(listed, FOSCliState.CMD_PROMPT)
        self.assertEqual(feature._phase, "format")
        feature.on_command_executed(attempt("exe disk format 43"), FOSCliState.CONFIRMATION)
        self.assertEqual(feature._phase, "reboot")
        feature.on_command_executed(attempt("y"), FOSCliState.REBOOTING)
        feature.on_block_complete()
        self.assertEqual(feature._disk_number, 3)
        feature.activate()
        feature.on_session_loss(attempt("y"))
        self.assertEqual(feature._phase, "restart-list")
        feature.on_block_complete()
        self.assertEqual(feature._phase, "list")
        empty = FormatDisks(None, commander())
        with patch.dict(os.environ, {"FOS_DISK_SPECS": ""}):
            empty._count = 0
        empty.activate()
        bad = FormatDisks(None, commander())
        bad._phase = "format"
        with self.assertRaisesRegex(RuntimeError, "unexpected state"):
            bad.on_command_executed(attempt("format"), FOSCliState.CMD_PROMPT)

    def test_token_poll_success_deadline_and_invalid_license(self):
        cmd = commander()
        not_valid = WaitForFortiTokens(None, cmd, SimpleNamespace(valid=False))
        not_valid.activate()
        cmd.feature_complete.assert_called_with(not_valid)
        valid = WaitForFortiTokens(None, cmd, SimpleNamespace(valid=True))
        with patch("fortinet.common.features.fortitoken.time.monotonic", return_value=10):
            valid.activate()
        self.assertEqual(valid._deadline, 25)
        valid.on_command_executed(attempt("show", b"config user fortitoken\n edit token1"), FOSCliState.CMD_PROMPT)
        valid.on_block_complete()
        cmd.feature_complete.assert_called_with(valid)
        self.assertTrue(WaitForFortiTokens._tokens_provisioned(b"config user fortitoken\n edit t"))
        self.assertFalse(WaitForFortiTokens._tokens_provisioned(b"config user local\n edit t"))
        deadline = WaitForFortiTokens(None, cmd, SimpleNamespace(valid=True))
        with patch("fortinet.common.features.fortitoken.time.monotonic", return_value=0):
            deadline.activate()
        cmd.busy = False
        cmd.feature_complete.reset_mock()
        with patch("fortinet.common.features.fortitoken.time.monotonic", return_value=15):
            deadline.tick()
        cmd.feature_complete.assert_called_with(deadline)
        self.assertTrue(cmd.logger.warning.called)

    def test_fortiguard_command_fallback_and_version_mapping(self):
        cmd = commander()
        with patch.dict(os.environ, {"FOS_FORTIGUARD_HOOKS": "true", "DIAG_2": "diag newer", "DIAG_1": "diag older"}, clear=False):
            self.assertTrue(fortiguard_hooks_enabled())
            feature = ConfigureFortiGuardHooks(None, cmd)
        feature.activate()
        self.assertEqual(cmd.submit_block.call_args.args[1].name, "hooks-guard")
        feature.on_command_executed(attempt("diag newer", b"Unknown action"), FOSCliState.CMD_PROMPT)
        self.assertEqual(cmd.submit_block.call_args.args[1].name, "hooks-guard-fallback")
        self.assertEqual(ConfigureFortiGuardHooks.fortiguard_block(SimpleNamespace(major=6)).children[-1], "set update-server-location any")
        with patch.dict(os.environ, {"FOS_FORTIGUARD_HOOKS": "false"}, clear=False):
            disabled = ConfigureFortiGuardHooks(None, cmd)
            disabled.activate()
            self.assertFalse(fortiguard_hooks_enabled())
        with patch.dict(os.environ, {"FOS_FORTIGUARD_HOOKS": "true"}, clear=False):
            reapply = ReapplyFortiGuardHooks(None, cmd)
            reapply.activate()
            self.assertEqual(cmd.submit_block.call_args.args[1].children[-1].line, "execute update-now")
        failed = ConfigureFortiGuardHooks(None, cmd)
        failed._guard_command = "diag"
        with self.assertRaisesRegex(RuntimeError, "hook command failed"):
            failed.on_command_executed(attempt("diag", b"command fail"), FOSCliState.CMD_PROMPT)


class StartupConfigTests(unittest.TestCase):
    def test_parser_nested_scopes_errors_and_dns_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "startup.cfg"
            path.write_text("""# startup
config system dns
 set primary 1.1.1.1
end
config system interface
 edit port1
  set mode static
 next
end
""")
            blocks = parse_startup_config(path)
            self.assertEqual([block.value for block in blocks], ["system dns", "system interface"])
            filtered = filter_startup_config_blocks(blocks, MagicMock())
            self.assertEqual(len(filtered), 2)
            with patch.dict(os.environ, {"FOS_FORTIGUARD_HOOKS": "true", "FTNT_DNS_PRIMARY": "1.1.1.1"}, clear=True):
                filtered = filter_startup_config_blocks(blocks, MagicMock())
            self.assertEqual([block.value for block in filtered], ["system interface"])
            with self.assertRaises(ValueError):
                parse_startup_config(write(path, "edit x\n"))
            with self.assertRaises(ValueError):
                parse_startup_config(write(path, "config x\nnext\n"))
            with self.assertRaises(ValueError):
                parse_startup_config(write(path, "set foo bar\n"))
            with self.assertRaises(ValueError):
                parse_startup_config(write(path, "config x\n"))


def write(path, value):
    path.write_text(value)
    return path


if __name__ == "__main__":
    unittest.main()
