"""Management transport setup and launcher helper behavior."""

import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO_ROOT), str(REPO_ROOT / "common")]

from fortinet.common.host_forwarded_bridge import HostForwardedBridge  # noqa: E402
from fortinet.common.passthrough_redirect import PassthroughRedirect  # noqa: E402
from fortinet.common.tftp import TFTPServer  # noqa: E402
from fortinet.common import launch  # noqa: E402


class NetworkSetupTests(unittest.TestCase):
    def test_host_bridge_configuration_qemu_options_and_commands(self):
        strategy = HostForwardedBridge()
        vm = MagicMock()
        strategy.configure_vm_mgmt(vm)
        self.assertEqual(vm.mgmt_address_ipv4, "172.31.255.30/30")
        self.assertEqual(vm.mgmt_address_ipv6, "200::1/127")
        self.assertFalse(vm.mgmt_passthrough)
        self.assertEqual(strategy.gen_mgmt_netdev(vm), "bridge,br=br-mgmt,id=p00")
        with patch("fortinet.common.host_forwarded_bridge.vrnetlab.run_command") as run_command:
            strategy.prep()
        self.assertGreaterEqual(run_command.call_count, 15)
        self.assertEqual(run_command.call_args_list[0].args[0], ["pkill", "socat"])
        self.assertTrue(any("br-mgmt" in str(call.args[0]) for call in run_command.call_args_list))

    def test_passthrough_commands_ifup_and_management_generation(self):
        strategy = PassthroughRedirect(["udp:69", "tcp:52000-52005"])
        with patch("fortinet.common.passthrough_redirect.vrnetlab.run_command") as run_command:
            strategy.prep()
        self.assertGreater(run_command.call_count, 10)
        self.assertEqual(run_command.call_args_list[0].args[0], ["ip", "link", "del", "FA"])
        script = strategy.get_tc_tap_mgmt_ifup("192.0.2.1", "24", "192.0.2.2", "aa:bb")
        self.assertIn("dst_port 69", script)
        self.assertIn("src_port 52000-52005", script)
        self.assertIn("ip netns exec fakehost", script)
        vm = SimpleNamespace(
            mgmt_host_ip=10, mgmt_guest_ip=20, snapshot_metadata={}, nic_type="virtio-net-pci",
            mgmt_gw_ipv4="192.0.2.1", mgmt_address_ipv4="192.0.2.2/24",
            mgmt_mac="aa:bb", get_mgmt_mac=lambda: "aa:bb",
        )
        with patch.object(strategy, "write_ifup_script") as write:
            args = strategy.gen_mgmt(vm)
        write.assert_called_once_with(vm)
        self.assertIn("script=/etc/tc-tap-mgmt-ifup", args[-1])

    def test_tftp_host_and_passthrough_launchers(self):
        with patch("fortinet.common.tftp.vrnetlab.run_command") as run_command:
            host = TFTPServer(addr="127.0.0.1", directory="/tmp/tftp", tid_range=(100, 200))
            host.launch()
            commands = [call.args[0] for call in run_command.call_args_list]
        self.assertIn("127.0.0.1:69", commands[0])
        self.assertIn("-R", commands[0])
        self.assertEqual(commands[1], ["chmod", "-R", "777", "/tmp/tftp"])
        run_command.reset_mock()
        passthrough = TFTPServer(directory="/tmp/tftp", mgmt_net=SimpleNamespace(mgmt_passthrough=True), tid_range=(10, 20))
        with patch("fortinet.common.tftp.vrnetlab.run_command") as run_command:
            passthrough.launch()
        self.assertEqual(run_command.call_args_list[0].args[0][:4], ["ip", "netns", "exec", "fakehost"])
        self.assertEqual(run_command.call_args_list[-1].args[0], ["chmod", "-R", "777", "/tmp/tftp"])


class LauncherHelperTests(unittest.TestCase):
    def test_log_error_policy_dns_and_debug_cutoff(self):
        self.assertEqual(launch.parse_log_level(None), logging.DEBUG)
        self.assertEqual(launch.parse_log_level(" trace "), launch.TRACE_LEVEL_NUM)
        self.assertEqual(launch.parse_log_level("17"), 17)
        with self.assertRaises(ValueError):
            launch.parse_log_level("NOPE")
        with patch.dict(os.environ, {"FOS_EXIT_ON_BOOTSTRAP_ERROR": "false"}, clear=True):
            self.assertFalse(launch.exit_on_bootstrap_error())
        self.assertTrue(launch.exit_on_bootstrap_error(" typo "))
        with tempfile.TemporaryDirectory() as directory:
            resolver = Path(directory) / "resolv.conf"
            resolver.write_text("nameserver 1.1.1.1\nsearch example.org\nnameserver 8.8.8.8 extra\n")
            self.assertEqual(launch.container_dns_servers(resolver), ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(launch.container_dns_servers("/missing/resolv"), [])
        features = [SimpleNamespace(name=n) for n in ("one", "two", "three")]
        logger = MagicMock()
        self.assertEqual(launch.apply_debug_feature_cutoff(features, " two ", logger), features[:2])
        self.assertEqual(launch.apply_debug_feature_cutoff(features, "", logger), features)
        with self.assertRaisesRegex(ValueError, "Unknown FOS_DEBUG_FEATURE"):
            launch.apply_debug_feature_cutoff(features, "missing", logger)
        logger.warning.assert_called_once()
        self.assertFalse(launch.exit_on_bootstrap_error("FALSE"))

    def test_console_reads_suppression_and_vm_address_helpers(self):
        driver = MagicMock()
        driver.channel.read.return_value = b"console"
        driver.transport.socket.sock = object()
        console = launch.FortiOSConsole(driver)
        output = MagicMock()
        output.buffer = MagicMock()
        with patch.object(launch.sys, "stdout", output):
            self.assertEqual(console.read_blocking(), b"console")
        output.buffer.write.assert_called_once_with(b"console")
        with console.suppress_output():
            with patch.object(launch.sys, "stdout", output):
                self.assertEqual(console._read(), b"console")
            self.assertFalse(console._output_enabled)
        self.assertTrue(console._output_enabled)
        with patch.object(launch.select, "select", return_value=([], [], [])):
            self.assertEqual(console.read_very_eager(), b"")
        with patch.object(launch.select, "select", return_value=([driver.transport.socket.sock], [], [])):
            with patch.object(launch.sys, "stdout", output):
                self.assertEqual(console.read_very_eager(), b"console")
        self.assertEqual(launch.FortiOS_vm.mgmt_gateway_destination("192.0.2.1", "192.0.2.8/24"), "192.0.2.1/24")
        self.assertEqual(launch.FortiOS_vm.mgmt_gateway_destination("2001:db8::1", "dhcp"), "2001:db8::1/128")

    def test_signal_helpers(self):
        with patch.object(launch.os, "waitpid") as waitpid:
            launch.handle_SIGCHLD(None, None)
        waitpid.assert_called_once_with(-1, launch.os.WNOHANG)
        with patch.object(launch.sys, "exit", side_effect=SystemExit(0)):
            with self.assertRaises(SystemExit):
                launch.handle_SIGTERM(None, None)


if __name__ == "__main__":
    unittest.main()

class VmLifecycleTests(unittest.TestCase):
    def test_vm_initialization_builds_features_and_disks(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "fortios.qcow2").touch()
            feature_names = (
                "CredentialsFeature", "ConfigureMgmtDns", "ConfigSaveFeature", "FormatDisks",
                "DefaultConfig", "ConfigureFortiGuardHooks", "ReapplyFortiGuardHooks", "SetLicense",
                "WaitForLicenseValidation", "WaitForFortiTokens", "ConfigureMgmtNetwork",
                "ReconfigureMgmtNetwork", "MoveMgmtToVrf1", "ImageInfo", "InstallPkiCertificates",
                "ApplyStartupConfig", "ValidateProduct",
            )
            created = {}
            patches = []
            def fake_feature(name):
                def factory(*args, **kwargs):
                    value = SimpleNamespace(name=name)
                    created.setdefault(name, []).append(value)
                    return value
                return factory
            for name in feature_names:
                patches.append(patch.object(launch, name, side_effect=fake_feature(name)))
            def init_vm(instance, *args, **kwargs):
                instance.logger = MagicMock()
                instance.scrapli_tn = MagicMock()
                instance.qemu_args = []
                instance.wait_pattern = b"#"
            patches.extend([
                patch.object(launch.vrnetlab.VM, "__init__", autospec=True, side_effect=init_vm),
                patch.object(launch.vrnetlab, "run_command"),
                patch.object(launch, "Terminal", return_value=MagicMock()),
                patch.object(launch, "FOSCommander", return_value=MagicMock()),
                patch.object(launch, "FOSCliDriver", return_value=MagicMock()),
                patch.object(launch, "FeatureFileWatcher", return_value=MagicMock()),
                patch.object(launch, "container_dns_servers", return_value=["192.0.2.53"]),
            ])
            stack = __import__("contextlib").ExitStack()
            with stack:
                active_patches = [stack.enter_context(item) for item in patches]
                run_command = active_patches[18]
                previous = os.getcwd()
                os.chdir(directory)
                try:
                    with patch.dict(os.environ, {"FOS_DISK_SPECS": "", "FOS_DEBUG_FEATURE": "ImageInfo"}, clear=True):
                        vm = launch.FortiOS_vm("fw", None, None, "tc", MagicMock(mgmt_passthrough=False, configure_vm_mgmt=MagicMock()))
                finally:
                    os.chdir(previous)
            self.assertEqual(vm.mgmt_dns_primary, "192.0.2.53")
            self.assertEqual(vm.mgmt_dns_secondary, "8.8.8.8")
            self.assertEqual(vm.desired_credentials.password, launch.DEFAULT_PASSWORD)
            self.assertEqual([feature.name for feature in vm._features], ["ImageInfo"])
            run_command.assert_called_once_with(["qemu-img", "create", "-f", "qcow2", "empty.qcow2", "30G"])

    def test_vm_heartbeat_work_and_serial_reconnect(self):
        vm = object.__new__(launch.FortiOS_vm)
        vm.logger = MagicMock()
        vm.driver = MagicMock()
        vm.commander = MagicMock()
        vm.terminal = MagicMock()
        vm.tn = MagicMock()
        vm.num = 3
        vm.stopped = True
        vm.running = True
        vm._file_watcher = MagicMock()
        vm.credentials = launch.Credentials("admin", "old")
        vm.desired_credentials = launch.Credentials("new", "desired")
        vm._bootstrap_username = "admin"
        vm._bootstrap_password = "bootstrap"
        with patch.object(launch, "HEARTBEAT_FILE", "/tmp/unused-heartbeat"):
            with patch("builtins.open", side_effect=OSError("read-only")):
                vm._write_heartbeat()
        vm.logger.debug.assert_called_once()
        vm.bootstrap_spin = MagicMock(return_value=True)
        with patch.object(launch.vrnetlab.VM, "work", return_value=None):
            vm.work()
        vm._file_watcher.poll.assert_called_once()
        vm.driver.ready = False
        with patch.object(launch.vrnetlab.VM, "work", return_value=None):
            vm.work()
        vm.bootstrap_spin.assert_called_once()
        del vm.bootstrap_spin
        vm._bootstrap_error = None
        vm._exit_on_bootstrap_error = False
        vm.commander.startup_complete = False
        vm.driver.ready = True
        vm.commander.feature_errors = ()
        self.assertTrue(vm.bootstrap_spin())
        self.assertTrue(vm.running)
        vm.driver.process_state.side_effect = RuntimeError("recoverable")
        vm.commander.startup_complete = False
        vm.commander.continue_after_error.return_value = "test-feature"
        self.assertTrue(vm.bootstrap_spin())
        vm.commander.continue_after_error.assert_called_with(unittest.mock.ANY, at_command_prompt=vm.driver.at_command_prompt)
        vm.commander.continue_after_error.return_value = None
        self.assertFalse(vm.bootstrap_spin())
        self.assertIsNotNone(vm._bootstrap_error)
        vm.tn.open.side_effect = [RuntimeError("retry"), None]
        with patch.object(launch.vrnetlab, "MAX_RETRIES", 2), patch.object(launch.time, "sleep"):
            vm.connect_serial_console()
        self.assertFalse(vm.stopped)
        self.assertEqual(vm.terminal.write.call_args.args[0], b"\r")
        vm.activate_desired_credentials()
        self.assertEqual((vm.credentials.username, vm.credentials.password), ("new", "desired"))
        vm.activate_bootstrap_credentials()
        self.assertEqual(vm.credentials.password, "bootstrap")
        vm.activate_blank_credentials()
        self.assertEqual(vm.credentials.password, "")
        with patch.object(launch.vrnetlab.VM, "stop", return_value=None):
            vm.stop()
        self.assertTrue(vm.stopped)
