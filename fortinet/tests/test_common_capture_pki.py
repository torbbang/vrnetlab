"""File triggered config capture and certificate input validation tests."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from fortinet.common.cli_commands import CommandAttempt, CommandSpec, SetValue  # noqa: E402
from fortinet.common.common import FOSCliState  # noqa: E402
from fortinet.common.features.capture_config import ConfigSaveFeature  # noqa: E402
from fortinet.common.features.pki import (  # noqa: E402
    CA_CERTS_ENV,
    CRLS_ENV,
    LOCAL_CERTS_ENV,
    LOCAL_CERT_PASS_FILES_ENV,
    REMOTE_CERTS_ENV,
    InstallPkiCertificates,
    parse_ca_certs,
    parse_crls,
    parse_local_certs,
    parse_pass_files,
    parse_remote_certs,
    read_certificate_cn,
    read_crl_body,
    read_pass_file,
)


def attempt(output):
    result = CommandAttempt(CommandSpec("show", capture_output=True), 1, 0)
    result.output.extend(output)
    return result


class ConfigCaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.baseline = root / "baseline.conf"
        self.current = root / "current.conf"
        self.trigger = root / "get-config"
        self.status = root / "status"
        self.vm = MagicMock()
        self.commander = MagicMock()
        self.commander.ready = True
        self.commander.busy = False
        self.commander.logger = MagicMock()
        self.feature = ConfigSaveFeature(
            self.vm, self.commander, self.baseline, self.current,
            self.trigger, self.status,
        )

    def test_baseline_cleaning_atomic_write_and_completion(self):
        raw = (b"show\r\n# metadata\r\nSystem file integrity check failed!\r\n"
               b"config system dns\r\n set  primary 1.1.1.1\x08\x1b[31m\r\nend\r\nfw #\r\n")
        cleaned = self.feature.clean_show_output(raw)
        self.assertEqual(cleaned, "config system dns\n set  primary 1.1.1.1\nend")
        self.feature.activate()
        self.feature.on_command_executed(attempt(raw), FOSCliState.CMD_PROMPT)
        self.assertEqual(self.baseline.read_text(), cleaned + "\n")
        self.assertEqual(self.baseline.stat().st_mode & 0o777, 0o600)
        self.assertIn(str(self.baseline), self.feature.completion_message)
        self.feature.on_block_complete()
        self.commander.feature_complete.assert_called_with(self.feature)
        self.baseline.chmod(0o400)
        ConfigSaveFeature.atomic_write(self.baseline, b"replacement")
        self.assertEqual(self.baseline.stat().st_mode & 0o777, 0o400)
        self.assertEqual(self.baseline.read_bytes(), b"replacement")

    def test_request_success_and_status_record(self):
        self.baseline.write_text("config system dns\n set primary 1.1.1.1\nend\n")
        self.trigger.write_text(json.dumps({"id": "request-1"}))
        self.feature._handle_request(self.trigger)
        self.vm.connect_serial_console.assert_called_once()
        self.commander.enqueue_runtime_feature.assert_called_once_with(self.feature)
        self.assertFalse(self.trigger.exists())
        status = json.loads((self.status / "request-1.json").read_text())
        self.assertEqual(status, {"id": "request-1", "status": "pending"})
        current = attempt(b"config system dns\n set primary 9.9.9.9\nend\n")
        self.feature.on_command_executed(current, FOSCliState.CMD_PROMPT)
        self.assertIn("9.9.9.9", self.current.read_text())
        status = json.loads((self.status / "request-1.json").read_text())
        self.assertEqual(status["status"], "success")
        self.assertEqual(status["output"], "current.conf")
        self.assertEqual(self.feature.completion_message, f"Config saved to {self.current}")

    def test_busy_invalid_replaced_and_reconnect_failure_paths(self):
        self.trigger.write_text("{")
        self.feature._handle_request(self.trigger)
        self.assertTrue((self.status / "invalid.json").exists())
        self.commander.busy = True
        self.trigger.write_text('{"id":"busy"}')
        self.feature._handle_request(self.trigger)
        self.assertEqual(json.loads((self.status / "busy.json").read_text())["status"], "busy")
        self.commander.busy = False
        self.vm.connect_serial_console.side_effect = RuntimeError("connect")
        self.trigger.write_text('{"id":"broken"}')
        self.feature._handle_request(self.trigger)
        self.assertEqual(json.loads((self.status / "broken.json").read_text())["status"], "error")
        self.commander.logger.exception.assert_called_once()
        self.trigger.write_text('{"id":"newer"}')
        self.feature._consume_trigger(self.trigger, "older")
        self.assertTrue(self.trigger.exists())
        self.assertIsNotNone(self.feature._read_request_id(self.trigger))
        self.trigger.write_text("")
        with patch("fortinet.common.features.capture_config.uuid.uuid4", return_value=SimpleNamespace(hex="touch")):
            self.assertEqual(self.feature._read_request_id(self.trigger), "touch")
        for invalid in ('[]', '{"id":".."}', '{"id":"bad/id"}', '{"id":4}'):
            self.trigger.write_text(invalid)
            with self.assertRaises(ValueError):
                self.feature._read_request_id(self.trigger)

    def test_atomic_cleanup_config_delta_and_status_sweep(self):
        self.assertIn("set ip 9", ConfigSaveFeature.config_delta("set ip 1", "set ip 9"))
        with patch.dict(os.environ, {"FOS_NO_ENC_CONFIG": "true"}):
            self.assertEqual(ConfigSaveFeature.config_delta("set pw ENC a", "set pw ENC b"), "")
        old = self.status / "old.json"
        fresh = self.status / "fresh.json"
        self.status.mkdir()
        old.touch()
        fresh.touch()
        os.utime(old, (0, 0))
        self.feature._sweep_status_dir()
        self.assertFalse(old.exists())
        self.assertTrue(fresh.exists())
        self.feature._write_status_safely("failed", "error", "no")
        self.assertEqual(json.loads((self.status / "failed.json").read_text())["error"], "no")
        with patch.object(self.feature, "_write_status", side_effect=OSError("disk")):
            self.feature._write_status_safely("failed", "error")
        self.commander.logger.warning.assert_called()


class PkiInputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.key = root / "key.pem"
        self.cert = root / "cert.pem"
        self.ca = root / "ca.pem"
        self.crl = root / "ca.crl"
        self.password = root / "password"
        for path, text in ((self.key, "private key"), (self.cert, "certificate"),
                           (self.ca, "ca"), (self.crl, "pem crl"), (self.password, " secret \n")):
            path.write_text(text)
        self.root = root

    def test_environment_entry_parsers_and_file_readers(self):
        self.assertEqual(parse_ca_certs(f"root:{self.ca};"), [("root", str(self.ca))])
        self.assertEqual(parse_local_certs(f"leaf:{self.key}:{self.cert}"), [("leaf", str(self.key), str(self.cert))])
        self.assertEqual(parse_remote_certs(f"remote:{self.cert}"), [("remote", str(self.cert))])
        self.assertEqual(parse_crls(f"revocation:{self.crl}"), [("revocation", str(self.crl))])
        self.assertEqual(parse_pass_files(f"{self.password}"), [str(self.password)])
        self.assertEqual(read_pass_file(self.password), "secret")
        self.assertEqual(read_crl_body(self.crl), "pem crl")
        with patch("fortinet.common.features.pki.ssl._ssl._test_decode_cert", return_value={"subject": [(("commonName", "from-cert"),)]}):
            self.assertEqual(read_certificate_cn(self.cert), "from-cert")
        self.assertEqual(parse_ca_certs(None), [])
        for parser, value in ((parse_ca_certs, "missing:/no/such/file"),
                              (parse_local_certs, f"x:{self.key}"),
                              (parse_remote_certs, "missing:/no/such/file"),
                              (parse_crls, "missing:/no/such/file"),
                              (parse_pass_files, "/no/such/file")):
            with self.assertRaises(ValueError):
                parser(value)
        empty = self.root / "empty-password"
        empty.write_text(" \n")
        with self.assertRaisesRegex(ValueError, "empty password"):
            read_pass_file(empty)
        with patch("fortinet.common.features.pki.ssl._ssl._test_decode_cert", return_value={"subject": []}):
            with self.assertRaisesRegex(ValueError, "CN"):
                read_certificate_cn(self.cert)

    def test_malformed_entries_and_password_pairing(self):
        with self.assertRaisesRegex(ValueError, "refname field"):
            parse_ca_certs(str(self.ca))
        with self.assertRaisesRegex(ValueError, "path after"):
            parse_ca_certs("name:")
        with self.assertRaisesRegex(ValueError, "private key and certificate"):
            parse_local_certs(f"name:{self.key}")
        env = {
            CA_CERTS_ENV: f"root:{self.ca}",
            LOCAL_CERTS_ENV: f"leaf:{self.key}:{self.cert}",
            LOCAL_CERT_PASS_FILES_ENV: str(self.password),
            REMOTE_CERTS_ENV: f"remote:{self.cert}",
            CRLS_ENV: f"revocation:{self.crl}",
        }
        with patch.dict(os.environ, env, clear=True):
            feature = InstallPkiCertificates(SimpleNamespace(mgmt_gw_ipv4="192.0.2.1", fos_version=SimpleNamespace(major=7)), MagicMock())
        self.assertEqual(feature._local_with_password()[0][3], str(self.password))
        self.assertEqual(feature._crl_config, None)
        with patch.dict(os.environ, {LOCAL_CERTS_ENV: f"leaf:{self.key}:{self.cert}", LOCAL_CERT_PASS_FILES_ENV: f"{self.password};{self.password}"}, clear=True):
            with self.assertRaisesRegex(ValueError, "more entries"):
                InstallPkiCertificates(SimpleNamespace(mgmt_gw_ipv4="gw"), MagicMock())

    def test_install_flow_and_tftp_fallback(self):
        cmd = MagicMock()
        cmd.logger = MagicMock()
        owner = SimpleNamespace(mgmt_gw_ipv4="192.0.2.1", fos_version=SimpleNamespace(major=6))
        env = {CA_CERTS_ENV: f"root:{self.ca}", REMOTE_CERTS_ENV: f"remote:{self.cert}", CRLS_ENV: f"my-crl:{self.crl}"}
        with patch.dict(os.environ, env, clear=True):
            feature = InstallPkiCertificates(owner, cmd)
        feature._staging_directory = str(self.root / "staging")
        feature.activate()
        self.assertEqual(feature._crl_config, None)
        self.assertEqual(cmd.submit_block.call_args.args[1].name, "vpn certificate ca-root")
        feature.on_command_executed(attempt(b"Command parse error"), FOSCliState.CMD_PROMPT)
        feature.on_block_complete()
        self.assertTrue(feature._fallback_active)
        self.assertIn("execute vpn certificate ca import tftp", cmd.submit_block.call_args.args[1].children[0].line)
        feature.on_block_complete()
        self.assertEqual(feature._phase, "remote-certs")
        feature._current_item = ("remote", "remote", str(self.cert))
        feature._fallback_active = True
        with self.assertRaisesRegex(RuntimeError, "through config and TFTP"):
            feature.on_command_executed(attempt(b"Command fail"), FOSCliState.CMD_PROMPT)
        self.assertEqual(InstallPkiCertificates._crl_config_from_major(7), "vpn certificate crl")
        self.assertEqual(InstallPkiCertificates._crl_config_from_major(6), None)
        self.assertEqual(InstallPkiCertificates._crl_basename("/a/b.crl"), "b")
        empty = InstallPkiCertificates(owner, cmd)
        empty.activate()
        cmd.feature_complete.assert_called_with(empty)
        no_version = InstallPkiCertificates(SimpleNamespace(mgmt_gw_ipv4="gw", fos_version=None), cmd)
        with patch.dict(os.environ, {CA_CERTS_ENV: f"root:{self.ca}"}, clear=True):
            no_version = InstallPkiCertificates(SimpleNamespace(mgmt_gw_ipv4="gw", fos_version=None), cmd)
        with self.assertRaisesRegex(RuntimeError, "version is unavailable"):
            no_version.activate()


if __name__ == "__main__":
    unittest.main()
