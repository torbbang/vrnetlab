import ast
import os
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "common"))
import vrnetlab


class TestQemuResourceEnvironment(unittest.TestCase):
    def setUp(self):
        self.vm = object.__new__(vrnetlab.VM)
        self.vm._ram = 4096
        self.vm._cpu = "host"
        self.vm._smp = "1"

    def test_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.vm.ram, 4096)
            self.assertEqual(self.vm.cpu, "host")
            self.assertEqual(self.vm.smp, "1")

    def test_environment_overrides_defaults(self):
        with patch.dict(
            os.environ,
            {
                "QEMU_MEMORY": "8192",
                "QEMU_CPU": "qemu64",
                "QEMU_SMP": "4",
            },
            clear=False,
        ):
            self.assertEqual(self.vm.ram, 8192)
            self.assertEqual(self.vm.cpu, "qemu64")
            self.assertEqual(self.vm.smp, "4")

    def test_sonic_launchers_use_common_smp_override(self):
        launchers = [
            REPO_ROOT / "sonic/docker/launch.py",
            REPO_ROOT / "dell/dell_sonic/docker/launch.py",
            REPO_ROOT / "plvision/plvision_sonic/docker/launch.py",
        ]

        for launcher in launchers:
            source = launcher.read_text()
            self.assertNotIn('self.qemu_args.extend(["-smp", "2"])', source)
            tree = ast.parse(source, filename=str(launcher))
            smp_defaults = [
                keyword.value.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                for keyword in node.keywords
                if keyword.arg == "smp"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ]
            self.assertIn("2", smp_defaults, launcher)

    def test_sros_uses_common_resource_properties(self):
        launcher = REPO_ROOT / "nokia/sros/docker/launch.py"
        tree = ast.parse(launcher.read_text(), filename=str(launcher))
        sros_vm = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "SROS_vm"
        )
        property_names = {
            node.name
            for node in sros_vm.body
            if isinstance(node, ast.FunctionDef)
            and any(
                isinstance(decorator, ast.Name) and decorator.id == "property"
                for decorator in node.decorator_list
            )
        }
        self.assertNotIn("ram", property_names)
        self.assertNotIn("cpu", property_names)
        self.assertNotIn("smp", property_names)


class TestQemuUuid(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.vm = self.make_vm()

    def make_vm(self):
        vm = object.__new__(vrnetlab.VM)
        vm._uuid = None
        return vm

    def test_random_uuid_is_valid_stable_and_distinct_per_vm(self):
        first = self.vm.uuid
        self.assertEqual(uuid.UUID(first).version, 4)
        self.assertEqual(self.vm.uuid, first)
        self.assertNotEqual(self.make_vm().uuid, first)

    def test_environment_uuid(self):
        value = "123e4567-e89b-12d3-a456-426614174000"
        with patch.dict(os.environ, {"UUID": value}):
            self.assertEqual(self.vm.uuid, value)
        self.assertEqual(self.vm.uuid, value)

    def test_empty_environment_uuid_generates_random_uuid(self):
        with patch.dict(os.environ, {"UUID": ""}):
            self.assertEqual(uuid.UUID(self.vm.uuid).version, 4)

    def test_explicit_uuid_overrides_environment(self):
        value = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with patch.dict(os.environ, {"UUID": "123e4567-e89b-12d3-a456-426614174000"}):
            self.vm.uuid = value
            self.assertEqual(self.vm.uuid, value)

    def test_sros_zero_default_and_license_override_are_preserved(self):
        self.vm.uuid = "00000000-0000-0000-0000-000000000000"
        self.assertEqual(self.vm.uuid, "00000000-0000-0000-0000-000000000000")
        self.vm.uuid = "123e4567-e89b-12d3-a456-426614174000"
        self.assertEqual(self.vm.uuid, "123e4567-e89b-12d3-a456-426614174000")


if __name__ == "__main__":
    unittest.main()
