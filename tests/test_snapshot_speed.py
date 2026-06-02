#!/usr/bin/env python3
"""Unit tests for the multifd/mapped-ram snapshot speedup (common/vrnetlab.py).

These drive the *real* VM/VR snapshot code with the QEMU monitor and all
subprocess/sleep/cpu_count calls faked out, so they validate the actual
migrate command sequence, the parallel sparse disk copy, the metadata the
restore side reads back, and the sparse tar packaging -- without Docker, a
VM image, or a running QEMU.

Run:  uv run python -m unittest tests.test_snapshot_speed -v
"""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
import vrnetlab  # noqa: E402

VM = vrnetlab.VM
VR = vrnetlab.VR


def make_vm(tmpdir, num=0, num_nics=2):
    """A VM whose primary+secondary disks are real (empty) files on disk.

    VM.__init__ normally probes/creates an overlay disk with qemu-img; stub
    that out since these tests only exercise the snapshot codepaths and we
    set qemu_args explicitly below."""
    with mock.patch.object(VM, "_overlay_disk_image_format", return_value="qcow2"), \
         mock.patch.object(vrnetlab, "run_command"):
        vm = VM("user", "pass", disk_image="/nonexistent.qcow2", num=num)
    vm.num_nics = num_nics
    primary = os.path.join(tmpdir, "primary.img")
    secondary = os.path.join(tmpdir, "secondary.img")
    for p in (primary, secondary):
        with open(p, "wb") as f:
            f.write(b"\0" * 16)
    vm.qemu_args = [
        "-drive", f"if=ide,file={primary}",
        "-drive", f"if=ide,file={secondary}",
    ]
    return vm, primary, secondary


class _MonitorRecorder:
    """Stands in for VM._qemu_monitor_cmd, recording every command in order
    and returning a 'completed' status for the migration poll."""

    def __init__(self):
        self.cmds = []

    def __call__(self, cmd, wait=False):
        self.cmds.append(cmd)
        if cmd == "info migrate":
            return "Migration status: completed"
        if cmd == "info network":
            return ""  # no MACs
        return None


class SnapshotSaveToDir(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = self.enterContext(tempfile.TemporaryDirectory())
        # No real waiting, deterministic channel count.
        self.enterContext(mock.patch.object(vrnetlab.time, "sleep"))
        self.enterContext(mock.patch.object(vrnetlab.os, "cpu_count", return_value=4))
        # Record cp/tar without actually shelling out, but create the dest so
        # downstream code that may stat it is happy.
        self.calls = []

        def fake_check_call(args, *a, **k):
            self.calls.append(list(args))
            if args[:1] == ["cp"]:
                # cp --sparse=always SRC DEST  -> make DEST exist
                with open(args[-1], "wb") as f:
                    f.write(b"")
            return 0

        self.enterContext(
            mock.patch.object(vrnetlab.subprocess, "check_call", fake_check_call)
        )

    def _run(self):
        vm, primary, secondary = make_vm(self.tmp)
        rec = _MonitorRecorder()
        vm._qemu_monitor_cmd = rec
        vm_dir = os.path.join(self.tmp, "vm0")
        result = vm.snapshot_save_to_dir(vm_dir)
        return vm, rec, result, vm_dir

    def test_uses_file_migration_not_exec_cat(self):
        _, rec, _, vm_dir = self._run()
        state = os.path.join(vm_dir, "state.img")
        self.assertIn(f'migrate "file:{state}"', rec.cmds)
        self.assertFalse(
            any("exec:cat" in c for c in rec.cmds),
            "old exec:cat path must be gone",
        )

    def test_enables_multifd_and_mapped_ram_with_cpu_channels(self):
        _, rec, _, _ = self._run()
        self.assertIn("migrate_set_capability multifd on", rec.cmds)
        self.assertIn("migrate_set_capability mapped-ram on", rec.cmds)
        # os.cpu_count patched to 4
        self.assertIn("migrate_set_parameter multifd-channels 4", rec.cmds)

    def test_monitor_command_order(self):
        _, rec, _, vm_dir = self._run()
        # stop -> set caps -> migrate -> poll info migrate -> cont
        i_stop = rec.cmds.index("stop")
        i_caps = rec.cmds.index("migrate_set_capability multifd on")
        i_migrate = rec.cmds.index(
            f'migrate "file:{os.path.join(vm_dir, "state.img")}"'
        )
        i_poll = rec.cmds.index("info migrate")
        i_cont = rec.cmds.index("cont")
        self.assertLess(i_stop, i_caps)
        self.assertLess(i_caps, i_migrate)
        # migration kicked off before we start polling for completion (the
        # disk copies are submitted in that gap -> overlap)
        self.assertLess(i_migrate, i_poll)
        self.assertLess(i_poll, i_cont)

    def test_never_sets_compression(self):
        # zstd/TLS compression is incompatible with mapped-ram migration
        # ("Cannot use compression with mapped-ram"), so it must never be set.
        _, rec, _, _ = self._run()
        self.assertFalse(any("compression" in c or "zstd" in c for c in rec.cmds))

    def test_disks_copied_sparse_in_parallel(self):
        self._run()
        cp_calls = [c for c in self.calls if c[:1] == ["cp"]]
        self.assertEqual(len(cp_calls), 2, "primary + secondary copied")
        for c in cp_calls:
            self.assertIn("--sparse=always", c)
        # primary renamed to disk.qcow2
        self.assertTrue(any(c[-1].endswith("disk.qcow2") for c in cp_calls))

    def test_metadata_records_secondary_disks(self):
        _, _, _, vm_dir = self._run()
        with open(os.path.join(vm_dir, "metadata.json")) as f:
            meta = json.load(f)
        self.assertEqual(meta["secondary_disks"], ["secondary.img"])
        self.assertNotIn("compression", meta)


class VRTarPackaging(unittest.TestCase):
    def _vr(self):
        vr = VR.__new__(VR)  # skip __init__ (needs username/password plumbing)
        vr.logger = vrnetlab.logging.getLogger()
        return vr

    def test_snapshot_save_uses_sparse_tar(self):
        vr = self._vr()
        vm = mock.Mock()
        vm.num = 0
        vr.vms = [vm]
        calls = []
        with mock.patch.object(
            vrnetlab.subprocess, "check_call", lambda a, *x, **k: calls.append(list(a))
        ):
            path = vr.snapshot_save()
        self.assertEqual(path, "/snapshot-output.tar")
        vm.snapshot_save_to_dir.assert_called_once()
        # sparse tar create: tar -Scf <tar> -C <tmpdir> vm0
        self.assertEqual(len(calls), 1)
        tar = calls[0]
        self.assertEqual(tar[0], "tar")
        self.assertEqual(tar[1], "-Scf")
        self.assertEqual(tar[2], "/snapshot-output.tar")
        self.assertEqual(tar[3], "-C")
        self.assertIn("vm0", tar)

    def test_snapshot_restore_uses_sparse_tar(self):
        vr = self._vr()
        calls = []
        with mock.patch.object(vrnetlab.os.path, "exists", return_value=True), \
             mock.patch.object(vrnetlab.os, "makedirs"), \
             mock.patch.object(
                 vrnetlab.subprocess, "check_call",
                 lambda a, *x, **k: calls.append(list(a)),
             ):
            out = vr.snapshot_restore()
        self.assertEqual(out, "/snapshot-data")
        self.assertEqual(
            calls, [["tar", "-Sxf", "/snapshot.tar", "-C", "/snapshot-data"]]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
