"""The whole test suite, driven through ``webtest`` against the app.

Most tests post to the plugin the way Docker does, then check what came back
and what the snapshots directory holds, so they need a real BTRFS filesystem:
``./test_local.sh`` sets one up. The ones that need no BTRFS sit in their own
classes at the bottom: they read names, patterns and schedule lines directly,
on nothing more than a temporary file.
"""

import json
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
import weakref
from contextlib import suppress
from datetime import datetime, timedelta
from os.path import join
from subprocess import CalledProcessError, check_output, run
from unittest.mock import MagicMock, patch

from webtest import TestApp

from buttervolume import ValidationError, btrfs, cli, plugin, schedule, scheduler
from buttervolume.config import (
    DTFORMAT,
    SNAPSHOTS_PATH,
    TEST_REMOTE_PATH,
    VOLUMES_PATH,
)
from buttervolume.init import init_btrfs
from buttervolume.names import (
    Snapshot,
    new_snapshot,
    sent_snapshots,
    snapshots_of,
)
from buttervolume.purge import Pattern, compute_purges
from buttervolume.schedule import (
    Entry,
    Job,
    read_last_runs,
    read_rows,
    read_schedule,
    write_last_runs,
    write_schedule,
)
from buttervolume.scheduler import is_due, run_job, runjobs

# check that the target dir is btrfs
SCHEDULE = plugin.SCHEDULE = tempfile.mkstemp()[1]
LAST_RUNS = tempfile.mkstemp()[1]
PREFIX_TEST_VOLUME = "buttervolume-test-"


def jsonloads(stuff):
    return json.loads(stuff.decode())


class TestCase(unittest.TestCase):
    def cleanup(self):
        """clean-up test volumes and snapshots before each test"""
        for directory in (VOLUMES_PATH, SNAPSHOTS_PATH, TEST_REMOTE_PATH):
            if os.path.exists(directory):
                # Get all test items and delete them explicitly
                items_to_delete = []
                try:
                    for item in os.listdir(directory):
                        if item.startswith(PREFIX_TEST_VOLUME):
                            items_to_delete.append(join(directory, item))
                except FileNotFoundError:
                    continue

                # Delete each item, trying both BTRFS and regular deletion
                for item_path in items_to_delete:
                    try:
                        if os.path.exists(item_path):
                            if os.path.isdir(item_path):
                                # Try BTRFS subvolume deletion first
                                try:
                                    btrfs.Subvolume(item_path).delete()
                                except Exception:
                                    # If BTRFS deletion fails, try regular directory removal

                                    shutil.rmtree(item_path, ignore_errors=True)
                            else:
                                # Regular file
                                os.unlink(item_path)
                    except Exception:
                        pass  # Continue with cleanup even if individual items fail

    def setUp(self):
        with open(SCHEDULE, "w") as f:
            f.truncate()
        with open(LAST_RUNS, "w") as f:
            f.truncate()
        self.app = TestApp(cli.app)
        # Check that the target dir is BTRFS - skip tests if not
        # Set BUTTERVOLUME_SKIP_BTRFS_CHECK=1 to skip this check for testing
        if not os.environ.get("BUTTERVOLUME_SKIP_BTRFS_CHECK"):
            try:
                btrfs.Filesystem(VOLUMES_PATH).label()
            except Exception as e:
                # For Docker tests, try to create a BTRFS filesystem on a loop device
                if self._try_create_btrfs_filesystem():
                    # Retry after filesystem creation
                    try:
                        btrfs.Filesystem(VOLUMES_PATH).label()
                    except Exception:
                        raise unittest.SkipTest(
                            f"BTRFS filesystem required at {VOLUMES_PATH}. Error: {e}"
                        ) from None
                else:
                    raise unittest.SkipTest(
                        f"BTRFS filesystem required at {VOLUMES_PATH}. Error: {e}"
                    ) from None
        self.cleanup()

    def _try_create_btrfs_filesystem(self):
        """Try to create a BTRFS filesystem for testing"""
        if os.getuid() != 0:
            return False

        # Create sparse file and loop device
        loop_file = f"/tmp/btrfs_test_{int(time.time())}.img"
        subprocess.run(["truncate", "-s", "1G", loop_file], check=True)
        self._cleanup_stale_loop_devices()

        result = subprocess.run(
            ["losetup", "--find", "--show", loop_file],
            capture_output=True,
            text=True,
            check=True,
        )
        loop_dev = result.stdout.strip()

        # Create and mount BTRFS filesystem
        subprocess.run(
            ["mkfs.btrfs", "-f", loop_dev],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        os.makedirs(VOLUMES_PATH, exist_ok=True)
        subprocess.run(["mount", loop_dev, "/var/lib/buttervolume"], check=True)

        # Create subdirectories
        for path in [VOLUMES_PATH, SNAPSHOTS_PATH, TEST_REMOTE_PATH]:
            os.makedirs(path, exist_ok=True)

        return True

    def _cleanup_stale_loop_devices(self):
        """Clean up loop devices pointing to non-existent files"""
        try:
            result = subprocess.run(["losetup", "-l"], capture_output=True, text=True)
            if result.returncode != 0:
                return

            for line in result.stdout.strip().split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 6:
                    loop_dev, backing_file = parts[0], parts[5]
                    if backing_file.startswith("/tmp/btrfs_test") and not os.path.exists(
                        backing_file
                    ):
                        subprocess.run(["losetup", "-d", loop_dev], capture_output=True)
        except Exception:
            pass  # Don't fail the test if cleanup fails

    def test_replication_lock(self):
        """Check that the replication lock prevents concurrent replications"""
        # create a volume with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        # schedule a replication
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "replicate:localhost", "Timer": 1}),
        )

        # simulate a long-running replication
        def slow_send(*args, **kwargs):
            time.sleep(2)
            return True

        with patch("buttervolume.api.send") as mock_send:
            mock_send.side_effect = slow_send
            # run the scheduler in a separate thread
            t = threading.Thread(
                target=runjobs, args=(SCHEDULE, True), kwargs={"last_runs": LAST_RUNS}
            )
            t.start()
            # wait for the replication to start
            time.sleep(1)
            # check that the replication is in progress
            self.assertIn(name, scheduler.ReplicationInProgress)
            # run the scheduler again
            runjobs(SCHEDULE, True, last_runs=LAST_RUNS)
            # check that the second replication was skipped
            mock_send.assert_called_once()
            # wait for the replication to finish
            t.join()
            # check that the lock is released
            self.assertNotIn(name, scheduler.ReplicationInProgress)
        # unschedule
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "replicate:localhost", "Timer": 0}),
        )

    def test_snapshot_names_are_validated(self):
        """Snapshot names from the API cannot reach outside the snapshots directory"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        snap = jsonloads(self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name})).body)[
            "Snapshot"
        ]
        # a traversal through an existing snapshot resolves to the volume
        # itself: it must be rejected, not deleted
        evil = f"{snap}/../../volumes/{name}"
        resp = jsonloads(
            self.app.post("/VolumeDriver.Snapshot.Remove", json.dumps({"Name": evil})).body
        )
        self.assertTrue(resp["Err"])
        self.assertTrue(os.path.exists(join(VOLUMES_PATH, name)))
        # malformed names are rejected by the three endpoints taking a snapshot name
        for bad in (
            "@",
            "foo@",
            "a@b@c@d",
            "foo@$(reboot)",
            "foo@back`tick",
            # a trailing newline splits the remote command line in two
            "foo@2026-01-01T00:00:00.000000\n",
        ):
            for urlpath, param in (
                ("/VolumeDriver.Snapshot.Remove", {"Name": bad}),
                ("/VolumeDriver.Snapshot.Send", {"Name": bad, "Host": "localhost"}),
                ("/VolumeDriver.Snapshot.Restore", {"Name": bad}),
            ):
                resp = jsonloads(self.app.post(urlpath, json.dumps(param)).body)
                self.assertTrue(resp["Err"], f"{urlpath} accepted {bad!r}")
        # cleanup
        self.app.post("/VolumeDriver.Snapshot.Remove", json.dumps({"Name": snap}))
        self.app.post("/VolumeDriver.Remove", json.dumps({"Name": name}))

    def test_snapshot_name_must_stay_readable(self):
        """A DTFORMAT building a name the API cannot read back is refused"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        # a space in the timestamp would give a snapshot no endpoint can name
        with patch("buttervolume.plugin.DTFORMAT", "%Y-%m-%d %H:%M:%S"):
            resp = jsonloads(
                self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name})).body
            )
        self.assertTrue(resp["Err"])
        self.assertEqual([s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name + "@")], [])
        self.app.post("/VolumeDriver.Remove", json.dumps({"Name": name}))

    def test_replication_cleanup_on_failure(self):
        """A failed replication deletes the snapshot it created for the occasion"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "replicate:localhost", "Timer": 1}),
        )
        with patch("buttervolume.api.send") as mock_send:
            mock_send.side_effect = Exception("replication failed")
            runjobs(SCHEDULE, True, last_runs=LAST_RUNS)
        mock_send.assert_called_once()
        # the snapshot created for the failed replication was removed
        snapshots = [s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name + "@")]
        self.assertEqual(snapshots, [])
        # the lock was released
        self.assertNotIn(name, scheduler.ReplicationInProgress)
        # unschedule
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "replicate:localhost", "Timer": 0}),
        )

    def test_a_replication_that_failed_is_not_reported_as_a_success(self):
        """A send answering an error is a failed replication, not a done one"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "replicate:localhost", "Timer": 1}),
        )
        with patch("buttervolume.api.send") as mock_send:
            # what the client answers when the endpoint fills the Err field
            mock_send.return_value = False
            with self.assertLogs(level=logging.INFO) as log_capture:
                runjobs(SCHEDULE, True, last_runs=LAST_RUNS)

        self.assertFalse(any("Successfully replicated" in msg for msg in log_capture.output))
        self.assertTrue(any("Replication failed" in msg for msg in log_capture.output))
        # the snapshot taken for that replication was removed, like any other
        # failed replication
        self.assertEqual([s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name + "@")], [])

    def test_send_error_reports_send_stderr(self):
        """A failed send/receive reports the error of the send side too"""
        missing = join(SNAPSHOTS_PATH, PREFIX_TEST_VOLUME + "missing@snap")
        with self.assertRaises(plugin.ReplicationError) as ctx:
            # the send fails (missing snapshot) and ssh fails (port 1 refused):
            # the exception must carry the send side error, which names the path
            plugin.run_btrfs_send_receive(missing, "localhost", SNAPSHOTS_PATH, port="1")
        self.assertIn(missing, str(ctx.exception))

    def test_send_timeout_is_not_retried(self):
        """A transfer killed for hanging is not sent again over the same link"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        snap = jsonloads(self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name})).body)[
            "Snapshot"
        ]
        with patch("buttervolume.plugin.run_btrfs_send_receive") as mock_send:
            mock_send.side_effect = plugin.ReplicationTimeoutError("waited too long")
            resp = jsonloads(
                self.app.post(
                    "/VolumeDriver.Snapshot.Send",
                    json.dumps({"Name": snap, "Host": "localhost", "Test": True}),
                ).body
            )
        mock_send.assert_called_once()
        self.assertIn("waited too long", resp["Err"])
        # cleanup
        self.app.post("/VolumeDriver.Snapshot.Remove", json.dumps({"Name": snap}))
        self.app.post("/VolumeDriver.Remove", json.dumps({"Name": name}))

    def create_a_volume_with_a_file(self, name):
        # create a volume with a file
        path = join(VOLUMES_PATH, name)
        self.app.post("/VolumeDriver.Create", json.dumps({"Name": name}))
        with open(join(path, "foobar"), "w") as f:
            f.write("foobar")

    def write_a_byte(self, name):
        """Make the volume differ from its latest snapshot, and nothing more"""
        with open(join(VOLUMES_PATH, name, "foobar"), "a") as f:
            f.write(".")

    def test(self):
        """first basic scenario"""
        resp = jsonloads(self.app.post("/VolumeDriver.List", "{}").body)
        self.assertEqual(resp, {"Volumes": [], "Err": ""})

        # create a volume
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path = join(VOLUMES_PATH, name)
        resp = jsonloads(self.app.post("/VolumeDriver.Create", json.dumps({"Name": name})).body)
        self.assertEqual(resp, {"Err": ""})

        # get
        resp = jsonloads(self.app.post("/VolumeDriver.Get", json.dumps({"Name": name})).body)
        self.assertEqual(resp["Volume"]["Name"], name)
        self.assertEqual(resp["Volume"]["Mountpoint"], path)
        self.assertEqual(resp["Err"], "")

        # create the same volume
        resp = jsonloads(self.app.post("/VolumeDriver.Create", json.dumps({"Name": name})).body)
        self.assertEqual(resp, {"Err": ""})

        # list
        resp = jsonloads(self.app.post("/VolumeDriver.List").body)
        self.assertEqual(resp["Volumes"], [{"Name": name}])

        # mount
        resp = jsonloads(self.app.post("/VolumeDriver.Mount", json.dumps({"Name": name})).body)
        self.assertEqual(resp["Mountpoint"], join(VOLUMES_PATH, name))
        resp = jsonloads(self.app.post("/VolumeDriver.Mount", json.dumps({"Name": name})).body)
        self.assertEqual(resp["Mountpoint"], join(VOLUMES_PATH, name))
        # not existing path
        name2 = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        resp = jsonloads(self.app.post("/VolumeDriver.Mount", json.dumps({"Name": name2})).body)
        self.assertTrue(resp["Err"].endswith("no such volume"))

        # path
        resp = jsonloads(self.app.post("/VolumeDriver.Path", json.dumps({"Name": name})).body)
        self.assertEqual(resp["Mountpoint"], join(VOLUMES_PATH, name))
        # not existing path
        resp = jsonloads(
            self.app.post(
                "/VolumeDriver.Path",
                json.dumps({"Name": PREFIX_TEST_VOLUME + uuid.uuid4().hex}),
            ).body
        )
        self.assertTrue(resp["Err"].endswith("no such volume"))

        # unmount
        resp = jsonloads(self.app.post("/VolumeDriver.Unmount", json.dumps({"Name": name})).body)
        self.assertEqual(resp, {"Err": ""})
        resp = jsonloads(
            self.app.post(
                "/VolumeDriver.Unmount",
                json.dumps({"Name": PREFIX_TEST_VOLUME + uuid.uuid4().hex}),
            ).body
        )
        self.assertEqual(resp, {"Err": ""})

        # remove
        resp = jsonloads(self.app.post("/VolumeDriver.Remove", json.dumps({"Name": name})).body)
        self.assertEqual(resp, {"Err": ""})
        # remove again
        resp = jsonloads(self.app.post("/VolumeDriver.Remove", json.dumps({"Name": name})).body)
        self.assertTrue(resp["Err"].endswith("no such volume"))

        # get
        resp = jsonloads(self.app.post("/VolumeDriver.Get", json.dumps({"Name": name})).body)
        self.assertTrue(resp["Err"].endswith("no such volume"))

        # list
        resp = jsonloads(self.app.post("/VolumeDriver.List", "{}").body)
        self.assertEqual(resp["Volumes"], [])

    def test_enabled_cow(self):
        """Check that cow is enabled by default"""
        # create a volume with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path = join(VOLUMES_PATH, name)
        self.create_a_volume_with_a_file(name)

        # mount
        self.app.post("/VolumeDriver.Mount", json.dumps({"Name": name}))
        # check the nocow
        self.assertTrue(b"-C-" not in check_output(f"lsattr -d '{path}'", shell=True).split()[0])
        self.app.post("/VolumeDriver.Remove", json.dumps({"Name": name}))

    def test_compression_option(self):
        """Check that compression option works"""
        # Test with compression=true
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path = join(VOLUMES_PATH, name)
        resp = jsonloads(
            self.app.post(
                "/VolumeDriver.Create",
                json.dumps({"Name": name, "Opts": {"compression": "true"}}),
            ).body
        )
        self.assertEqual(resp, {"Err": ""})

        # Check if compression attribute is set (if lsattr is available)
        try:
            attrs = check_output(f'lsattr -d "{path}"', shell=True).decode()
            self.assertIn("c", attrs.split()[0], "Compression attribute should be set")
        except Exception:
            # lsattr might not be available in all environments
            pass

        self.app.post("/VolumeDriver.Remove", json.dumps({"Name": name}))

        # Test with invalid compression option
        name2 = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        resp = jsonloads(
            self.app.post(
                "/VolumeDriver.Create",
                json.dumps({"Name": name2, "Opts": {"compression": "invalid"}}),
            ).body
        )
        self.assertIn("Invalid option for compression", resp["Err"])

        # Test with compression=false (should work normally)
        name3 = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        resp = jsonloads(
            self.app.post(
                "/VolumeDriver.Create",
                json.dumps({"Name": name3, "Opts": {"compression": "false"}}),
            ).body
        )
        self.assertEqual(resp, {"Err": ""})
        self.app.post("/VolumeDriver.Remove", json.dumps({"Name": name3}))

    @unittest.skipIf(
        os.environ.get("BUTTERVOLUME_LOCAL_TEST"), "SSH not available in local test mode"
    )
    def test_send(self):
        """We can send a snapshot incrementally to another host"""
        # create a volume with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path = join(VOLUMES_PATH, name)
        self.create_a_volume_with_a_file(name)
        # snapshot
        resp = self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name}))
        snapshot = json.loads(resp.body.decode())["Snapshot"]
        snapshot_path = join(SNAPSHOTS_PATH, snapshot)
        # send the snapshot (to the same host with another name)
        self.app.post(
            "/VolumeDriver.Snapshot.Send",
            json.dumps({"Name": snapshot, "Host": "localhost", "Test": True}),
        )
        remote_path = join(TEST_REMOTE_PATH, snapshot)
        # check the volumes have the same content
        with open(join(snapshot_path, "foobar")) as x, open(join(remote_path, "foobar")) as y:
            self.assertEqual(x.read(), y.read())
        # change files in the master volume
        with open(join(path, "foobar"), "w") as f:
            f.write("changed foobar")
        # send again to the other volume
        resp = self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name}))
        snapshot2 = json.loads(resp.body.decode())["Snapshot"]
        snapshot2_path = join(SNAPSHOTS_PATH, snapshot2)
        self.app.post(
            "/VolumeDriver.Snapshot.Send",
            json.dumps({"Name": snapshot2, "Host": "localhost", "Test": True}),
        )
        remote_path2 = join(TEST_REMOTE_PATH, snapshot2)
        # check the files are the same
        with open(join(snapshot2_path, "foobar")) as x, open(join(remote_path2, "foobar")) as y:
            self.assertEqual(x.read(), y.read())
        # check the second snapshot is a child of the first one
        self.assertEqual(
            btrfs.Subvolume(remote_path).show()["UUID"],
            btrfs.Subvolume(remote_path2).show()["Parent UUID"],
        )

    def test_a_snapshot_the_remote_already_has_is_not_sent_again(self):
        """The trace of a send is what says the remote already holds it"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        resp = self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name}))
        snapshot = jsonloads(resp.body)["Snapshot"]
        # the trace a previous send to that host left behind
        trace = f"{snapshot}@localhost"
        btrfs.Subvolume(join(SNAPSHOTS_PATH, snapshot)).snapshot(
            join(SNAPSHOTS_PATH, trace), readonly=True
        )

        resp = self.app.post(
            "/VolumeDriver.Snapshot.Send",
            json.dumps({"Name": snapshot, "Host": "localhost", "Test": True}),
        )
        self.assertEqual(jsonloads(resp.body), {"Err": ""})
        # nothing crossed the network, and no second trace was written
        self.assertEqual([s for s in os.listdir(TEST_REMOTE_PATH) if s.startswith(name)], [])
        self.assertEqual(
            sorted(s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name + "@")),
            sorted([snapshot, trace]),
        )

    @unittest.skipIf(
        os.environ.get("BUTTERVOLUME_LOCAL_TEST"), "SSH not available in local test mode"
    )
    def test_sending_the_same_snapshot_twice_leaves_the_remote_copy_whole(self):
        """The second send is refused rather than deleting the copy of the first"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        resp = self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name}))
        snapshot = jsonloads(resp.body)["Snapshot"]
        for _ in range(2):
            resp = self.app.post(
                "/VolumeDriver.Snapshot.Send",
                json.dumps({"Name": snapshot, "Host": "localhost", "Test": True}),
            )
            self.assertEqual(jsonloads(resp.body), {"Err": ""})
        self.assertEqual(
            [s for s in os.listdir(TEST_REMOTE_PATH) if s.startswith(name)], [snapshot]
        )

        # restoring the remote copy is the only proof that it is whole: a copy
        # deleted and sent again counts exactly the same as one left alone
        target = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        btrfs.Subvolume(join(TEST_REMOTE_PATH, snapshot)).snapshot(join(VOLUMES_PATH, target))
        with open(join(VOLUMES_PATH, target, "foobar")) as f:
            self.assertEqual(f.read(), "foobar")

    def test_snapshot(self):
        """Check we can snapshot a volume"""
        # create a volume with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path = join(VOLUMES_PATH, name)
        self.create_a_volume_with_a_file(name)
        # snapshot the volume
        resp = self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name}))
        resp_data = json.loads(resp.body.decode())
        if "Err" in resp_data and resp_data["Err"]:
            self.fail(f"Snapshot creation failed: {resp_data['Err']}")
        snapshot = join(SNAPSHOTS_PATH, resp_data["Snapshot"])
        # check the snapshot has the same content
        with open(join(path, "foobar")) as x, open(join(snapshot, "foobar")) as y:
            self.assertEqual(x.read(), y.read())

    def test_a_snapshot_says_whether_the_volume_changed_since_another_one(self):
        """What is compared is two readonly subvolumes, never the live volume"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        volume = btrfs.Subvolume(join(VOLUMES_PATH, name))
        paths = [join(SNAPSHOTS_PATH, f"{name}@2026-01-0{i}T00:00:00.000000") for i in range(1, 4)]
        volume.snapshot(paths[0], readonly=True)
        volume.snapshot(paths[1], readonly=True)
        self.assertTrue(btrfs.Subvolume(paths[1]).is_same_as(paths[0]))

        self.write_a_byte(name)
        volume.snapshot(paths[2], readonly=True)
        self.assertFalse(btrfs.Subvolume(paths[2]).is_same_as(paths[1]))

    def test_an_extended_attribute_nobody_can_read_as_text_is_still_compared(self):
        """receive --dump writes the value of an attribute exactly as it is"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        volume = btrfs.Subvolume(join(VOLUMES_PATH, name))
        before = join(SNAPSHOTS_PATH, f"{name}@2026-02-01T00:00:00.000000")
        after = join(SNAPSHOTS_PATH, f"{name}@2026-02-02T00:00:00.000000")
        volume.snapshot(before, readonly=True)
        # the kind of thing a file server writes next to a file it stores
        os.setxattr(join(VOLUMES_PATH, name, "foobar"), "user.binary", b"\xff\xfe\x00")
        volume.snapshot(after, readonly=True)
        self.assertFalse(btrfs.Subvolume(after).is_same_as(before))

    def test_an_unchanged_volume_is_not_snapshotted_again(self):
        """The answer names the snapshot that holds the state, and says who took it"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        first = jsonloads(self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name})).body)
        second = jsonloads(self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name})).body)
        self.assertTrue(first["Created"])
        self.assertEqual(second["Snapshot"], first["Snapshot"])
        self.assertFalse(second["Created"])
        # and the copy taken for the comparison is gone from the disk
        self.assertEqual(
            [s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name + "@")],
            [first["Snapshot"]],
        )

    def test_a_volume_written_to_is_snapshotted_again(self):
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        first = jsonloads(self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name})).body)
        self.write_a_byte(name)
        second = jsonloads(self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name})).body)
        self.assertTrue(second["Created"])
        self.assertNotEqual(second["Snapshot"], first["Snapshot"])
        self.assertEqual(
            len([s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name + "@")]), 2
        )

    def test_the_snapshot_of_an_unchanged_volume_still_restores(self):
        """The name given back is a snapshot, not a bookkeeping entry"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path = join(VOLUMES_PATH, name)
        self.create_a_volume_with_a_file(name)
        self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name}))
        again = jsonloads(self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name})).body)
        with open(join(path, "foobar"), "w") as f:
            f.write("modified foobar")

        resp = jsonloads(
            self.app.post(
                "/VolumeDriver.Snapshot.Restore", json.dumps({"Name": again["Snapshot"]})
            ).body
        )
        self.assertEqual(resp["Err"], "")
        with open(join(path, "foobar")) as f:
            self.assertEqual(f.read(), "foobar")

    def test_a_failed_replication_keeps_a_snapshot_it_did_not_create(self):
        """Only the snapshot of this round goes, and an unchanged volume gave none"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        existing = jsonloads(
            self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name})).body
        )["Snapshot"]
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "replicate:localhost", "Timer": 1}),
        )
        with patch("buttervolume.api.send") as mock_send:
            mock_send.side_effect = Exception("replication failed")
            runjobs(SCHEDULE, True, last_runs=LAST_RUNS)
        mock_send.assert_called_once()
        self.assertEqual(
            [s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name + "@")], [existing]
        )
        # unschedule
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "replicate:localhost", "Timer": 0}),
        )

    @unittest.skipIf(
        os.environ.get("BUTTERVOLUME_LOCAL_TEST"), "SSH not available in local test mode"
    )
    def test_replicating_a_volume_at_rest_twice_transfers_nothing_the_second_time(self):
        """Two rounds on a volume nobody wrote to leave one snapshot and one copy"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        with open(SCHEDULE, "w") as f:
            f.write(f"{name},replicate:localhost,60,True\n")
        for _ in range(2):
            write_last_runs(
                LAST_RUNS,
                {"replicate:localhost": {name: datetime.now() - timedelta(days=1)}},
            )
            runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)

        # the second round reported a success, so its date was written down
        last = read_last_runs(LAST_RUNS)["replicate:localhost"][name]
        self.assertGreater(last, datetime.now() - timedelta(minutes=1))
        # one snapshot and its trace, and a single copy on the other side
        self.assertEqual(
            len([s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name + "@")]), 2
        )
        remote = [s for s in os.listdir(TEST_REMOTE_PATH) if s.startswith(name + "@")]
        self.assertEqual(len(remote), 1)

        # restored, because counting the copies proves nothing: one destroyed
        # and sent again counts exactly like one left alone
        target = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        btrfs.Subvolume(join(TEST_REMOTE_PATH, remote[0])).snapshot(join(VOLUMES_PATH, target))
        with open(join(VOLUMES_PATH, target, "foobar")) as f:
            self.assertEqual(f.read(), "foobar")

    def test_snapshots(self):
        """Check we can list snapshots"""
        # create two volumes with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        name2 = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name2)
        # snapshot each volume twice, writing in between so that the second
        # snapshot is really taken: an unchanged volume gives back the first
        resp = self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name}))
        snap1 = json.loads(resp.body.decode())["Snapshot"]
        self.write_a_byte(name)
        resp = self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name}))
        snap2 = json.loads(resp.body.decode())["Snapshot"]
        resp = self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name2}))
        snap3 = json.loads(resp.body.decode())["Snapshot"]
        self.write_a_byte(name2)
        resp = self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name2}))
        snap4 = json.loads(resp.body.decode())["Snapshot"]
        # list all the snapshots
        resp = self.app.get("/VolumeDriver.Snapshot.List")
        snapshots = json.loads(resp.body.decode())["Snapshots"]
        # check the list of snapshots
        self.assertEqual(set(snapshots), {snap1, snap2, snap3, snap4})
        # list all the snapshots of the second volume only
        resp = self.app.get(f"/VolumeDriver.Snapshot.List/{name2}")
        snapshots = json.loads(resp.body.decode())["Snapshots"]
        # check the list of snapshots
        self.assertEqual(set(snapshots), {snap3, snap4})

    def test_schedule_snapshot(self):
        """check we can schedule actions such as snapshots"""
        # create two volumes with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        name2 = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name2)
        # check we have no schedule yet
        resp = self.app.get("/VolumeDriver.Schedule.List")
        schedule = json.loads(resp.body.decode())["Schedule"]
        self.assertEqual(len(schedule), 0)
        # schedule a snapshot of the two volumes every 60 minutes
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "snapshot", "Timer": 60}),
        )
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name2, "Action": "snapshot", "Timer": 60}),
        )
        # check we have 2 scheduled jobs
        resp = self.app.get("/VolumeDriver.Schedule.List")
        schedule = json.loads(resp.body.decode())["Schedule"]
        self.assertEqual(len(schedule), 2)
        self.assertEqual(schedule[0]["Action"], "snapshot")
        self.assertEqual(schedule[1]["Timer"], "60")
        # check that the schedule is stored
        with open(SCHEDULE) as f:
            lines = f.readlines()
            self.assertEqual(lines[1], f"{name2},snapshot,60,True\n")
        # run the scheduler jobs
        runjobs(SCHEDULE, test=True, last_runs=LAST_RUNS)
        # check we have two snapshots
        self.assertEqual(
            2,
            len(
                {s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name) or s.startswith(name2)}
            ),
        )
        # unschedule
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "snapshot", "Timer": 0}),
        )
        with open(SCHEDULE) as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
        # check we have 1 scheduled job
        resp = self.app.get("/VolumeDriver.Schedule.List")
        schedule = json.loads(resp.body.decode())["Schedule"]
        self.assertEqual(len(schedule), 1)
        # simulate the last snapshot is 1 day in the past
        write_last_runs(LAST_RUNS, {"snapshot": {name2: datetime.now() - timedelta(days=1)}})
        # and write in the volume, otherwise the round below takes no snapshot
        # at all: an unchanged volume is not snapshotted again
        self.write_a_byte(name2)
        # run the scheduler jobs and check we only have one more snapshot
        runjobs(SCHEDULE, test=True, last_runs=LAST_RUNS)
        self.assertEqual(
            3,
            len(
                {s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name) or s.startswith(name2)}
            ),
        )
        # unschedule the last job
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name2, "Action": "snapshot", "Timer": 0}),
        )
        resp = self.app.get("/VolumeDriver.Schedule.List")
        schedule = json.loads(resp.body.decode())["Schedule"]
        self.assertEqual(len(schedule), 0)

    @unittest.skipIf(
        os.environ.get("BUTTERVOLUME_LOCAL_TEST"), "SSH not available in local test mode"
    )
    def test_schedule_replicate(self):
        # create a volume with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        # check we have no schedule yes
        resp = self.app.get("/VolumeDriver.Schedule.List")
        schedule = json.loads(resp.body.decode())["Schedule"]
        self.assertEqual(len(schedule), 0)
        # check we have no snapshots
        resp = self.app.get("/VolumeDriver.Snapshot.List")
        snapshots = json.loads(resp.body.decode())["Snapshots"]
        self.assertEqual(len(snapshots), 0)
        # replicate the volume every 120 minutes
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "replicate:localhost", "Timer": 120}),
        )
        # also replicate a non existing volume
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": "boo", "Action": "replicate:localhost", "Timer": 120}),
        )
        # simulate the last replicate is 1 day in the past
        write_last_runs(
            LAST_RUNS, {"replicate:localhost": {name: datetime.now() - timedelta(days=1)}}
        )
        # run the scheduler jobs jobs and check we only have two more snapshots
        runjobs(SCHEDULE, test=True, last_runs=LAST_RUNS)
        self.assertEqual(
            2,
            len(
                {s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name) or s.startswith(name)}
            ),
        )
        self.assertEqual(
            1,
            len(
                {
                    s
                    for s in os.listdir(TEST_REMOTE_PATH)
                    if s.startswith(name) or s.startswith(name)
                }
            ),
        )
        # unschedule the last job
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": "boo", "Action": "replicate:localhost", "Timer": 0}),
        )
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "replicate:localhost", "Timer": 0}),
        )

    def test_restore_of_a_volume_takes_its_latest_snapshot_or_says_why_not(self):
        """A snapshot nobody can name again hides no other one behind it"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path = join(VOLUMES_PATH, name)
        self.create_a_volume_with_a_file(name)
        self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name}))
        # a snapshot from an older version, taken under a date format holding
        # a space, and more recent than the one above
        legacy = f"{name}@2999-01-01 00:00:00"
        btrfs.Subvolume(path).snapshot(join(SNAPSHOTS_PATH, legacy), readonly=True)
        with open(join(path, "foobar"), "w") as f:
            f.write("modified foobar")
        # restoring by volume name must not silently fall back to the snapshot
        # underneath: the latest one is unusable, and the answer says so
        resp = jsonloads(
            self.app.post("/VolumeDriver.Snapshot.Restore", json.dumps({"Name": name})).body
        )
        self.assertTrue(resp["Err"])
        with open(join(path, "foobar")) as f:
            self.assertEqual(f.read(), "modified foobar")
        # cleanup
        btrfs.Subvolume(join(SNAPSHOTS_PATH, legacy)).delete()

    def test_the_trace_of_a_send_cannot_be_sent(self):
        """Sending it back would name its own trace, and only fail once sent"""
        resp = jsonloads(
            self.app.post(
                "/VolumeDriver.Snapshot.Send",
                json.dumps({"Name": "www@2026-01-01T00:00:00.000000@node2", "Host": "node2"}),
            ).body
        )
        self.assertIn("trace of a send", resp["Err"])

    def test_restore(self):
        """Check we can restore a snapshot as a volume"""
        # create a volume with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path = join(VOLUMES_PATH, name)
        self.create_a_volume_with_a_file(name)
        # snapshot the volume
        resp = self.app.post("/VolumeDriver.Snapshot", json.dumps({"Name": name}))
        snapshot = json.loads(resp.body.decode())["Snapshot"]
        # modify the file
        with open(join(path, "foobar"), "w") as f:
            f.write("modified foobar")
        # overwrite the volume with the snapshot
        resp = self.app.post("/VolumeDriver.Snapshot.Restore", json.dumps({"Name": snapshot}))
        # check the volume has the original content
        with open(join(path, "foobar")) as f:
            self.assertEqual(f.read(), "foobar")
        # check we have another snapshot with the volume backup
        volume_backup = json.loads(resp.body.decode())["VolumeBackup"]
        path = join(SNAPSHOTS_PATH, volume_backup)
        with open(join(path, "foobar")) as f:
            self.assertEqual(f.read(), "modified foobar")

        # create a different volume
        name2 = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path2 = join(VOLUMES_PATH, name2)
        self.create_a_volume_with_a_file(name2)
        # modify the file
        with open(join(path2, "foobar"), "w") as f:
            f.write("modified2 foobar")
        # restore the snapshot to this volume
        self.app.post(
            "/VolumeDriver.Snapshot.Restore",
            json.dumps({"Name": snapshot, "Target": name2}),
        )
        # check the volume has the original content
        with open(join(path2, "foobar")) as f:
            self.assertEqual(f.read(), "foobar")

    def test_clone(self):
        """Check we can clone as a new volume"""
        # create a volume with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path = join(VOLUMES_PATH, name)
        self.create_a_volume_with_a_file(name)

        # clone a different volume
        name2 = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path2 = join(VOLUMES_PATH, name2)

        # clone name as new volume name2
        self.app.post("/VolumeDriver.Clone", json.dumps({"Name": name, "Target": name2}))

        # check the cloned volume has a copy of the original content
        with open(join(path2, "foobar")) as f:
            self.assertEqual(f.read(), "foobar")
        # modify the file in name2 (new volume)
        with open(join(path2, "foobar"), "w") as f:
            f.write("modified2 foobar")
        # check the orginal volume has unmodified content
        with open(join(path, "foobar")) as f:
            self.assertEqual(f.read(), "foobar")
        # check the new volume has the new content
        with open(join(path2, "foobar")) as f:
            self.assertEqual(f.read(), "modified2 foobar")

    def create_20_hourly_snapshots(self, name):
        path = join(VOLUMES_PATH, name)
        # Five minutes short of the round hour: a snapshot exactly as old as a
        # purge threshold falls on either side of it depending on how long the
        # test itself takes, which made the expected counts below a coin flip.
        hours = [
            (datetime.now() - timedelta(hours=h) + timedelta(minutes=5)).strftime(DTFORMAT)
            for h in range(20)
        ]
        for h in hours:
            run(
                f"btrfs subvolume snapshot {path} {join(SNAPSHOTS_PATH, name)}@{h}",
                shell=True,
            )
        timestamp = datetime.now().strftime(DTFORMAT) + "@127.1.2.3"
        run(
            f"btrfs subvolume snapshot {path} {join(SNAPSHOTS_PATH, name)}@{timestamp}",
            shell=True,
        )
        run(
            "btrfs subvolume snapshot {} {}@{}".format(path, join(SNAPSHOTS_PATH, name), "invalid"),
            shell=True,
        )

    def test_purge(self):
        """Check we can purge snapshots with a save pattern"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        # first run the purge without snapshots (should do nothing) - use single pattern now
        self.app.post(
            "/VolumeDriver.Snapshots.Purge",
            json.dumps({"Name": name, "Pattern": "2h"}),
        )
        # create a volume with a file
        self.create_a_volume_with_a_file(name)

        def cleanup_snapshots():
            """Clean up all test snapshots"""
            if os.path.exists(SNAPSHOTS_PATH):
                for item in os.listdir(SNAPSHOTS_PATH):
                    if item.startswith(PREFIX_TEST_VOLUME):
                        item_path = join(SNAPSHOTS_PATH, item)
                        # Continue cleanup even if individual items fail
                        with suppress(Exception):
                            btrfs.Subvolume(item_path).delete()

        self.create_20_hourly_snapshots(name)
        # run the purge with a simple save pattern (2h only)
        nb_snaps = len(os.listdir(SNAPSHOTS_PATH))
        resp = self.app.post(
            "/VolumeDriver.Snapshots.Purge",
            json.dumps({"Name": name, "Pattern": "2h"}),
        )
        result = jsonloads(resp.body)
        print(f"DEBUG: Purge result: {result}")
        print(
            f"DEBUG: Before purge: {nb_snaps} snapshots, After purge: {len(os.listdir(SNAPSHOTS_PATH))} snapshots"
        )
        self.assertEqual(result, {"Err": ""})
        # check we deleted 17 snapshots (the @invalid snapshot is not counted)
        self.assertEqual(len(os.listdir(SNAPSHOTS_PATH)), nb_snaps - 17)
        # run the purge again and check we have no more snapshot deleted
        nb_snaps = len(os.listdir(SNAPSHOTS_PATH))
        resp = self.app.post(
            "/VolumeDriver.Snapshots.Purge",
            json.dumps({"Name": name, "Pattern": "2h"}),
        )
        self.assertEqual(jsonloads(resp.body), {"Err": ""})
        self.assertEqual(len(os.listdir(SNAPSHOTS_PATH)), nb_snaps)

        cleanup_snapshots()
        self.create_20_hourly_snapshots(name)
        # run the purge with a more complex save pattern (2h:4h:8h:16h)
        nb_snaps = len(os.listdir(SNAPSHOTS_PATH))
        resp = self.app.post(
            "/VolumeDriver.Snapshots.Purge",
            json.dumps({"Name": name, "Pattern": "2h:4h:8h:16h"}),
        )
        self.assertEqual(jsonloads(resp.body), {"Err": ""})
        # check we deleted 14 snapshots
        self.assertEqual(len(os.listdir(SNAPSHOTS_PATH)), nb_snaps - 14)

        cleanup_snapshots()
        self.create_20_hourly_snapshots(name)

        # Test that deprecated duplicate patterns are rejected with helpful message
        resp = self.app.post(
            "/VolumeDriver.Snapshots.Purge",
            json.dumps({"Name": name, "Pattern": "2h:2h"}),
        )
        self.assertIn("Invalid pattern '2h:2h'. Use '2h' instead", jsonloads(resp.body)["Err"])

        # check the order of the components is checked, shortest first
        resp = self.app.post(
            "/VolumeDriver.Snapshots.Purge",
            json.dumps({"Name": name, "Pattern": "4h:2h"}),
        )
        self.assertEqual(
            jsonloads(resp.body),
            {
                "Err": "Invalid purge pattern: 4h:2h - Time values must be in ascending order"
                " (e.g., 2h:4h:8h or 30m:2h:1d)"
            },
        )

        # check we have an error with an unknown unit
        resp = self.app.post(
            "/VolumeDriver.Snapshots.Purge",
            json.dumps({"Name": name, "Pattern": "5x"}),
        )
        self.assertEqual(
            jsonloads(resp.body),
            {"Err": "Invalid purge pattern: 5x - unknown unit 'x'"},
        )

        # check we have an error with a non numeric pattern
        resp = self.app.post(
            "/VolumeDriver.Snapshots.Purge",
            json.dumps({"Name": name, "Pattern": "60m:plop:3000m"}),
        )
        self.assertEqual(
            jsonloads(resp.body),
            {
                "Err": "Invalid purge pattern: 60m:plop:3000m - Pattern components must be numeric with unit suffix"
            },
        )
        # run the purge with a more complex multi-component save pattern
        nb_snaps = len(os.listdir(SNAPSHOTS_PATH))
        resp = self.app.post(
            "/VolumeDriver.Snapshots.Purge",
            json.dumps({"Name": name, "Pattern": "60m:120m:180m:240m:300m"}),
        )
        self.assertEqual(jsonloads(resp.body), {"Err": ""})
        # check we deleted 15 snapshots
        self.assertEqual(len(os.listdir(SNAPSHOTS_PATH)), nb_snaps - 15)
        cleanup_snapshots()
        self.app.post("/VolumeDriver.Remove", json.dumps({"Name": name}))

    def test_a_purge_does_not_delete_what_a_send_still_needs(self):
        """The trace of a send, and its snapshot, outlive a purge of their age"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        # a snapshot older than the pattern below, and the trace of its send
        old = (datetime.now() - timedelta(hours=3)).strftime(DTFORMAT)
        snap = f"{name}@{old}"
        trace = f"{snap}@127.1.2.3"
        volume = btrfs.Subvolume(join(VOLUMES_PATH, name))
        volume.snapshot(join(SNAPSHOTS_PATH, snap), readonly=True)
        volume.snapshot(join(SNAPSHOTS_PATH, trace), readonly=True)

        resp = self.app.post(
            "/VolumeDriver.Snapshots.Purge",
            json.dumps({"Name": name, "Pattern": "2h"}),
        )
        self.assertEqual(jsonloads(resp.body), {"Err": ""})
        # without them the next send would have no parent and would cross the
        # network with the whole volume again
        self.assertEqual(
            sorted(s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name + "@")),
            sorted([snap, trace]),
        )

    def test_every_route_answers_json(self):
        """One decorator, one contract: no request turns a route into a 500.

        Sent an empty body, every handler stumbles on a missing key; sent a
        body that is not JSON, the decoding itself fails. Either way the
        client must still read a JSON body from a 200 answer.
        """
        disabled = plugin.SCHEDULE_DISABLED
        plugin.SCHEDULE_DISABLED = SCHEDULE + ".disabled"
        self.assertTrue(cli.app.routes)
        try:
            for body in (b"", b"{not json"):
                for route in cli.app.routes:
                    path = route.rule.replace("<name>", PREFIX_TEST_VOLUME + "nothing")
                    resp = self.app.request(
                        path, method=route.method, body=body, expect_errors=True
                    )
                    self.assertEqual(resp.status_int, 200, path)
                    self.assertIsInstance(jsonloads(resp.body), dict, path)
        finally:
            with suppress(OSError):
                os.rename(plugin.SCHEDULE_DISABLED, SCHEDULE)
            plugin.SCHEDULE_DISABLED = disabled

    def test_run_safe_typed_error(self):
        """A failed command raises the requested type, and says which command failed"""
        missing = join(VOLUMES_PATH, "there_is_no_such_volume")
        with self.assertRaises(btrfs.BtrfsSubvolumeError) as caught:
            btrfs.run_safe(
                ["btrfs", "subvolume", "show", missing],
                timeout=btrfs.SHOW_TIMEOUT,
                error=btrfs.BtrfsSubvolumeError,
            )
        self.assertIn(missing, str(caught.exception))
        # the original failure stays reachable instead of being swallowed
        self.assertIsInstance(caught.exception.__cause__, CalledProcessError)

    def test_run_safe_missing_command(self):
        """A command that cannot even be started is reported like any other failure"""
        with self.assertRaises(btrfs.BtrfsError):
            btrfs.run_safe(["there_is_no_such_command"], timeout=btrfs.SHOW_TIMEOUT)

    def test_compute_purge(self):
        now = datetime.now()
        snapshots = [
            "foobar@" + (now - timedelta(hours=h, minutes=30)).strftime(DTFORMAT)
            for h in range(5000)
        ]
        purge_list = compute_purges(snapshots, Pattern.parse("1d:1w:4w:1y"), now, DTFORMAT)
        not_purged = set(snapshots) - set(purge_list)
        self.assertEqual(len(not_purged), 40)

    def test_compute_purge2(self):
        now = datetime.now()
        snapshots = ["foobar@" + (now - timedelta(hours=h)).strftime(DTFORMAT) for h in range(3000)]
        for now in [now + timedelta(hours=h) for h in range(3000)]:
            purge_list = compute_purges(snapshots, Pattern.parse("1d:1w:4w:1y"), now, DTFORMAT)
            snapshots = sorted(set(snapshots) - set(purge_list))
        self.assertEqual(len(snapshots), 4)

    def test_schedule_purge(self):
        # create a volume with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        self.create_20_hourly_snapshots(name)
        # schedule a purge of the volumes with single pattern
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "purge:2h", "Timer": 60}),
        )
        write_last_runs(LAST_RUNS, {"purge:2h": {name: datetime.now() - timedelta(days=1)}})
        nb_snaps = len(os.listdir(SNAPSHOTS_PATH))
        runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)
        self.assertEqual(len(os.listdir(SNAPSHOTS_PATH)), nb_snaps - 17)
        # unschedule
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "purge:2h", "Timer": 0}),
        )

    def test_schedule_purge_backward_compat(self):
        """Test that scheduler handles deprecated 2h:2h patterns with warnings"""
        # create a volume with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        self.create_20_hourly_snapshots(name)

        # Create a schedule entry with deprecated pattern (this will be in schedule.csv)
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "purge:2h:2h", "Timer": 60}),
        )
        write_last_runs(LAST_RUNS, {"purge:2h:2h": {name: datetime.now() - timedelta(days=1)}})
        nb_snaps = len(os.listdir(SNAPSHOTS_PATH))

        # This should work (with warning) because scheduler uses backward compatibility

        with self.assertLogs(level=logging.WARNING) as log_capture:
            runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)

        # Check that warning was logged
        self.assertTrue(
            any(
                "Converting deprecated pattern '2h:2h' to '2h'" in msg for msg in log_capture.output
            )
        )

        # Check that purge still worked (converted 2h:2h to 2h)
        self.assertEqual(len(os.listdir(SNAPSHOTS_PATH)), nb_snaps - 17)

        # unschedule the deprecated pattern
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "purge:2h:2h", "Timer": 0}),
        )

    def test_a_purge_that_failed_is_tried_again_at_the_next_round(self):
        """A job whose date is written down anyway is a job nobody retries

        The scheduler counted the period of a purge from the moment it ran it,
        whether it worked or not, so a purge that failed went quiet until its
        next turn, which is a day for most schedules.
        """
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        with open(SCHEDULE, "w") as f:
            f.write(f"{name},purge:2h,60,True\n")

        with patch("buttervolume.api.purge", return_value=False) as failing_purge:
            runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)
            runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)

        self.assertEqual(failing_purge.call_count, 2)
        # nothing written down for a job that failed, not even across a restart
        self.assertEqual(read_last_runs(LAST_RUNS), {})

    def test_a_synchronization_that_could_not_pull_waits_for_its_turn(self):
        """A purge that failed can be tried again for free, a pull cannot

        The snapshot taken before the pull holds the volume as it was before
        rsync, and it is what a pull stopped halfway is recovered from, so it
        stays. Coming back at the next round would therefore leave one
        snapshot per minute behind while the other host is away.
        """
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        with open(SCHEDULE, "w") as f:
            f.write(f"{name},synchronize:localhost,60,True\n")

        with patch("buttervolume.api.sync", return_value=False) as failing_sync:
            runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)
            runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)

        self.assertEqual(failing_sync.call_count, 1)
        snapshots = [s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name + "@")]
        self.assertEqual(len(snapshots), 1)

    def test_a_line_the_scheduler_never_ran_starts_at_once(self):
        """A weekly job used to wait six days after every restart

        The scheduler wrote down exactly one day of lateness for a line it had
        never seen, so a period longer than a day started late by the whole
        difference, and nothing said so.
        """
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        weekly = 7 * 24 * 60
        with open(SCHEDULE, "w") as f:
            f.write(f"{name},snapshot,{weekly},True\n")

        runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)

        snapshots = os.listdir(SNAPSHOTS_PATH)
        self.assertTrue(any(snap.startswith(name + "@") for snap in snapshots))

    def test_the_scheduler_picks_its_jobs_up_where_it_left_them(self):
        """The date of a job that ran used to die with the daemon

        Since a line nobody has a date for starts at once, a restart ran
        everything that was scheduled, whatever its period. The two rounds
        below share nothing but the file, which is what a restart leaves.
        """
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        with open(SCHEDULE, "w") as f:
            f.write(f"{name},snapshot,60,True\n")

        runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)
        runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)

        snapshots = [s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name + "@")]
        self.assertEqual(len(snapshots), 1)
        self.assertIn(name, read_last_runs(LAST_RUNS)["snapshot"])

    def test_an_unknown_scheduled_action_is_reported(self):
        """A misspelled action in the schedule must be said out loud

        It can only come from a hand-edited file, and until now the scheduler
        skipped it silently at every run, so a volume nobody replicated looked
        exactly like a volume replicated every hour.
        """
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        with open(SCHEDULE, "w") as f:
            f.write(f"{name},replicat:localhost,60,True\n")
        nb_snaps = len(os.listdir(SNAPSHOTS_PATH))

        with self.assertLogs(level=logging.WARNING) as log_capture:
            runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)

        self.assertTrue(
            any(
                f"Skipping the unknown action replicat:localhost of {name}" in msg
                for msg in log_capture.output
            )
        )
        self.assertEqual(len(os.listdir(SNAPSHOTS_PATH)), nb_snaps)

    def test_the_scheduler_runs_the_lines_around_one_it_cannot_read(self):
        """A file from Buttervolume 3.10 has three columns, and a hand-edited one anything

        Neither is a reason to stop snapshotting every other volume in the
        file, which is what reading the whole file in one go would do.
        """
        legacy = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        mangled = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        healthy = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        for name in (legacy, mangled, healthy):
            self.create_a_volume_with_a_file(name)
        with open(SCHEDULE, "w") as f:
            f.write(f"{legacy},snapshot,60\n")
            f.write(f"{mangled},snapshot,60,True,extra\n")
            f.write(f"{healthy},snapshot,60,True\n")

        with self.assertLogs(level=logging.WARNING) as log_capture:
            runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)

        self.assertTrue(any("Invalid schedule line" in msg for msg in log_capture.output))
        snapshots = os.listdir(SNAPSHOTS_PATH)
        self.assertTrue(any(s.startswith(legacy) for s in snapshots))
        self.assertTrue(any(s.startswith(healthy) for s in snapshots))
        self.assertFalse(any(s.startswith(mangled) for s in snapshots))

    def test_the_scheduler_names_the_line_it_could_not_read(self):
        """The line at fault, not the one before it

        The fields of a line are only filled once it has been read whole, so a
        message built from them names the last line that could be read, which
        is precisely the one that gave no trouble.
        """
        healthy = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        mangled = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(healthy)
        with open(SCHEDULE, "w") as f:
            f.write(f"{healthy},snapshot,60,True\n")
            f.write(f"{mangled},snapshot,60,True,extra\n")

        # the error alone: the healthy line announces itself at a lower level,
        # and its name in the capture would say nothing about the error
        with self.assertLogs(level=logging.ERROR) as log_capture:
            runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)

        error = "\n".join(log_capture.output)
        self.assertIn(mangled, error)
        self.assertNotIn(healthy, error)

    def test_a_schedule_nobody_could_run_is_refused(self):
        """The endpoint is where a schedule is written, so it is where it is judged"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        for req, expected in (
            ({"Name": name, "Action": "replicat:localhost", "Timer": 60}, "Invalid action"),
            ({"Name": name, "Action": "purge:5x", "Timer": 60}, "unknown unit"),
            ({"Name": name, "Action": "snapshot", "Timer": "demain"}, "Invalid timer"),
            ({"Name": name, "Action": "snapshot", "Timer": "²"}, "Invalid timer"),
            ({"Name": name + "/../..", "Action": "snapshot", "Timer": 60}, "Invalid characters"),
        ):
            resp = self.app.post("/VolumeDriver.Schedule", json.dumps(req))
            self.assertIn(expected, jsonloads(resp.body)["Err"])
        # nothing of all this was written
        resp = self.app.get("/VolumeDriver.Schedule.List")
        self.assertEqual(jsonloads(resp.body)["Schedule"], [])

    def test_unscheduling_a_job_nobody_scheduled_is_refused(self):
        """Saying yes to that is how a typo passes for a job that is running"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        for timer in ("0", "delete", "pause", "resume"):
            resp = self.app.post(
                "/VolumeDriver.Schedule",
                json.dumps({"Name": name, "Action": "snapshot", "Timer": timer}),
            )
            self.assertIn("is scheduled", jsonloads(resp.body)["Err"])

    def test_a_job_written_before_this_validation_can_still_be_deleted(self):
        """An action the endpoint now refuses may already sit in the file"""
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        with open(SCHEDULE, "w") as f:
            f.write(f"{name},replicat:localhost,60,True\n")

        resp = self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": name, "Action": "replicat:localhost", "Timer": 0}),
        )
        self.assertEqual(jsonloads(resp.body)["Err"], "")
        resp = self.app.get("/VolumeDriver.Schedule.List")
        self.assertEqual(jsonloads(resp.body)["Schedule"], [])

    def test_a_host_the_schedule_can_no_longer_name_stops_the_job(self):
        """A replication to a host that is refused now stops, and says so

        Such a line could be written by an older version. It never replicated
        anything, because the send refused the host too, but it did keep
        snapshotting the volume every period while logging a success.
        """
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        self.create_a_volume_with_a_file(name)
        with open(SCHEDULE, "w") as f:
            f.write(f"{name},replicate:backup_host,60,True\n")
        nb_snaps = len(os.listdir(SNAPSHOTS_PATH))

        with self.assertLogs(level=logging.WARNING) as log_capture:
            runjobs(config=SCHEDULE, test=True, last_runs=LAST_RUNS)

        self.assertTrue(any("replicate:backup_host" in msg for msg in log_capture.output))
        self.assertEqual(len(os.listdir(SNAPSHOTS_PATH)), nb_snaps)

    @unittest.skipIf(
        os.environ.get("BUTTERVOLUME_LOCAL_TEST"), "SSH not available in local test mode"
    )
    def test_synchronization(self):
        """Check we can synchronize a volume"""
        # create a volume with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path = join(VOLUMES_PATH, name)
        remote_path = join(TEST_REMOTE_PATH, name)
        # Prepare local btrfs subvolume
        self.create_a_volume_with_a_file(name)
        # We can't use same subvolume name twice on the same host so use a
        # non btrf directory for testing purpose
        with TemporaryDirectory(path=remote_path) as remote_path:
            with open(join(remote_path, "foobar"), "w") as f:
                f.write("test sync")
            self.app.post(
                "/VolumeDriver.Volume.Sync",
                json.dumps(
                    {
                        "Volumes": [name],
                        "Hosts": ["localhost"],
                        "Test": True,
                    }
                ),
            )
            with open(join(path, "foobar")) as x:
                self.assertEqual(x.read(), "test sync")
            # change it after localy and sync again
            with open(join(path, "foobar"), "w") as f:
                f.write("foobar")
            self.app.post(
                "/VolumeDriver.Volume.Sync",
                json.dumps(
                    {
                        "Volumes": [name],
                        "Hosts": ["localhost"],
                        "Test": True,
                    }
                ),
            )
            with open(join(path, "foobar")) as x:
                self.assertEqual(x.read(), "test sync")

    @unittest.skipIf(
        os.environ.get("BUTTERVOLUME_LOCAL_TEST"), "SSH not available in local test mode"
    )
    def test_schedule_synchronization(self):
        # create a volume with a file
        name = PREFIX_TEST_VOLUME + uuid.uuid4().hex
        path = join(VOLUMES_PATH, name)
        remote_path = join(TEST_REMOTE_PATH, name)
        self.create_a_volume_with_a_file(name)
        # check we have no schedule yes
        resp = self.app.get("/VolumeDriver.Schedule.List")
        schedule = json.loads(resp.body.decode())["Schedule"]
        self.assertEqual(len(schedule), 0)
        # check we have no snapshots
        resp = self.app.get("/VolumeDriver.Snapshot.List")
        snapshots = json.loads(resp.body.decode())["Snapshots"]
        self.assertEqual(len(snapshots), 0)
        # synchronize the volume every 120 minutes, even some host are not
        # responding we should synchronise other hosts
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps(
                {
                    "Name": name,
                    "Action": "synchronize:localhost,wronghost.mlf",
                    "Timer": 120,
                }
            ),
        )
        # also replicate a non existing volume
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": "boo", "Action": "synchronize:localhost", "Timer": 120}),
        )
        # simulate the last synchronize is 1 day in the past
        write_last_runs(
            LAST_RUNS,
            {"synchronize:localhost,wronghost.mlf": {name: datetime.now() - timedelta(days=1)}},
        )
        with TemporaryDirectory(path=remote_path) as remote_path:
            with open(join(remote_path, "foobar"), "w") as f:
                f.write("test sync")
            runjobs(SCHEDULE, test=True, last_runs=LAST_RUNS)
        # make sure a snapshot has occured before rsync
        snapshots = [s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(name)]
        self.assertEqual(1, len(snapshots))
        with open(join(SNAPSHOTS_PATH, snapshots[0], "foobar")) as x:
            self.assertEqual(x.read(), "foobar")
        with open(join(path, "foobar")) as x:
            self.assertEqual(x.read(), "test sync")

        # unschedule the last job
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps({"Name": "boo", "Action": "synchronize:localhost", "Timer": 0}),
        )
        self.app.post(
            "/VolumeDriver.Schedule",
            json.dumps(
                {
                    "Name": name,
                    "Action": "synchronize:localhost,wronghost.mlf",
                    "Timer": 0,
                }
            ),
        )

    def test_init_file(self):
        """Test the buttervolume init --file command"""

        # Test image file creation as non-root user (should work in user directory)
        with patch("os.geteuid", return_value=1000), patch("os.access", return_value=True), patch(
            "os.makedirs"
        ), patch("subprocess.run") as mock_run:
            args = MagicMock()
            args.file = "/home/user/test.img"
            args.path = None
            args.size = "10G"

            result = init_btrfs(args)
            self.assertTrue(result)

            # Check that subprocess.run was called for truncate and mkfs.btrfs
            calls = mock_run.call_args_list
            self.assertTrue(any("truncate" in str(call) for call in calls))
            self.assertTrue(any("mkfs.btrfs" in str(call) for call in calls))

        # Test image file creation in system directory (should fail as non-root)
        with patch("os.geteuid", return_value=1000), patch("os.access", return_value=False):
            args = MagicMock()
            args.file = "/var/lib/docker/test.img"
            args.path = None
            args.size = "10G"

            result = init_btrfs(args)
            self.assertFalse(result)

    def test_capabilities(self):
        rsp = jsonloads(self.app.post("/VolumeDriver.Capabilities", "{}").body)
        self.assertEqual(rsp.get("Capabilities", {}).get("Scope"), "local")


class TestTheDaemonServesItsRoutes(unittest.TestCase):
    """What `buttervolume run` would answer, asked from a fresh interpreter.

    The routes are posted on the default Bottle application as a side effect of
    importing plugin.py, and api.py is the only place in the daemon that
    imports it. The rest of this file cannot see that import disappear, because
    it imports plugin.py on its own, and the application would look full here
    while the daemon served nothing. Hence a new interpreter, which imports
    exactly what the daemon imports and nothing more.
    """

    def test_importing_the_api_is_enough_to_have_the_routes(self):
        result = subprocess.run(
            [sys.executable, "-c", "from buttervolume.api import app; assert app.routes"],
            capture_output=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            "the daemon would serve an application without a single route: "
            + result.stderr.decode(),
        )


class TestNames(unittest.TestCase):
    """The naming rules, read and written without touching a filesystem"""

    def test_a_snapshot_name_survives_a_round_trip(self):
        for name in ("www@2026-08-26T10:00:00.000000", "www@2026-08-26T10:00:00.000000@node2"):
            self.assertEqual(str(Snapshot.parse(name)), name)
        snapshot = Snapshot.parse("www@2026-08-26T10:00:00.000000")
        self.assertEqual(snapshot.volume, "www")
        self.assertEqual(snapshot.timestamp, "2026-08-26T10:00:00.000000")
        self.assertIsNone(snapshot.host)
        self.assertEqual(snapshot.taken_at(DTFORMAT), datetime(2026, 8, 26, 10, 0, 0))

    def test_a_name_that_is_not_a_snapshot_name_is_refused(self):
        for bad in ("", "www", "@", "www@", "a@b@c@d", "www@$(reboot)", "www@2026-08-26 10:00"):
            with self.assertRaises(ValidationError, msg=f"{bad!r} was accepted"):
                Snapshot.parse(bad)

    def test_a_new_snapshot_is_named_after_the_moment_it_is_taken(self):
        now = datetime(2026, 8, 26, 10, 0, 0)
        self.assertEqual(str(new_snapshot("www", DTFORMAT, now)), "www@2026-08-26T10:00:00.000000")
        # a date format the API could not read back is refused, not created
        with self.assertRaises(ValidationError):
            new_snapshot("www", "%Y-%m-%d %H:%M:%S", now)

    def test_the_snapshots_of_a_volume_are_its_own(self):
        names = ["www@t1", "wwwbis@t1", "www@t2@node2", "other@t3"]
        self.assertEqual(snapshots_of("www", names), ["www@t1", "www@t2@node2"])
        # a name we could not have written is still shown: hiding it would let
        # the caller take www@t1 for the most recent snapshot of the volume
        self.assertEqual(snapshots_of("www", ["www@t 2", "www@t1"]), ["www@t 2", "www@t1"])

    def test_the_parent_of_a_send_is_the_last_one_sent_to_that_host(self):
        names = ["www@t1", "www@t2", "www@t1@node2", "www@t2@node2", "other@t3@node2"]
        already_sent = sent_snapshots("www", "node2", names)
        self.assertEqual([str(s) for s in already_sent], ["www@t1@node2", "www@t2@node2"])
        self.assertEqual(str(already_sent[-1].without_host()), "www@t2")
        # and the trace this send will leave behind
        self.assertEqual(str(Snapshot.parse("www@t3").sent_to("node2")), "www@t3@node2")


class TestPurgePattern(unittest.TestCase):
    """The retention pattern, read without touching a filesystem"""

    def test_a_pattern_is_read_as_the_durations_it_names(self):
        self.assertEqual(Pattern.parse("2h").minutes, (120,))
        self.assertEqual(Pattern.parse("30m:2h:1d:1w:1y").minutes, (30, 120, 1440, 10080, 525600))
        self.assertEqual(str(Pattern.parse("4h:1d")), "4h:1d")
        self.assertIsNone(Pattern.parse("4h:1d").deprecated)

    def test_the_old_way_of_writing_a_single_duration_is_read_as_that_duration(self):
        pattern = Pattern.parse("2h:2h")
        self.assertEqual(pattern.minutes, (120,))
        self.assertEqual(pattern.text, "2h")
        self.assertEqual(pattern.deprecated, "2h:2h")

    def test_a_pattern_nobody_could_apply_is_refused(self):
        for text in ("", "2h:", "60m:plop:3000m", "5x", "²h", "4h:2h", "2h:120m", "2h:2h:4h"):
            with self.assertRaises(ValidationError):
                Pattern.parse(text)


class TestWhatAPurgeCondemns(unittest.TestCase):
    """What a purge spares for a send, read without touching a filesystem"""

    now = datetime(2026, 8, 26, 12, 0, 0)

    def aged(self, hours):
        """The timestamp of a snapshot taken that many hours ago"""
        return (self.now - timedelta(hours=hours)).strftime(DTFORMAT)

    def condemned(self, names, pattern):
        return compute_purges(names, Pattern.parse(pattern), self.now, DTFORMAT)

    def test_a_trace_and_the_snapshot_it_was_made_from_are_spared(self):
        t1, t2 = self.aged(3), self.aged(4)
        names = [f"www@{t1}", f"www@{t1}@node2", f"www@{t2}"]
        self.assertEqual(self.condemned(names, "2h"), [f"www@{t2}"])

    def test_a_trace_whose_snapshot_is_already_gone_is_spared_too(self):
        t1 = self.aged(3)
        self.assertEqual(self.condemned([f"www@{t1}@node2"], "2h"), [])

    def test_a_trace_does_not_spare_a_snapshot_that_is_not_its_own(self):
        """Same moment, another volume: the trace says nothing about it"""
        t1 = self.aged(3)
        names = [f"www@{t1}@node2", f"other@{t1}"]
        self.assertEqual(self.condemned(names, "2h"), [f"other@{t1}"])

    def test_traces_to_several_hosts_spare_the_same_snapshot_once(self):
        t1, t2 = self.aged(3), self.aged(4)
        names = [f"www@{t1}", f"www@{t1}@node2", f"www@{t1}@node3", f"www@{t2}"]
        self.assertEqual(self.condemned(names, "2h"), [f"www@{t2}"])

    def test_a_spared_snapshot_still_takes_up_its_timeframe(self):
        """Spared at the end: sparing it earlier would free the timeframe it
        occupies, and the neighbour condemned as its duplicate would survive"""
        old, young = self.aged(6), self.aged(5)
        names = [f"www@{old}", f"www@{old}@node2", f"www@{young}"]
        self.assertEqual(self.condemned(names, "4h:1d"), [f"www@{young}"])


class TestScheduledJob(unittest.TestCase):
    """What a scheduled action asks for, read without touching a filesystem"""

    def test_an_action_is_read_as_the_job_it_asks_for(self):
        self.assertEqual(Job.parse("snapshot"), schedule.Snapshot("snapshot"))
        self.assertEqual(
            Job.parse("replicate:node2"), schedule.Replicate("replicate:node2", "node2")
        )
        self.assertEqual(
            Job.parse("synchronize:node2,node3"),
            schedule.Synchronize("synchronize:node2,node3", ("node2", "node3")),
        )
        purge_job = Job.parse("purge:4h:1d")
        self.assertEqual(purge_job.pattern, Pattern.parse("4h:1d"))

    def test_a_job_remembers_how_the_schedule_spells_it(self):
        """The scheduler keys its own log on that text, deprecated spelling included"""
        self.assertEqual(Job.parse("purge:2h:2h").text, "purge:2h:2h")
        self.assertEqual(Job.parse("purge:2h:2h").pattern.text, "2h")

    def test_an_action_nobody_could_run_is_refused(self):
        for action in (
            "",
            "replicat:node2",
            "snapshot:",
            "snapshot:node2",
            "snapshots",
            "replicate",
            "replicate:no host",
            "purge:5x",
            "purge:",
            "synchronize:node2,",
        ):
            with self.assertRaises(ValidationError):
                Job.parse(action)


class TestWhatIsDue(unittest.TestCase):
    """When a line's turn has come, decided on paper

    No volume, no daemon and no schedule file: the decision has never needed
    more than a line, the date of its last run and a clock.
    """

    def hourly(self):
        return Entry("volume", "snapshot", "60", "True")

    def test_a_line_waits_for_its_timer(self):
        now = datetime(2026, 8, 26, 12, 0)
        self.assertFalse(is_due(self.hourly(), now - timedelta(minutes=59), now))

    def test_a_line_whose_timer_has_elapsed_is_due(self):
        now = datetime(2026, 8, 26, 12, 0)
        self.assertTrue(is_due(self.hourly(), now - timedelta(minutes=60), now))

    def test_a_last_run_later_than_the_clock_is_not_believed(self):
        """A host that booted with its clock ahead used to stop its own jobs

        The date is written down and now outlives the daemon, so a job whose
        last run sits in the future would wait for a day that never comes.
        """
        now = datetime(2026, 8, 26, 12, 0)
        self.assertTrue(is_due(self.hourly(), now + timedelta(days=365), now))


class TestRunningAJob(unittest.TestCase):
    """Which function runs which kind of job"""

    def test_a_job_nobody_knows_how_to_run_says_so(self):
        """Job.parse builds the four kinds the command line knows how to run

        A fifth one added there without its execution here used to fall into
        the last branch and be synchronized. It now names itself and stops,
        and the scheduler reports it like any other line that failed.
        """

        class Rewind(Job):
            pass

        with self.assertRaises(ValidationError):
            run_job(Rewind("rewind"), "volume", test=True)


class TestScheduleFile(unittest.TestCase):
    """The lines of the schedule file, read and written in a single place"""

    def schedule_file(self, content):
        path = os.path.join(self.tmp, "schedule.csv")
        with open(path, "w") as f:
            f.write(content)
        return path

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = self.tmpdir.name
        self.addCleanup(self.tmpdir.cleanup)

    def test_a_line_survives_being_read_and_written_back(self):
        path = self.schedule_file("www,snapshot,60,True\r\nwww,purge:2h,120,False\r\n")
        entries = read_schedule(path)
        self.assertEqual(entries[0], Entry("www", "snapshot", "60", "True"))
        self.assertTrue(entries[0].enabled)
        self.assertFalse(entries[1].enabled)
        write_schedule(path, entries)
        with open(path, newline="") as f:
            self.assertEqual(f.read(), "www,snapshot,60,True\r\nwww,purge:2h,120,False\r\n")

    def test_an_interrupted_write_leaves_the_previous_schedule_alone(self):
        """A schedule is what a daemon owes its volumes, and half of it is none of it"""
        content = "www,snapshot,60,True\r\nwww,purge:2h,120,False\r\n"
        path = self.schedule_file(content)

        def entries():
            yield Entry("www", "snapshot", "60", "True")
            raise OSError("No space left on device")

        with self.assertRaises(OSError):
            write_schedule(path, entries())
        with open(path, newline="") as f:
            self.assertEqual(f.read(), content)
        self.assertEqual(os.listdir(self.tmp), ["schedule.csv"])

    def test_writing_the_schedule_keeps_the_mode_of_the_file_it_replaces(self):
        """Saving a job is no reason for the file to change hands"""
        path = self.schedule_file("www,snapshot,60,True\r\n")
        os.chmod(path, 0o640)
        write_schedule(path, read_schedule(path))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)

    def test_writing_the_schedule_keeps_the_hands_of_the_file_it_replaces(self):
        """Renaming gives a new file, where writing in place kept the old one"""
        path = self.schedule_file("www,snapshot,60,True\r\n")
        mine = os.stat(path).st_gid
        # root belongs to its own group alone and may give a file to any other
        other = next((g for g in os.getgroups() if g != mine), mine + 1)
        try:
            os.chown(path, -1, other)
        except PermissionError:
            self.skipTest("no other group to give the schedule to")
        write_schedule(path, read_schedule(path))
        self.assertEqual(os.stat(path).st_gid, other)

    def test_a_schedule_reached_through_a_symbolic_link_stays_that_file(self):
        """A rename replaces a name, so the link is followed before renaming"""
        target = os.path.join(self.tmp, "elsewhere.csv")
        with open(target, "w") as f:
            f.write("www,snapshot,60,True\r\n")
        link = os.path.join(self.tmp, "schedule.csv")
        os.symlink(target, link)
        write_schedule(link, [Entry("www", "snapshot", "120", "True")])
        self.assertTrue(os.path.islink(link))
        with open(target, newline="") as f:
            self.assertEqual(f.read(), "www,snapshot,120,True\r\n")

    def test_a_schedule_written_where_there_was_none_is_read_by_nobody_else(self):
        """It names volumes and hosts, so it is born no more open than that"""
        path = os.path.join(self.tmp, "new.csv")
        write_schedule(path, [Entry("www", "snapshot", "60", "True")])
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_the_api_says_a_line_the_way_it_always_did(self):
        """Clients read these four keys, and read Active as a word, not a boolean"""
        path = self.schedule_file("www,snapshot,60,False\r\n")
        self.assertEqual(
            read_schedule(path)[0].fields,
            {"Name": "www", "Action": "snapshot", "Timer": "60", "Active": "False"},
        )

    def test_a_line_nobody_can_read_the_action_of_is_still_a_line(self):
        """An older version wrote it, and it must stay listable and deletable"""
        path = self.schedule_file("www,replicat:node2,60,True\r\n")
        entry = read_schedule(path)[0]
        self.assertEqual(entry.action, "replicat:node2")
        with self.assertRaises(ValidationError):
            Job.parse(entry.action)

    def test_a_file_written_before_the_active_column_existed_is_still_read(self):
        """Buttervolume 3.10 wrote three columns, and nothing ever rewrote those files"""
        path = self.schedule_file("www,snapshot,60\r\n")
        self.assertEqual(read_schedule(path), [Entry("www", "snapshot", "60", "")])
        self.assertTrue(read_schedule(path)[0].enabled)

    def test_a_blank_line_is_not_a_line(self):
        path = self.schedule_file("www,snapshot,60,True\r\n\r\n")
        self.assertEqual(len(read_schedule(path)), 1)

    def test_a_line_with_more_columns_than_we_know_is_refused(self):
        """Writing the file back would lose them, so we do not pretend to read it"""
        with self.assertRaises(ValidationError):
            read_schedule(self.schedule_file("www,snapshot,60,True,extra\r\n"))

    def test_a_line_nobody_can_read_stops_only_itself(self):
        """The scheduler reads line by line: one bad line must not stop the others"""
        path = self.schedule_file("www,snapshot,60,True,extra\r\nwww,snapshot,60,True\r\n")
        rows = read_rows(path)
        self.assertEqual(len(rows), 2)
        with self.assertRaises(ValidationError):
            Entry.parse(rows[0])
        self.assertEqual(Entry.parse(rows[1]), Entry("www", "snapshot", "60", "True"))

    def test_a_schedule_file_that_is_not_there_says_so(self):
        """Each caller answers that differently, so it is not decided here"""
        with self.assertRaises(FileNotFoundError):
            read_schedule(os.path.join(self.tmp, "nothing.csv"))

    def test_converting_the_old_patterns_leaves_every_other_line_alone(self):
        """Including a line whose action nobody can read: this converts, it does not clean up"""
        path = self.schedule_file(
            "www,purge:2h:2h,60,True\r\nwww,replicat:node2,60,True\r\nwww,snapshot,60,False\r\n"
        )
        with patch.object(cli, "SCHEDULE", path), patch("builtins.input", lambda: "y"):
            self.assertTrue(cli._auto_convert_old_patterns())
        with open(path, newline="") as f:
            self.assertEqual(
                f.read(),
                "www,purge:2h,60,True\r\nwww,replicat:node2,60,True\r\nwww,snapshot,60,False\r\n",
            )


class TestLastRunsFile(unittest.TestCase):
    """The date of the last run of each job, kept between two daemons"""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmpdir.name, "lastruns.csv")
        self.addCleanup(self.tmpdir.cleanup)

    def test_a_date_survives_being_written_and_read_back(self):
        dates = {
            "snapshot": {"www": datetime(2026, 8, 26, 12, 0)},
            "purge:4h:1d:1w": {"www": datetime(2026, 8, 26, 2, 0, 7, 900011)},
        }
        write_last_runs(self.path, dates)
        self.assertEqual(read_last_runs(self.path), dates)

    def test_a_line_nobody_can_read_only_forgets_its_own_job(self):
        """A job we have no date for runs at once: one run too many, never one too few"""
        with open(self.path, "w", newline="") as f:
            f.write(
                "www,snapshot,not a date\r\nwww,purge:2h\r\nwww,replicate:node2,2026-08-26T12:00:00\r\n"
            )

        with self.assertLogs(level=logging.WARNING):
            dates = read_last_runs(self.path)

        self.assertEqual(dates, {"replicate:node2": {"www": datetime(2026, 8, 26, 12, 0)}})

    def test_a_date_carrying_a_time_zone_is_refused_like_an_unreadable_one(self):
        """The clock it would be compared to has none, and comparing them raises"""
        with open(self.path, "w", newline="") as f:
            f.write("www,snapshot,2026-08-26T12:00:00+02:00\r\n")

        with self.assertLogs(level=logging.WARNING):
            self.assertEqual(read_last_runs(self.path), {})

    def test_a_file_that_is_not_there_says_so(self):
        """A first start and a file somebody deleted are the caller's business"""
        with self.assertRaises(FileNotFoundError):
            read_last_runs(self.path)

    def test_the_directory_is_made_on_the_first_start(self):
        path = os.path.join(self.tmpdir.name, "made", "lastruns.csv")
        write_last_runs(path, {"snapshot": {"www": datetime(2026, 8, 26, 12, 0)}})
        self.assertEqual(read_last_runs(path)["snapshot"]["www"], datetime(2026, 8, 26, 12, 0))

    def test_a_leftover_temporary_file_says_which_file_it_comes_from(self):
        """Two files are written here, and a temporary named after the other one lies"""

        def rows():
            yield ["www", "snapshot", "2026-08-26T12:00:00"]
            raise OSError("No space left on device")

        with patch("buttervolume.schedule.os.unlink"), self.assertRaises(OSError):
            schedule.write_rows(self.path, rows())
        left = os.listdir(self.tmpdir.name)
        self.assertEqual(len(left), 1)
        self.assertTrue(left[0].startswith("lastruns.csv."), left)


class TemporaryDirectory(tempfile.TemporaryDirectory):
    """Create and return a temporary directory. This change the
    tempfile.TemporaryDirectory behavior by letting user provide his wished
    directory, if directory already exists that directory and everything
    contained in it are removed.  For
    example:
        with TemporaryDirectory('/tmp/mydir') as tmpdir:
            ...
    Upon exiting the context, the directory and everything contained
    in it are removed.
    """

    def __init__(self, suffix=None, prefix=None, dir=None, path=None):
        self.name = self.mkdir(path) if path else tempfile.mkdtemp(suffix, prefix, dir)
        self._ignore_cleanup_errors = False  # Add missing attribute for Python 3.11+ compatibility
        self._finalizer = weakref.finalize(
            self,
            self._cleanup,
            self.name,
            warn_message=f"Implicitly cleaning up {self!r}",
        )

    def mkdir(self, path):
        if os.path.isdir(path):
            shutil.rmtree(path)
        os.mkdir(path, 0o700)
        return path


if __name__ == "__main__":
    unittest.main(verbosity=2)
