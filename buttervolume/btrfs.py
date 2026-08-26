"""The subvolume operations, and the guarded way to call the ``btrfs`` command.

Every call goes through ``run_safe``: no shell, a timeout each caller states
for itself, and any failure raised as a typed error rather than returned as
something the caller cannot tell apart from a result. One path escapes it and
needs the same care: ``run_btrfs_send_receive`` in ``plugin.py`` builds its own
send and receive to pipe them over SSH.

Nothing here knows what a volume is, which is why ``BtrfsError`` lives here
rather than with the errors the API answers with.
"""

import contextlib
import os
from subprocess import CalledProcessError, TimeoutExpired
from subprocess import run as _run

# How long each command may legitimately take, in seconds
SHOW_TIMEOUT = 15
SNAPSHOT_TIMEOUT = 120
CREATE_TIMEOUT = 120
DELETE_TIMEOUT = 300
CHATTR_TIMEOUT = 10
LABEL_TIMEOUT = 15


class BtrfsError(Exception):
    """Base exception for BTRFS operations"""


class BtrfsSubvolumeError(BtrfsError):
    """Raised when BTRFS subvolume operations fail"""


def run_safe(cmd, timeout, error=BtrfsError):
    """Run a command without a shell and turn any failure into a typed error.

    :param timeout: how long the command may run, in seconds. No default:
                    every caller states the delay it expects.
    :param error: the exception class raised on failure.
    :return: the standard output, decoded
    """
    try:
        return _run(
            cmd,
            shell=False,
            check=True,
            capture_output=True,
            timeout=timeout,
        ).stdout.decode()
    except CalledProcessError as e:
        stderr = e.stderr.decode() if e.stderr else "No error output"
        raise error(f"Command failed: {' '.join(cmd)}\nStderr: {stderr}") from e
    except TimeoutExpired as e:
        raise error(f"Command timed out after {timeout}s: {' '.join(cmd)}") from e
    except OSError as e:
        # The command could not even be started: missing binary, no permission
        raise error(f"Command could not be run: {' '.join(cmd)}\n{e}") from e


class Subvolume:
    """basic wrapper around the CLI"""

    def __init__(self, path):
        # Store absolute path - validation happens at the plugin layer
        self.path = os.path.abspath(path)

    def show(self):
        """Parse btrfs subvolume show output"""
        raw = run_safe(
            ["btrfs", "subvolume", "show", self.path],
            timeout=SHOW_TIMEOUT,
            error=BtrfsSubvolumeError,
        )
        lines = raw.split("\n")

        if len(lines) < 13:
            raise BtrfsSubvolumeError(
                f"Unexpected output format from 'btrfs subvolume show {self.path}'"
            )

        # Parse key-value pairs from lines 1-12
        output = {}
        for line in lines[1:12]:
            if ":" in line:
                k, v = line.split(":", 1)
                output[k.strip()] = v.strip()

        # Check for snapshots section
        if len(lines) > 12 and "Snapshot(s):" in lines[12]:
            output["Snapshot(s)"] = [s.strip() for s in lines[13:] if s.strip()]
        else:
            output["Snapshot(s)"] = []

        return output

    def exists(self):
        """Check if this path is a valid BTRFS subvolume"""
        if not os.path.isdir(self.path):
            return False
        try:
            self.show()
            return True
        except BtrfsError:
            return False

    def snapshot(self, target, readonly=False):
        """Create a snapshot of this subvolume"""
        cmd = ["btrfs", "subvolume", "snapshot"]
        if readonly:
            cmd.append("-r")
        cmd.extend([self.path, target])
        return run_safe(cmd, timeout=SNAPSHOT_TIMEOUT, error=BtrfsSubvolumeError)

    def create(self, cow=False):
        """Create a new BTRFS subvolume"""
        out = run_safe(
            ["btrfs", "subvolume", "create", self.path],
            timeout=CREATE_TIMEOUT,
            error=BtrfsSubvolumeError,
        )
        if not cow:
            with contextlib.suppress(BtrfsError):
                run_safe(["chattr", "+C", self.path], timeout=CHATTR_TIMEOUT)
                # chattr failure is not critical, subvolume was created successfully
        return out

    def delete(self):
        """Delete this BTRFS subvolume

        :return: btrfs output string
        """
        return run_safe(
            ["btrfs", "subvolume", "delete", self.path],
            timeout=DELETE_TIMEOUT,
            error=BtrfsSubvolumeError,
        )


class Filesystem:
    def __init__(self, path):
        self.path = path

    def label(self, label=None):
        cmd = ["btrfs", "filesystem", "label", self.path]
        if label is not None:
            cmd.append(label)
        return run_safe(cmd, timeout=LABEL_TIMEOUT)
