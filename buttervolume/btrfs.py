"""The subvolume operations, and the guarded way to call the ``btrfs`` command.

Every call goes through ``run_safe``: no shell, a timeout each caller states
for itself, and any failure raised as a typed error rather than returned as
something the caller cannot tell apart from a result. Two paths escape it and
need the same care, because they pipe a send into a receive: ``is_same_as``
below, and ``run_btrfs_send_receive`` in ``plugin.py``, which sends over SSH.

Nothing here knows what a volume is, which is why ``BtrfsError`` lives here
rather than with the errors the API answers with.

What ``btrfs subvolume show`` prints is read here too, for one subvolume or
for a whole directory of them, and read into ``Listed``: the name, the rank a
subvolume was created at, and whether it arrived through ``btrfs receive``.
That rank is how the plugin orders snapshots in time, because the date in a
snapshot's name is the clock of whichever host took it.
"""

import contextlib
import os
import tempfile
import time
from dataclasses import dataclass
from subprocess import PIPE, CalledProcessError, Popen, TimeoutExpired
from subprocess import run as _run

# How long each command may legitimately take, in seconds
SHOW_TIMEOUT = 15
SNAPSHOT_TIMEOUT = 120
CREATE_TIMEOUT = 120
DELETE_TIMEOUT = 300
CHATTR_TIMEOUT = 10
LABEL_TIMEOUT = 15
COMPARE_TIMEOUT = 60


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


# The fields ``btrfs subvolume show`` prints, one per line, before the list of
# snapshots. Reading them by name rather than by line number keeps a version
# that prints one more of them from shifting the others.
SHOW_FIELDS = frozenset(
    [
        "Name",
        "UUID",
        "Parent UUID",
        "Received UUID",
        "Creation time",
        "Subvolume ID",
        "Generation",
        "Gen at creation",
        "Parent ID",
        "Top level ID",
        "Flags",
        "Send transid",
        "Send time",
        "Receive transid",
        "Receive time",
        "Quota group",
    ]
)


def parse_shows(text):
    """The subvolumes described by this ``btrfs subvolume show`` output, one dict each.

    Pure: the output of one call, or of several concatenated, which is how a
    remote host describes a whole directory in a single command. Each
    description opens with the path of the subvolume, unindented, and goes on
    with indented ``Field: value`` lines. What follows ``Snapshot(s):`` is a
    list of paths, not fields, and is left out.
    """
    shown = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            shown.append({})
            continue
        field, _, value = line.strip().partition(":")
        if shown and field in SHOW_FIELDS:
            shown[-1][field] = value.strip()
    return shown


@dataclass(frozen=True)
class Listed:
    """A subvolume of a directory: its name, its rank, and whether it was received.

    The rank is the subvolume id, which a filesystem hands out in creation
    order, so it says in what order the subvolumes appeared there, whatever
    their names say. A subvolume that arrived through ``btrfs receive`` carries
    the id of the one it was sent from, and ``received`` says so; a writable
    snapshot made from it does not inherit that mark, nor do the snapshots
    taken from that writable one.
    """

    name: str
    rank: int
    received: bool


def parse_listing(text):
    """The subvolumes of a directory in creation order, read from their descriptions.

    Pure: ``text`` is what ``listing_command`` prints, the ``show`` of every
    subvolume of the directory. A description missing a field it should have
    raises rather than being skipped, because a listing that is read wrong is
    answered as a host holding less than it does.
    """
    listed = []
    for shown in parse_shows(text):
        try:
            listed.append(
                Listed(shown["Name"], int(shown["Subvolume ID"]), shown["Received UUID"] != "-")
            )
        except (KeyError, ValueError) as e:
            raise BtrfsError(f"Unreadable subvolume description {shown}: {e}") from e
    return sorted(listed, key=lambda s: s.rank)


def listing_command(directory):
    """The shell command that describes every subvolume of this directory.

    Meant to run on another host over ssh, which is why it is a shell string:
    ``cd`` fails when the directory is not there and the version check when
    ``btrfs`` is not, and either failure reaches the caller as a non-zero
    status, where an empty output only ever means a directory holding no
    subvolume. A directory that is not a subvolume prints nothing, which is
    what it is worth. The names never enter the command: the shell lists them
    itself.
    """
    return (
        f"cd {directory} && btrfs --version > /dev/null && "
        '{ for s in */; do btrfs subvolume show "${s%/}" 2> /dev/null; done; true; }'
    )


def subvolumes_in(directory):
    """The subvolumes of this directory, in the order they appeared there.

    A directory that is not a subvolume is left out, the way ``list_volumes``
    leaves it out of the volumes: it is not something ``btrfs`` made.
    """
    listed = []
    for name in os.listdir(directory):
        subvolume = Subvolume(os.path.join(directory, name))
        if not subvolume.exists():
            continue
        shown = subvolume.show()
        listed.append(Listed(name, int(shown["Subvolume ID"]), shown["Received UUID"] != "-"))
    return sorted(listed, key=lambda s: s.rank)


class Subvolume:
    """basic wrapper around the CLI"""

    def __init__(self, path):
        # Store absolute path - validation happens at the plugin layer
        self.path = os.path.abspath(path)

    def show(self):
        """What ``btrfs subvolume show`` says of this subvolume, as a dict."""
        raw = run_safe(
            ["btrfs", "subvolume", "show", self.path],
            timeout=SHOW_TIMEOUT,
            error=BtrfsSubvolumeError,
        )
        shown = parse_shows(raw)
        if len(shown) != 1:
            raise BtrfsSubvolumeError(
                f"Unexpected output format from 'btrfs subvolume show {self.path}'"
            )
        return shown[0]

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

    def is_same_as(self, other_path):
        """Does this snapshot hold nothing the one at other_path does not?

        Both are readonly subvolumes, which ``btrfs send`` requires, and
        ``other_path`` is the parent: the difference is what this one adds to
        it. An incremental stream carrying nothing but its ``snapshot``
        header, a single line under ``receive --dump``, says nothing changed.
        The lines are counted on the bytes and nothing is decoded: the dump
        prints the value of an extended attribute exactly as it is, so a
        volume holding a binary one would raise where it has to answer.

        Neither command goes through ``run_safe``: the send is piped into the
        dump, with the same four precautions as ``run_btrfs_send_receive``.
        The whole dump is read into memory rather than line by line;
        ``--no-data`` leaves the file contents out, but a volume where
        millions of files changed would still produce as many lines, and
        COMPARE_TIMEOUT is what bounds that. It also bounds the sync below,
        which the send of a snapshot just taken needs to see committed.
        """
        run_safe(["btrfs", "filesystem", "sync", self.path], timeout=COMPARE_TIMEOUT)
        send_cmd = ["btrfs", "send", "--no-data", "-p", other_path, self.path]
        # the send stderr goes to a temporary file rather than a pipe: nobody
        # can read that pipe while waiting for the dump side, and a verbose
        # failure would fill it and deadlock both processes
        with tempfile.TemporaryFile() as send_stderr_file:
            send_proc = Popen(send_cmd, stdout=PIPE, stderr=send_stderr_file)
            dump_proc = Popen(
                ["btrfs", "receive", "--dump"], stdin=send_proc.stdout, stdout=PIPE, stderr=PIPE
            )
            send_proc.stdout.close()  # so the send gets a SIGPIPE if the dump exits

            # one deadline for the two waits, so the comparison really is
            # bounded by COMPARE_TIMEOUT and not by twice that
            deadline = time.monotonic() + COMPARE_TIMEOUT
            try:
                dump, dump_stderr = dump_proc.communicate(timeout=COMPARE_TIMEOUT)
                send_proc.wait(timeout=max(0.0, deadline - time.monotonic()))
            except TimeoutExpired:
                # killed, then reaped: a daemon that lives for months has no
                # right to leave zombies behind
                send_proc.kill()
                dump_proc.kill()
                send_proc.wait()
                dump_proc.wait()
                send_stderr_file.seek(0)
                raise BtrfsError(
                    f"Comparing {self.path} to {other_path} timed out after "
                    f"{COMPARE_TIMEOUT}s: {send_stderr_file.read().decode(errors='replace')}"
                ) from None

            if send_proc.returncode != 0 or dump_proc.returncode != 0:
                send_stderr_file.seek(0)
                raise BtrfsError(
                    f"Could not compare {self.path} to {other_path} "
                    f"(send: {send_proc.returncode}, dump: {dump_proc.returncode}): "
                    f"{send_stderr_file.read().decode(errors='replace')} "
                    f"{dump_stderr.decode(errors='replace')}"
                )

        return len(dump.splitlines()) == 1

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
