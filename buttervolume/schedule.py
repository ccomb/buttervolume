"""What the schedule file says: its lines, and the job each one names.

A line of ``schedule.csv`` names its job in a single string: ``snapshot``,
``replicate:node2``, ``purge:4h:1d:1w``, ``synchronize:node2,node3``. Reading
that string is what ``Job.parse`` does, and it does it without touching the
disk: what a host is worth is decided in ``names.py``, what a retention
pattern says in ``purge.py``, and this module asks them.

A job keeps the action exactly as the schedule spells it, because that string
is how the scheduler remembers when the job last ran.

An action nobody could run leaves here as a ``ValidationError``, so no caller
has to decide what an unknown verb means. A line may well hold such an action:
an older version wrote it, and it must stay possible to list, to pause and to
delete. So an ``Entry`` is the line as written, four strings, and reading the
job out of it is a separate step nobody is forced to take.

``read_schedule`` and ``write_schedule`` are the only place where the CSV
format is known. They are thin: turning a row into an ``Entry`` is pure, only
the opening of the file is not. ``read_schedule`` says nothing about a file
that is not there, because its callers answer that differently and it is their
decision, not this module's. ``write_schedule`` replaces the file in one go,
because it is the only state the plugin keeps outside BTRFS and a half-written
schedule is a lost one.
"""

import csv
import os
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass

from buttervolume import ValidationError
from buttervolume.names import validate_hostname
from buttervolume.purge import Pattern

FIELDS = ["Name", "Action", "Timer", "Active"]


@dataclass(frozen=True)
class Job:
    """A scheduled job, and the action it was read from."""

    text: str

    @classmethod
    def parse(cls, action):
        verb, colon, rest = action.partition(":")
        # the colon, not the rest: "snapshot:" names no job either
        if verb == "snapshot" and not colon:
            return Snapshot(action)
        if verb == "replicate":
            return Replicate(action, validate_hostname(rest))
        if verb == "purge":
            return Purge(action, Pattern.parse(rest))
        if verb == "synchronize":
            return Synchronize(action, tuple(validate_hostname(h) for h in rest.split(",")))
        raise ValidationError(
            f"Invalid action '{action}'. It must be 'snapshot', 'replicate:<host>', "
            "'purge:<pattern>' or 'synchronize:<host>[,<host>]'"
        )


@dataclass(frozen=True)
class Snapshot(Job):
    """Snapshot the volume."""


@dataclass(frozen=True)
class Replicate(Job):
    """Snapshot the volume, then send that snapshot to this host."""

    host: str


@dataclass(frozen=True)
class Purge(Job):
    """Delete the snapshots this retention pattern does not keep."""

    pattern: Pattern


@dataclass(frozen=True)
class Synchronize(Job):
    """Snapshot the volume, then pull it back from these hosts."""

    hosts: tuple


@dataclass(frozen=True)
class Entry:
    """One line of the schedule file, as written there.

    Four strings, because that is what the file holds and what the API hands
    back to its clients. What the action means is ``Job.parse``'s business.
    """

    name: str
    action: str
    timer: str
    active: str

    @property
    def enabled(self):
        """Anything but the word the pause writes means the job runs."""
        return self.active != "False"

    @classmethod
    def parse(cls, row):
        """The columns of a line, the missing ones read as empty.

        Buttervolume 3.10 and older wrote three columns, without the ``Active``
        one, and such a file is still out there: its lines are read as running,
        which is what they were. A line with more columns than we know is
        another matter, because writing the file back would lose them.
        """
        if len(row) > len(FIELDS):
            raise ValidationError(
                f"Invalid schedule line {row}. It must have at most {len(FIELDS)} "
                f"columns: {', '.join(FIELDS)}"
            )
        return cls(*row, *[""] * (len(FIELDS) - len(row)))

    @property
    def row(self):
        return [self.name, self.action, self.timer, self.active]

    @property
    def fields(self):
        """The line as the API says it, and as the command line reads it back."""
        return dict(zip(FIELDS, self.row))


def read_rows(path):
    """The columns of each line, blank lines left out, nothing read of them.

    The scheduler wants them this way: it decides line by line what to do with
    one it cannot read, and a whole file that refuses to be read would stop
    every job in it, not just the line at fault.
    """
    with open(path) as f:
        return [row for row in csv.reader(f) if row]


def read_schedule(path):
    """The lines of the schedule file. Raises if the file is not there."""
    return [Entry.parse(row) for row in read_rows(path)]


def write_schedule(path, entries):
    """Replace the file in one go, or leave it exactly as it was.

    Writing in place would empty the file before knowing what goes back in it,
    and an interruption there loses the whole schedule. So the lines are
    written next to it and the file is renamed over the old one, which is
    atomic within a filesystem, hence the temporary file in the same directory.

    A rename replaces a name, where the previous write followed it: the file
    written is the one the path really designates, so a schedule reached
    through a symbolic link keeps being the file it points at.

    A machine that stops between the temporary file and the rename leaves that
    temporary file behind. Nothing here removes it: it is named after the
    schedule so that whoever finds it knows what it is, and deleting files
    nobody asked to delete is how a schedule gets lost.
    """
    path = os.path.realpath(path)
    # the name says whose leftover it is, on the day a machine stops between
    # this line and the rename below and leaves one behind
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix="schedule.")
    try:
        with os.fdopen(fd, "w", newline="") as f:
            csv.writer(f).writerows(entry.row for entry in entries)
            f.flush()
            # without this, a crash can bring the rename to the disk before
            # the lines it renames, which is the empty file we are avoiding
            os.fsync(f.fileno())
        # renaming gives a new file where writing in place kept the old one,
        # so the mode and the hands of the one being replaced are put back. A
        # temporary file is readable by nobody else, and a schedule that names
        # volumes and hosts has no reason to be born more open than that
        with suppress(FileNotFoundError):
            previous = os.stat(path)
            os.chmod(tmp, stat.S_IMODE(previous.st_mode))
            os.chown(tmp, previous.st_uid, previous.st_gid)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
