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
that is not there, because its three callers answer that differently and it is
their decision, not this module's.
"""

import csv
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
        if len(row) != len(FIELDS):
            raise ValidationError(
                f"Invalid schedule line {row}. It must have {len(FIELDS)} columns: "
                f"{', '.join(FIELDS)}"
            )
        return cls(*row)

    @property
    def row(self):
        return [self.name, self.action, self.timer, self.active]

    @property
    def fields(self):
        """The line as the API says it, and as the command line reads it back."""
        return dict(zip(FIELDS, self.row))


def read_schedule(path):
    """The lines of the schedule file. Raises if the file is not there."""
    with open(path) as f:
        return [Entry.parse(row) for row in csv.reader(f)]


def write_schedule(path, entries):
    with open(path, "w", newline="") as f:
        csv.writer(f).writerows(entry.row for entry in entries)
