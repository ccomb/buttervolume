"""What a scheduled job asks for, read from the way it is written.

A line of ``schedule.csv`` names its job in a single string: ``snapshot``,
``replicate:node2``, ``purge:4h:1d:1w``, ``synchronize:node2,node3``. Reading
that string is all this module does. It touches no disk and runs nothing: what
a host is worth is decided in ``names.py``, what a retention pattern says in
``purge.py``, and this module asks them.

A job keeps the action exactly as the schedule spells it, because that string
is how the scheduler remembers when the job last ran.

An action nobody could run leaves here as a ``ValidationError``, so no caller
has to decide what an unknown verb means.
"""

from dataclasses import dataclass

from buttervolume import ValidationError
from buttervolume.names import validate_hostname
from buttervolume.purge import Pattern


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
