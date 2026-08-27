"""How volumes and snapshots are named, and how a name is read back.

A volume is named ``www``. A snapshot of it carries the moment it was taken:
``www@2026-08-26T10:00:00.000000``. Once that snapshot has been sent to a
host, the trace kept locally to serve as parent for the next send adds the
target: ``www@2026-08-26T10:00:00.000000@node2``.

Nothing here touches the disk and nothing here reads the configuration: the
date and its format arrive as arguments. A name is a name, valid or not, long
before anything is created with it.
"""

import re
from dataclasses import dataclass, replace
from datetime import datetime

from buttervolume import ValidationError


def validate_volume_name(name):
    """Validate volume name for security and correctness"""
    if not name:
        raise ValidationError("Volume name cannot be empty")

    if "@" in name:
        raise ValidationError('"@" is illegal in a volume name')

    # Check for path traversal
    if ".." in name or name.startswith("/"):
        raise ValidationError("Invalid characters in volume name")

    # Check for dangerous shell characters
    dangerous_chars = [
        "`",
        "$",
        "|",
        "&",
        ";",
        ">",
        "<",
        "*",
        "?",
        "[",
        "]",
        "(",
        ")",
        "{",
        "}",
        "\\",
    ]
    if any(char in name for char in dangerous_chars):
        raise ValidationError("Volume name contains dangerous characters")

    # Ensure reasonable length
    if len(name) > 255:
        raise ValidationError("Volume name too long")

    # Only allow alphanumeric, dash, underscore, dot
    if not re.fullmatch(r"[a-zA-Z0-9._-]+", name):
        raise ValidationError("Volume name contains invalid characters")

    return name


def validate_snapshot_name(name):
    """Validate a snapshot name: volume@timestamp, plus @host for sent snapshots.

    Snapshot names come from Docker or from a remote host and end up in a
    path and in a shell command, so they get the same care as volume names.
    """
    if not name:
        raise ValidationError("Snapshot name cannot be empty")

    if len(name) > 255:
        raise ValidationError("Snapshot name too long")

    parts = name.split("@")
    if len(parts) not in (2, 3):
        raise ValidationError("Invalid snapshot name format")

    validate_volume_name(parts[0])
    for part in parts[1:]:
        if not part or not re.fullmatch(r"[a-zA-Z0-9.:_-]+", part):
            raise ValidationError("Snapshot name contains invalid characters")

    return name


def validate_hostname(hostname):
    """Validate hostname for SSH operations"""
    if not hostname:
        raise ValidationError("Hostname cannot be empty")

    # Basic hostname validation
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", hostname):
        raise ValidationError("Invalid hostname format")

    if len(hostname) > 253:
        raise ValidationError("Hostname too long")

    return hostname


@dataclass(frozen=True)
class Snapshot:
    """A snapshot name, read: the volume, the moment, and the target of a send.

    It is only built by parse(), so a name with four parts or an empty
    timestamp never becomes one of these.
    """

    volume: str
    timestamp: str
    host: str | None = None

    @classmethod
    def parse(cls, name):
        return cls(*validate_snapshot_name(name).split("@"))

    def __str__(self):
        return "@".join(p for p in (self.volume, self.timestamp, self.host) if p)

    def taken_at(self, dtformat):
        """The moment this snapshot was taken, as written by new_snapshot."""
        return datetime.strptime(self.timestamp, dtformat)

    def sent_to(self, host):
        """The trace to keep locally once this snapshot has been sent there."""
        return replace(self, host=validate_hostname(host))

    def without_host(self):
        """The snapshot this trace was made from, which is its own parent."""
        return replace(self, host=None)


def new_snapshot(volume, dtformat, now):
    """Name a new snapshot of this volume, as the API will have to read it back.

    The date format is configurable, so a format holding a space or a plus
    sign would build a name the validation rejects: the snapshot would exist
    and no endpoint could name it again. Better to refuse to create it.
    """
    return Snapshot.parse(f"{volume}@{now.strftime(dtformat)}")


def parsed(names):
    """These names, read; the ones that are not snapshot names are left out.

    The snapshots directory is read with listdir, and nothing promises that
    everything sitting there was put there by us.
    """
    for name in names:
        try:
            yield Snapshot.parse(name)
        except ValidationError:
            continue


def snapshots_of(volume, names):
    """The names among these that are snapshots of this volume, oldest first.

    A name we could not have written is kept, not quietly dropped: hiding it
    would let the caller believe it has seen everything, and pick the second
    most recent snapshot thinking it is the most recent one. It is refused
    later, when it becomes a path, and then the answer says so.
    """
    return sorted(n for n in names if n.startswith(volume + "@"))


def sent_snapshots(volume, host, names):
    """The traces of the sends of this volume to this host, oldest first."""
    return sorted(
        (s for s in parsed(names) if s.volume == volume and s.host == host),
        key=str,
    )


def _taken_snapshots(volume, names):
    """The snapshots taken of this volume among these names, the traces left out.

    A trace of a send is named after the snapshot it was made from, plus the
    target, so `www@2026-08-26T10:00:00.000000@node3` sorts after the snapshot
    itself and would pass for the most recent one.

    Every name of this volume is read, and one that cannot be read raises
    rather than being dropped. These names come from another machine, and a
    listing we could not read must never be answered as a host with nothing.
    """
    return [s for s in map(Snapshot.parse, snapshots_of(volume, names)) if not s.host]


def snapshot_to_fetch(volume, remote_names, local_names):
    """What to ask that host for, and the parent both sides already hold.

    The pair `(snapshot, parent)`, or None when the host holds no snapshot of
    this volume. The parent is the most recent older snapshot the two sides
    have in common, which is what an incremental transfer is built on; None
    when they have none, and then the whole volume has to come over.

    The parent is read from the two listings rather than from the trace of a
    send, which says what we once sent there. The question here is what that
    host has now, and it has just been asked.
    """
    remote = _taken_snapshots(volume, remote_names)
    if not remote:
        return None
    # what we hold is read as plain names, none of which has to make sense: a
    # name saying the same thing as one over there is the same snapshot, and a
    # name we could not have written says the same thing as none of them. So a
    # stray file in our own directory stops nothing, the way it stops nothing
    # anywhere else this directory is read.
    held = set(local_names)
    # never the one being fetched, which cannot be its own parent
    common = [s for s in remote[:-1] if str(s) in held]
    return remote[-1], (common[-1] if common else None)
