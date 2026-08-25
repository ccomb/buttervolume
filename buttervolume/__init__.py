"""The errors Buttervolume answers with.

They live here rather than in `plugin.py` because the modules below it, such
as the naming rules, raise them too, and importing the plugin from there would
close a circle. `BtrfsError` is the exception: it belongs to `btrfs.py`, which
knows nothing of volumes.
"""


class ButtervolumeError(Exception):
    """Base exception for Buttervolume errors"""


class VolumeNotFoundError(ButtervolumeError):
    """Raised when a volume is not found"""


class SnapshotNotFoundError(ButtervolumeError):
    """Raised when a snapshot is not found"""


class ValidationError(ButtervolumeError):
    """Raised when input validation fails"""


class ReplicationError(ButtervolumeError):
    """Raised when replication fails"""


class ReplicationTimeoutError(ReplicationError):
    """Raised when a replication is killed for taking too long"""
