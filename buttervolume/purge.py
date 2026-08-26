"""What a snapshot retention pattern says, and which snapshots it condemns.

A pattern is written ``4h:1d:2w``: keep everything from the last four hours,
then one snapshot every four hours up to a day, then one a day up to two
weeks, then nothing. A pattern of a single specifier, ``2h``, keeps the last
two hours and deletes the rest.

Older versions accepted ``2h:2h`` for that last one. Such a pattern is read
back here as the ``2h`` it means, and the original spelling is kept in
``deprecated`` so the caller can decide what to do with it: an immediate purge
refuses it, the scheduler converts it and says so.

Nothing here touches the disk and nothing here reads the configuration: the
date format arrives as an argument, as it does for a snapshot name.
"""

import logging
from dataclasses import dataclass

from buttervolume import ValidationError
from buttervolume.names import Snapshot

log = logging.getLogger()

UNITS = {"m": 1, "h": 60, "d": 60 * 24, "w": 60 * 24 * 7, "y": 60 * 24 * 365}


@dataclass(frozen=True)
class Pattern:
    """A retention pattern, read: its durations in minutes and its spelling.

    It is only built by parse(), so `minutes` is always strictly ascending and
    a caller never has to wonder whether the pattern it holds was checked.
    """

    minutes: tuple[int, ...]
    text: str
    deprecated: str | None = None

    @classmethod
    def parse(cls, text):
        components = text.split(":")
        if not all(c[:-1].isnumeric() for c in components):
            raise ValidationError(
                f"Invalid purge pattern: {text} - "
                "Pattern components must be numeric with unit suffix"
            )
        for c in components:
            if c[-1] not in UNITS:
                raise ValidationError(f"Invalid purge pattern: {text} - unknown unit '{c[-1]}'")
        minutes = tuple(int(c[:-1]) * UNITS[c[-1]] for c in components)

        if len(components) == 2 and components[0] == components[1]:
            return cls(minutes[:1], components[0], deprecated=text)

        if not all(x < y for x, y in zip(minutes, minutes[1:])):
            raise ValidationError(
                f"Invalid purge pattern: {text} - "
                "Time values must be in ascending order (e.g., 2h:4h:8h or 30m:2h:1d)"
            )
        return cls(minutes, text)

    def __str__(self):
        return self.text


def compute_purges(snapshots, pattern, now, dtformat):
    """Return the list of snapshots this pattern condemns, at this moment."""
    snapshots = sorted(snapshots)
    ages = list(reversed(pattern.minutes))
    purge_list = []
    max_age = ages[0]
    # Age of the snapshots in minutes.
    # Example : [30, 70, 90, 150, 210, ..., 4000]
    snapshots_age = []
    valid_snapshots = []
    for s in snapshots:
        try:
            age = now - Snapshot.parse(s).taken_at(dtformat)
        except (ValidationError, ValueError):
            # a purge does not delete what it cannot date
            log.info("Skipping purge of %s with invalid date format", s)
            continue
        snapshots_age.append(int(age.total_seconds()) / 60)
        valid_snapshots.append(s)
    if not valid_snapshots:
        return purge_list

    # A single specifier ("2h" -> [120]) deletes everything past the threshold
    if len(ages) == 1:
        return [s for s, age in zip(valid_snapshots, snapshots_age) if age > ages[0]]

    # Several specifiers ("2h:1d:1w" -> [10080, 1440, 120]) keep one snapshot
    # per timeframe inside each segment.
    # age segments = [(10080, 1440), (1440, 120)]
    for age_segment in [(ages[i], ages[i + 1]) for i, _ in enumerate(ages[:-1])]:
        last_timeframe = -1
        for i, age in enumerate(snapshots_age):
            # if the age is outside the age_segment, delete nothing.
            # Only 70 and 90 are inside the age_segment (60, 180)
            if age > age_segment[0] < max_age or age < age_segment[1]:
                continue
            # Now get the timeframe number of the snapshot.
            # Ages 70 and 90 are in the same timeframe (70//60 == 90//60)
            timeframe = age // age_segment[1]
            # delete if we already had a snapshot in the same timeframe
            # or if the snapshot is very old
            if timeframe == last_timeframe or age > max_age:
                purge_list.append(valid_snapshots[i])
            last_timeframe = timeframe
    return purge_list
