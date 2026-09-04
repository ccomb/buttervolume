"""What a snapshot retention pattern says, and which snapshots it condemns.

A pattern is written ``4h:1d:2w``: keep everything from the last four hours,
then one snapshot every four hours up to a day, then one a day up to two
weeks, then nothing. A pattern of a single specifier, ``2h``, keeps the last
two hours and deletes the rest.

Older versions accepted ``2h:2h`` for that last one. Such a pattern is read
back here as the ``2h`` it means, and the original spelling is kept in
``deprecated`` so the caller can decide what to do with it: an immediate purge
refuses it, a schedule still accepts it as it is written, and the scheduler
converts it and says so at every run.

Nothing here touches the disk and nothing here reads the configuration: the
date format arrives as an argument, as it does for a snapshot name.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from buttervolume import ValidationError
from buttervolume.names import Snapshot, parsed

log = logging.getLogger()

UNITS = {"m": 1, "h": 60, "d": 60 * 24, "w": 60 * 24 * 7, "y": 60 * 24 * 365}

# Timeframes are counted from here, in wall clock minutes: a day wide timeframe
# starts at midnight, an hour wide one on the round hour, and a week wide one on
# a Thursday, since that is what the 1st of January 1970 was.
EPOCH = datetime(1970, 1, 1)


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
        # isdecimal, not isnumeric: "²".isnumeric() is True and int("²") raises,
        # and a pattern nobody can apply must not leave here as a ValueError
        if not all(c[:-1].isdecimal() for c in components):
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
    """Return the list of snapshots this pattern condemns, at this moment.

    Inside a segment the pattern keeps one snapshot per timeframe, and that
    timeframe is counted from the epoch, on the moment the snapshot was taken.
    Counting it on the age would move every boundary at every run, and the
    snapshot spared in a timeframe would not be the same one twice.

    Never the trace of a send, nor the snapshot it was made from: whatever
    the pattern says, a replication keeps the parent its next send needs.
    """
    snapshots = sorted(snapshots)
    # a purge does not delete what a send still needs: the trace of a send, and
    # the snapshot it was made from, which is the parent the next incremental
    # send is built on. Both are taken out of the answer rather than out of the
    # input, because a name missing from the input frees its timeframe below,
    # and a neighbour that should die would survive in its place.
    needed = set()
    for s in parsed(snapshots):
        if s.host:
            needed.add(str(s))
            needed.add(str(s.without_host()))
    ages = list(reversed(pattern.minutes))
    purge_list = []
    max_age = ages[0]
    # Each snapshot with the moment it was taken and its age in minutes.
    # Example : [(datetime(2026, 8, 26, 11, 30), "www@...", 30), ...]
    # Ordered on that moment and not on the name, because the date format is a
    # setting and nothing promises it sorts like a date.
    dated = []
    for s in snapshots:
        try:
            taken = Snapshot.parse(s).taken_at(dtformat)
        except (ValidationError, ValueError):
            # a purge does not delete what it cannot date
            log.info("Skipping purge of %s with invalid date format", s)
            continue
        dated.append((taken, s, int((now - taken).total_seconds()) / 60))
    dated.sort()
    # A single specifier ("2h" -> [120]) deletes everything past the threshold
    if len(ages) == 1:
        purge_list = [s for _, s, age in dated if age > ages[0]]
    else:
        # Several specifiers ("2h:1d:1w" -> [10080, 1440, 120]) keep one snapshot
        # per timeframe inside each segment.
        # age segments = [(10080, 1440), (1440, 120)]
        for age_segment in [(ages[i], ages[i + 1]) for i, _ in enumerate(ages[:-1])]:
            last_timeframe = None
            for taken, s, age in dated:
                # if the age is outside the age_segment, delete nothing.
                # Only 70 and 90 are inside the age_segment (60, 180)
                if age > age_segment[0] < max_age or age < age_segment[1]:
                    continue
                # Now get the timeframe number of the snapshot: the slice of
                # the calendar it was taken in, as wide as this segment steps,
                # and not the slice its age falls in today.
                timeframe = (taken - EPOCH) // timedelta(minutes=1) // age_segment[1]
                # delete if we already had a snapshot in the same timeframe
                # or if the snapshot is very old
                if timeframe == last_timeframe or age > max_age:
                    purge_list.append(s)
                last_timeframe = timeframe
    return [s for s in purge_list if s not in needed]
