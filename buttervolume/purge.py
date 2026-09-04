"""What a snapshot retention pattern says, and which snapshots it condemns.

A pattern is written ``4h:1d:2w``: keep everything from the last four hours,
then one snapshot every four hours up to a day, then one a day up to two
weeks, then nothing. A component can say how many snapshots it keeps instead
of where the next one starts: ``1h/4:1d/3:1w/4`` keeps everything from the
last hour, then one an hour for four hours, then one a day for three days,
then one a week for four weeks, then nothing, which is eleven snapshots plus
the last hour. A counted component starts where the one before it stopped,
so the count is what it says and adding them up says what the pattern keeps.
A pattern of a single specifier, ``2h``, keeps the last two hours and deletes
the rest.

A component with no count says where the next step starts, and the last
component of all is the age past which everything dies. That last one is the
only one a count changes anything for: coming after a counted component, what
the counted one covers and what it names would leave a range of ages
belonging to no step, kept for good although the pattern says the opposite.
``1h/4:1d`` is refused for that, and ``1h/4:1d/3`` is the pattern meant. In
the middle of a pattern a component with no count is fine: ``1h/48:1d:1w``
thins by the day from where the hours stopped up to a week.

Older versions accepted ``2h:2h`` for a single duration. Such a pattern is
read back here as the ``2h`` it means, and the original spelling is kept in
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
class Step:
    """A slice of ages where the pattern keeps one snapshot per timeframe.

    `width` is how wide a timeframe is, `start` and `end` are the ages the
    step covers, the end excluded. How many snapshots it keeps is
    `(end - start) // width`, which is the count a component spells out.
    """

    width: int
    start: int
    end: int


@dataclass(frozen=True)
class Pattern:
    """A retention pattern, read: the steps it thins, and where it stops.

    It is only built by parse(), so the steps follow each other without a gap
    and a caller never has to wonder whether the pattern it holds was checked.
    Anything younger than the first step is kept, anything as old as `cutoff`
    is deleted, and `cutoff` is where the last step ends.
    """

    steps: tuple[Step, ...]
    cutoff: int
    text: str
    deprecated: str | None = None

    @classmethod
    def parse(cls, text):
        components = text.split(":")
        durations = []
        counts = []
        for c in components:
            duration, counted, count = c.partition("/")
            # isdecimal, not isnumeric: "²".isnumeric() is True and int("²") raises,
            # and a pattern nobody can apply must not leave here as a ValueError
            if not duration[:-1].isdecimal():
                raise ValidationError(
                    f"Invalid purge pattern: {text} - "
                    "Pattern components must be numeric with unit suffix"
                )
            if duration[-1] not in UNITS:
                raise ValidationError(
                    f"Invalid purge pattern: {text} - unknown unit '{duration[-1]}'"
                )
            if counted and not (count.isdecimal() and int(count) >= 1):
                raise ValidationError(
                    f"Invalid purge pattern: {text} - a count is how many snapshots the "
                    "component keeps, a whole number of at least one, as in 1h/4"
                )
            if not int(duration[:-1]):
                raise ValidationError(
                    f"Invalid purge pattern: {text} - '{c}' lasts no time at all, and a "
                    "step of no length would hold every snapshot in the same timeframe"
                )
            durations.append(int(duration[:-1]) * UNITS[duration[-1]])
            counts.append(int(count) if counted else None)

        if len(components) == 2 and components[0] == components[1] and counts == [None, None]:
            return cls((), durations[0], components[0], deprecated=text)

        if not all(x < y for x, y in zip(durations, durations[1:])):
            raise ValidationError(
                f"Invalid purge pattern: {text} - "
                "Time values must be in ascending order (e.g., 2h:4h:8h or 30m:2h:1d)"
            )

        steps = []
        # everything younger than the first component is kept, so the first
        # step starts there and each one after starts where the last stopped
        start = durations[0]
        for i, (duration, count) in enumerate(zip(durations, counts)):
            last = i == len(components) - 1
            if count:
                end = start + duration * count
            elif not last:
                end = durations[i + 1]
                if end <= start:
                    raise ValidationError(
                        f"Invalid purge pattern: {text} - the components before "
                        f"'{components[i + 1]}' already keep snapshots older than it does"
                    )
            elif i and counts[i - 1]:
                raise ValidationError(
                    f"Invalid purge pattern: {text} - '{components[i]}' must say how many "
                    f"snapshots it keeps, as in '{components[i]}/3', because the component "
                    "before it does. Without a count it only says where a step stops, and "
                    "the ages between the two would belong to no step at all"
                )
            else:
                # a last component with no count is the age past which
                # everything dies, and the last step already stops there
                break
            steps.append(Step(duration, start, end))
            start = end
        return cls(tuple(steps), start, text)

    def __str__(self):
        return self.text


def compute_purges(snapshots, pattern, now, dtformat):
    """Return the list of snapshots this pattern condemns, at this moment.

    Inside a step the pattern keeps one snapshot per timeframe, and that
    timeframe is counted from the epoch, on the moment the snapshot was taken.
    Counting it on the age would move every boundary at every run, and the
    snapshot spared in a timeframe would not be the same one twice.

    Never the trace of a send, nor the snapshot it was made from: whatever
    the pattern says, a replication keeps the parent its next send needs.
    """
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
    # past the end of the pattern nothing survives
    purge_list = [s for _, s, age in dated if age >= pattern.cutoff]
    for step in pattern.steps:
        last_timeframe = None
        for taken, s, age in dated:
            if not step.start <= age < step.end:
                continue
            # the timeframe number of the snapshot: the slice of the calendar
            # it was taken in, as wide as this step steps, and not the slice
            # its age falls in today
            timeframe = (taken - EPOCH) // timedelta(minutes=step.width)
            # delete if we already had a snapshot in the same timeframe
            if timeframe == last_timeframe:
                purge_list.append(s)
            last_timeframe = timeframe
    return [s for s in purge_list if s not in needed]
