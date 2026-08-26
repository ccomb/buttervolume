"""What the schedule owes, decided first and done afterwards.

The scheduler runs what is due in ``schedule.csv``: a snapshot, a replication,
a synchronization or a purge. Reading that file, and reading what each of its
lines asks for, is ``schedule.py``'s business. What is left here is done in two
steps that do not mix: ``is_due`` decides, from a line, a date and a clock,
without touching anything; ``run_job`` does the work, one function per kind of
job, by asking the plugin through ``api.py`` exactly as the command line does.

The two files the plugin keeps outside BTRFS are both read and written in
``schedule.py``: ``schedule.csv``, which says what to run, and ``lastruns.csv``,
where the scheduler writes down the date of every job that succeeded. It reads
that second file at each round rather than remembering anything, so a daemon
that stops picks its jobs up where it left them. Only the replications under
way live in memory, and a daemon that stops has none.

The thread itself is started and stopped by ``cli.py``, which owns the daemon
and its signals. What is here only knows how to run one round.
"""

import logging
import traceback
from datetime import datetime, timedelta
from functools import singledispatch
from os.path import exists
from subprocess import CalledProcessError

from buttervolume import ReplicationError, ValidationError, api
from buttervolume.plugin import LAST_RUNS, SCHEDULE, TIMER
from buttervolume.schedule import (
    Entry,
    Job,
    Purge,
    Replicate,
    Snapshot,
    Synchronize,
    read_last_runs,
    read_rows,
    write_last_runs,
)

log = logging.getLogger()

# The volumes a replication is under way for. It lives in memory alone, and
# that is right: a daemon that stops has no replication under way either.
ReplicationInProgress = set()


def is_due(entry, last, now):
    """Has this line waited its timer since the last time it ran?

    Pure: a line, a date and a clock, nothing else. The clock is given rather
    than read here, so deciding what is due can be tested without a volume, a
    daemon or a filesystem.

    A last run later than the clock is a date nobody can believe, and the job
    is due. A host that boots with its clock ahead writes such a date, that
    date now outlives the daemon, and without this the job would wait for a
    day that never comes without a word. Running it says so and writes a date
    that can be read.
    """
    if last > now:
        return True
    return now >= last + timedelta(minutes=int(entry.timer))


@singledispatch
def run_job(job, name, test=False):
    """Run one scheduled job on one volume, and say whether its turn is spent.

    The scheduler writes down the date of a job that answers True and counts
    its timer from there, so a job that answers False comes back at the next
    round instead of waiting a full period. Three of the four say plainly
    whether they succeeded. The synchronization does not: it takes a snapshot
    of the volume before rsync overwrites it, and that snapshot cannot be
    taken back, so a failed pull spends its turn rather than leave one behind
    every minute for as long as the other host is away.

    Getting here means Job.parse accepted an action that nothing knows how to
    run. The caller logs it and moves on to the next line, which is what an
    action we cannot run deserves.
    """
    raise ValidationError(f"Nothing runs a {type(job).__name__} job")


@run_job.register
def run_snapshot(job: Snapshot, name, test=False):
    log.info("Starting scheduled snapshot of %s", name)
    snap = api.snapshot(name, test=test)
    if not snap:
        log.info("Could not snapshot %s", name)
        return False
    log.info("Successfully snapshotted to %s", snap)
    return True


@run_job.register
def run_replicate(job: Replicate, name, test=False):
    if name in ReplicationInProgress:
        log.warning(f"Replication of {name} already in progress, skipping.")
        return False
    log.info("Starting scheduled replication of %s", name)
    snap = None
    try:
        ReplicationInProgress.add(name)
        snap = api.snapshot(name, test=test)
        if not snap:
            log.info("Could not snapshot %s", name)
            return False
        log.info("Successfully snapshotted to %s", snap)
        if not api.send(snap, job.host, test=test):
            # the same road as an exception: the error is already logged,
            # and the snapshot taken for this replication has no reason to stay
            raise ReplicationError(f"Could not send {snap} to {job.host}")
        log.info("Successfully replicated %s to %s", name, snap)
        return True
    except Exception as e:
        log.warning("Replication failed: %s", e)
        # remove snapshot that was created for the failed replication
        if snap:
            if api.remove(snap, test=test):
                log.info("Removed snapshot %s for failed replication", snap)
            else:
                log.warning(
                    "Could not remove snapshot %s of the failed replication",
                    snap,
                )
        return False
    finally:
        ReplicationInProgress.remove(name)


@run_job.register
def run_purge(job: Purge, name, test=False):
    pattern = job.pattern
    log.info(
        "Starting scheduled purge of %s with pattern %s",
        name,
        pattern.deprecated or pattern.text,
    )
    # A deprecated pattern is converted and reported, not refused
    if pattern.deprecated:
        log.warning(
            "Converting deprecated pattern '%s' to '%s'. Please update your "
            "schedule using 'buttervolume scheduled --auto-convert-old-patterns'.",
            pattern.deprecated,
            pattern.text,
        )
    if not api.purge(name, pattern.text, dryrun=False, test=test):
        log.warning("Could not purge the snapshots of %s", name)
        return False
    log.info("Finished purging")
    return True


@run_job.register
def run_synchronize(job: Synchronize, name, test=False):
    log.info("Starting scheduled synchronization of %s", name)
    hosts = list(job.hosts)
    # do a snapshot to save state before pulling data
    snap = api.snapshot(name, test=test)
    if not snap:
        log.info("Could not snapshot %s", name)
        return False
    # said out loud, like the two other jobs that take one: this is the
    # snapshot a pull stopped halfway is recovered from, and an administrator
    # who has to go back to it needs to read its name somewhere
    log.info("Successfully snapshotted to %s", snap)
    if api.sync([name], hosts, test=test):
        log.debug("End of %s synchronization from %s", name, hosts)
    else:
        log.warning("Could not synchronize %s from %s", name, hosts)
    # the turn is spent either way: the snapshot taken above holds the volume
    # as it was before rsync, it is what a pull stopped halfway is recovered
    # from, and coming back at the next round would take a new one every
    # minute while the other host is away
    return True


def runjobs(config=SCHEDULE, test=False, last_runs=LAST_RUNS):
    """Run what the schedule owes, and write down the date of what succeeded.

    The dates are read from their file at each round and written back to it as
    soon as a job succeeds, so nothing of them is kept between two rounds: a
    daemon that stops forgets nothing, and a job done at the beginning of a
    round survives a machine that stops in the middle of it.
    """
    log.info("New scheduler job at %s", datetime.now())
    # open the config and launch the tasks
    if not exists(config):
        if exists(f"{config}.disabled"):
            log.warning("Config file disabled: %s", config)
        else:
            log.warning("No config file %s", config)
        return
    dates = read_last_runs(last_runs) if exists(last_runs) else {}
    # run each action in the schedule if time is elapsed since the last one
    for row in read_rows(config):
        try:
            # read here rather than in one go above: a line nobody can read
            # must not stop the lines that follow it
            entry = Entry.parse(row)
            name, action = entry.name, entry.action
            if not entry.enabled:
                log.info(f"{action} of {name} is disabled")
                continue
            try:
                job = Job.parse(action)
            except ValidationError as e:
                log.warning("Skipping the unknown action %s of %s: %s", action, name, e)
                continue
            now = datetime.now()
            # a line nobody has a date for is due: it is the first thing a
            # daemon owes a volume it was just given
            last = dates.setdefault(action, {}).get(name)
            if last is not None and not is_due(entry, last, now):
                continue
            # the date a job answered for, so one that failed and can be
            # tried again comes back at the next round
            if run_job(job, name, test=test):
                dates[action][name] = now
                write_last_runs(last_runs, dates)
        # the line at fault is the one being read, not the fields of the last
        # one read whole: a line nobody could read never filled them
        except CalledProcessError as e:
            log.error(
                "Error processing scheduler action file %s line=%s, "
                "exception=%s, stdout=%s, stderr=%s",
                config,
                row,
                str(e),
                e.stdout,
                e.stderr,
            )
        except Exception as e:
            log.error(
                "Error processing scheduler action file %s line=%s\n%s",
                config,
                row,
                str(e),
            )


def scheduler(event, config=SCHEDULE, test=False, timer=TIMER, last_runs=LAST_RUNS):
    """Read the scheduler config and apply it, then run scheduler again."""
    log.info(f"Starting the scheduler thread. Next jobs will run in {timer} seconds")
    while not test and not event.is_set():
        if event.wait(timeout=float(timer)):
            log.info("Terminating the scheduler thread")
            return
        else:
            try:
                runjobs(config, test, last_runs=last_runs)
            except Exception:
                log.critical("An exception occured in the scheduling job")
                log.critical(traceback.format_exc())
