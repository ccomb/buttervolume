"""The command line, the scheduler thread, and the server Docker talks to.

Most commands are argparse subcommands that unpack what the terminal gave
them, hand it to ``api.py`` and print what comes back, so the command line is
a client of the same API as Docker and reads the same answers. Three do not:
``run`` starts waitress on that socket with the scheduler thread beside it,
``init`` prepares a BTRFS filesystem before any daemon exists, which is
``init.py``'s business, and ``scheduled --auto-convert-old-patterns`` rewrites
``schedule.csv`` in place.

Nothing here knows how that call travels. Where the socket is, and what an
answer is shaped like, is ``api.py``'s business, and ``scheduler.py`` calls it
the same way the commands do, with the volume's name rather than the namespace
argparse would have built.

What ``run`` owns of the scheduler is its thread: it starts it beside the
server and stops it on a signal, which is also when the socket is removed.
What that thread does with a round is ``scheduler.py``'s business.
"""

import argparse
import logging
import os
import shutil
import signal
import sys
import threading
from contextlib import suppress
from dataclasses import replace
from os.path import exists

from waitress import serve

from buttervolume import ValidationError, api
from buttervolume.api import app
from buttervolume.config import (
    LOGLEVEL,
    SCHEDULE,
    SNAPSHOTS_PATH,
    SOCKET,
    TIMER,
    VOLUMES_PATH,
)
from buttervolume.init import init_btrfs
from buttervolume.purge import Pattern
from buttervolume.schedule import Job, Purge, read_schedule, write_schedule
from buttervolume.scheduler import scheduler

VERSION = "3.13.0"
logging.basicConfig(level=LOGLEVEL)
log = logging.getLogger()


def snapshot(args, test=False):
    # only the name is printed: the command answers "which snapshot holds the
    # state of this volume", and main() reads a False as an exit code of 1,
    # which a tuple could never be
    res, _ = api.snapshot(args.name[0], test=test)
    if res:
        print(res)
    return res


def schedule(args):
    return api.schedule(args.name[0], args.action[0], args.timer[0])


def _auto_convert_old_patterns():
    """Convert deprecated purge patterns in schedule.csv"""
    config = SCHEDULE
    if not exists(config):
        print(f"Schedule file not found: {config}")
        return False

    entries = read_schedule(config)
    converted = []
    for entry in entries:
        # An action nobody can read is left exactly as it is: this command
        # converts patterns, it does not clean up the file.
        job = None
        with suppress(ValidationError):
            job = Job.parse(entry.action)
        if isinstance(job, Purge) and job.pattern.deprecated:
            converted.append(replace(entry, action=f"purge:{job.pattern.text}"))
            print(
                f"Found deprecated pattern for volume '{entry.name}': "
                f"'{job.pattern.deprecated}' -> '{job.pattern.text}'"
            )
        else:
            converted.append(entry)

    count = sum(1 for old, new in zip(entries, converted) if old != new)
    if not count:
        print("No deprecated patterns found in schedule.")
        return True

    # Ask for confirmation
    print(f"\nFound {count} deprecated pattern(s). Convert them? (y/N): ", end="")
    response = input().strip().lower()

    if response not in ("y", "yes"):
        print("Conversion cancelled.")
        return False

    # Create backup
    backup_file = f"{config}.backup"

    shutil.copy2(config, backup_file)
    print(f"Created backup: {backup_file}")

    write_schedule(config, converted)

    print(f"Successfully converted {count} pattern(s).")
    print("Updated schedule file. The scheduler will use the new patterns on next run.")
    return True


def scheduled(args):
    # Handle auto-convert option
    if getattr(args, "auto_convert_old_patterns", False):
        return _auto_convert_old_patterns()

    if args.action == "list":
        scheduled = api.scheduled()
        if scheduled:
            formatted_jobs = []
            deprecated_patterns = []

            for job in scheduled:
                status = "(paused)" if job.get("Active") == "False" else ""
                action = job["Action"]

                # Check for deprecated purge patterns
                if action.startswith("purge:"):
                    _, pattern = action.split(":", 1)
                    try:
                        deprecated = Pattern.parse(pattern).deprecated
                    except ValidationError:
                        deprecated = None
                    if deprecated:
                        deprecated_patterns.append((job["Name"], action, pattern))
                        status += " (deprecated pattern)"

                formatted_jobs.append(f"{job['Action']} {job['Timer']} {job['Name']} {status}")

            print("\n".join(formatted_jobs))

            # Show warning about deprecated patterns
            if deprecated_patterns:
                print("\nWARNING: Found deprecated purge patterns:")
                for name, _, pattern in deprecated_patterns:
                    print(f"  Volume '{name}': pattern '{pattern}' should be converted")
                print(
                    "Run 'buttervolume scheduled --auto-convert-old-patterns' to convert them automatically."
                )

        return scheduled
    elif args.action == "pause":
        return api.schedule_pause()
    elif args.action == "resume":
        return api.schedule_resume()


def snapshots(args):
    snapshots = api.snapshots(args.name)
    if snapshots:
        print("\n".join(snapshots))
    return snapshots


def restore(args):
    res = api.restore(args.name[0], args.target)
    if res:
        print(res)
    return res


def clone(args):
    res = api.clone(args.name[0], args.target)
    if res:
        print(res)
    return res


def send(args, test=False):
    return api.send(args.snapshot[0], args.host[0], test=test)


def receive(args, test=False):
    res = api.receive(args.volume[0], args.host[0], test=test)
    if res:
        print(res)
    return res


def sync(args, test=False):
    return api.sync(args.volumes, args.hosts, test=test)


def remove(args, test=False):
    return api.remove(args.name[0], test=test)


def purge(args, test=False):
    return api.purge(args.name[0], args.pattern[0], args.dryrun, test=test)


def shutdown(thread, event):
    log.info("Shutting down buttervolume...")
    event.set()
    thread.join()

    # Clean up the socket file to prevent Docker from hanging
    if exists(SOCKET):
        try:
            os.unlink(SOCKET)
            log.info("Cleaned up socket: %s", SOCKET)
        except OSError as e:
            log.warning("Could not remove socket %s: %s", SOCKET, e)

    sys.exit(0)  # Use exit code 0 for clean shutdown


def run(_, test=False):
    if not exists(VOLUMES_PATH):
        log.info("Creating %s", VOLUMES_PATH)
        os.makedirs(VOLUMES_PATH, exist_ok=True)
    if not exists(SNAPSHOTS_PATH):
        log.info("Creating %s", SNAPSHOTS_PATH)
        os.makedirs(SNAPSHOTS_PATH, exist_ok=True)

    # Clean up any stale socket from previous unclean shutdown
    if exists(SOCKET):
        try:
            os.unlink(SOCKET)
            log.info("Removed stale socket: %s", SOCKET)
        except OSError as e:
            log.warning("Could not remove stale socket %s: %s", SOCKET, e)

    # run a thread for the scheduled jobs
    print(f"Starting scheduler job every {TIMER}s")
    event = threading.Event()
    thread = threading.Thread(
        target=scheduler,
        args=(event,),
        kwargs={"config": SCHEDULE, "test": test, "timer": TIMER},
    )
    thread.start()
    signal.signal(signal.SIGINT, lambda *_: shutdown(thread, event))
    signal.signal(signal.SIGTERM, lambda *_: shutdown(thread, event))
    signal.signal(signal.SIGHUP, lambda *_: shutdown(thread, event))
    signal.signal(signal.SIGQUIT, lambda *_: shutdown(thread, event))
    signal.signal(signal.SIGURG, lambda *_: shutdown(thread, event))
    # listen to requests
    print(f"Listening to requests on {SOCKET}...")
    serve(app, unix_socket=SOCKET, unix_socket_perms="660")


def main():
    parser = argparse.ArgumentParser(
        prog="buttervolume",
        description="Command-line client for the BTRFS Docker Volume Plugin",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(help="sub-commands")
    parser_run = subparsers.add_parser(
        "run", help="Run the plugin in foreground (for development or debugging)"
    )

    parser_snapshot = subparsers.add_parser("snapshot", help="Snapshot a volume")
    parser_snapshot.add_argument(
        "name", metavar="name", nargs=1, help="Name of the volume to snapshot"
    )
    parser_snapshots = subparsers.add_parser("snapshots", help="List snapshots")
    parser_snapshots.add_argument(
        "name",
        metavar="name",
        nargs="?",
        help="Name of the volume whose snapshots are to list",
    )

    parser_schedule = subparsers.add_parser(
        "schedule",
        help=(
            "Schedule, unschedule, pause or resume a periodic snapshot, "
            "replication, synchronization or purge"
        ),
    )
    parser_schedule.add_argument(
        "action",
        metavar="action",
        nargs=1,
        help=(
            "Name of the action to schedule "
            "(snapshot, replicate:<host>, purge:<pattern>, "
            "synchronize:<host[,host2[,host3]]>)"
        ),
    )
    parser_schedule.add_argument(
        "timer",
        metavar="timer",
        nargs=1,
        help=(
            "Time span in minutes between two actions. Or: '0' (or 'delete') to "
            "'remove' the schedule, 'pause' to pause, 'resume' to resume"
        ),
    )
    parser_schedule.add_argument(
        "name",
        metavar="name",
        nargs=1,
        help="Name of the volume whose snapshots are to schedule",
    )

    parser_scheduled = subparsers.add_parser(
        "scheduled", help="List, pause or resume all the scheduled actions"
    )
    parser_scheduled.add_argument(
        "action",
        metavar="action",
        nargs="?",
        choices=("list", "pause", "resume"),
        default="list",
        help=("Name of the action on the scheduled list (list, pause, resume). Default: list"),
    )
    parser_scheduled.add_argument(
        "--auto-convert-old-patterns",
        action="store_true",
        help="Automatically convert deprecated purge patterns in schedule.csv",
    )

    parser_restore = subparsers.add_parser("restore", help="Restore a snapshot")
    parser_restore.add_argument(
        "name",
        metavar="name",
        nargs=1,
        help=(
            "Name of the snapshot to restore "
            "(use the name of the volume to restore the latest snapshot)"
        ),
    )
    parser_restore.add_argument(
        "target",
        metavar="target",
        nargs="?",
        default=None,
        help=("Name of the restored volume"),
    )

    parser_clone = subparsers.add_parser("clone", help="Clone a volume")
    parser_clone.add_argument(
        "name", metavar="name", nargs=1, help=("Name of the volume to be cloned")
    )
    parser_clone.add_argument(
        "target",
        metavar="target",
        nargs="?",
        default=None,
        help=("Name of the new volume to be created"),
    )

    parser_send = subparsers.add_parser("send", help="Send a snapshot to another host")
    parser_send.add_argument("host", metavar="host", nargs=1, help="Host to send the snapshot to")
    parser_send.add_argument("snapshot", metavar="snapshot", nargs=1, help="Snapshot to send")

    parser_receive = subparsers.add_parser(
        "receive", help="Receive the last snapshot another host has of a volume"
    )
    parser_receive.add_argument(
        "host", metavar="host", nargs=1, help="Host to receive the snapshot from"
    )
    parser_receive.add_argument(
        "volume", metavar="volume", nargs=1, help="Volume whose snapshot to receive"
    )

    parser_sync = subparsers.add_parser("sync", help="Sync a volume from other host(s)")
    parser_sync.add_argument("volumes", metavar="volumes", nargs=1, help="Volumes to sync (1 max)")
    parser_sync.add_argument(
        "hosts",
        metavar="hosts",
        nargs="*",
        help="Host list to sync data from (space separator)",
    )

    parser_remove = subparsers.add_parser("rm", help="Delete a snapshot")
    parser_remove.add_argument(
        "name", metavar="name", nargs=1, help="Name of the snapshot to delete"
    )
    parser_purge = subparsers.add_parser("purge", help="Purge old snapshot using a purge pattern")
    parser_purge.add_argument(
        "pattern",
        metavar="pattern",
        nargs=1,
        help=(
            "Purge pattern (X:Y, or X:Y:Z, or X:Y:Z:T, etc.)\n"
            "Pattern components must have a suffix with the unit:\n"
            "  m = minutes, h = hours, d = days, w = weeks, y = years\n"
            "So 4h:1d:1w means:\n"
            "  Keep all snapshots in the last four hours,\n"
            "  then keep 1 snapshot every 4 hours during 1 day,\n"
            "  then keep 1 snapshot every day during the 1st week\n"
            "  then delete snapshots older than 1 week.\n"
        ),
    )
    parser_purge.add_argument(
        "name",
        metavar="name",
        nargs=1,
        help=("Name of the volume whose snapshots are to purge"),
    )
    parser_purge.add_argument(
        "--dryrun",
        action="store_true",
        help="Don't really purge but tell what would be deleted",
    )

    parser_init = subparsers.add_parser("init", help="Initialize BTRFS filesystem for buttervolume")
    init_group = parser_init.add_mutually_exclusive_group()
    init_group.add_argument(
        "--path",
        help="Path to existing BTRFS partition/mount",
    )
    init_group.add_argument(
        "--file",
        nargs="?",
        const="/var/lib/docker/btrfs.img",
        help="Create BTRFS image file (default: /var/lib/docker/btrfs.img)",
    )
    parser_init.add_argument(
        "--size",
        default="10G",
        help="Size of BTRFS image file, only with --file (default: 10G)",
    )

    parser_run.set_defaults(func=run)
    parser_snapshot.set_defaults(func=snapshot)
    parser_snapshots.set_defaults(func=snapshots)
    parser_schedule.set_defaults(func=schedule)
    parser_scheduled.set_defaults(func=scheduled)
    parser_restore.set_defaults(func=restore)
    parser_clone.set_defaults(func=clone)
    parser_send.set_defaults(func=send)
    parser_receive.set_defaults(func=receive)
    parser_sync.set_defaults(func=sync)
    parser_remove.set_defaults(func=remove)
    parser_purge.set_defaults(func=purge)
    parser_init.set_defaults(func=init_btrfs)

    args = parser.parse_args()
    if hasattr(args, "func"):
        if args.func(args) is False:
            sys.exit(1)
    else:
        parser.print_help()
