import argparse
import csv
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import traceback
import urllib.parse
from datetime import datetime, timedelta
from os.path import exists
from subprocess import CalledProcessError

import requests_unixsocket
from bottle import app
from requests.exceptions import ConnectionError
from waitress import serve
from webtest import TestApp

from buttervolume.plugin import (
    FIELDS,
    LOGLEVEL,
    SCHEDULE,
    SCHEDULE_DISABLED,
    SNAPSHOTS_PATH,
    SOCKET,
    TIMER,
    USOCKET,
    VOLUMES_PATH,
    convert_purge_pattern,
    validate_purge_pattern,
)

VERSION = "3.13.0"
logging.basicConfig(level=LOGLEVEL)
log = logging.getLogger()
app = app()


ReplicationInProgress = set()


class Session:
    """wrapper for requests_unixsocket.Session"""

    def __init__(self):
        self.session = requests_unixsocket.Session()

    def _log_connection_error(self):
        """Log connection error with helpful guidance"""
        log.error("Failed to connect to Buttervolume plugin.")

        # Check if we're running in a container
        if os.path.exists("/.dockerenv") or os.environ.get("BUTTERVOLUME_IN_CONTAINER"):
            log.error("Running in container detected. To use buttervolume CLI in a container:")
            log.error("1. Mount Docker socket: -v /var/run/docker.sock:/var/run/docker.sock")
            log.error("2. Mount plugin sockets: -v /run/docker/plugins:/run/docker/plugins")
            log.error("3. Or override socket path: -e BUTTERVOLUME_SOCKET=/path/to/btrfs.sock")
        else:
            log.error("You can start the plugin with: buttervolume run")
            log.error("Or install the Docker plugin: docker plugin install ccomb/buttervolume")

    def post(self, *a, **kw):
        try:
            return self.session.post(*a, **kw)
        except ConnectionError:
            self._log_connection_error()
            return

    def get(self, *a, **kw):
        try:
            return self.session.get(*a, **kw)
        except ConnectionError:
            self._log_connection_error()


def get_from(resp, key):
    """get specified key from plugin response output"""
    if resp is None:
        return False
    try:  # bottle
        content = resp.content
    except Exception:  # TestApp
        content = resp.body
    if resp.status_code == 200:
        error = json.loads(content.decode())["Err"]
        if error:
            log.error(error)
            return False
        return json.loads(content.decode()).get(key)
    else:
        log.error("%s: %s", resp.status_code, resp.reason)
        return False


def snapshot(args, test=False):
    urlpath = "/VolumeDriver.Snapshot"
    param = json.dumps({"Name": args.name[0]})
    if test:
        resp = TestApp(app).post(urlpath, param)
    else:
        resp = Session().post(f"http+unix://{urllib.parse.quote_plus(USOCKET)}{urlpath}", param)
    res = get_from(resp, "Snapshot")
    if res:
        print(res)
    return res


def schedule(args):
    urlpath = "/VolumeDriver.Schedule"
    param = json.dumps({"Name": args.name[0], "Action": args.action[0], "Timer": args.timer[0]})
    resp = Session().post(f"http+unix://{urllib.parse.quote_plus(USOCKET)}{urlpath}", param)
    return get_from(resp, "")


def _auto_convert_old_patterns():
    """Convert deprecated purge patterns in schedule.csv"""
    config = SCHEDULE
    if not exists(config):
        print(f"Schedule file not found: {config}")
        return False

    # Read current schedule
    updates = []
    needs_conversion = False

    with open(config) as f:
        for line in csv.DictReader(f, fieldnames=FIELDS):
            name, action, timer, enabled = line.values()

            if action.startswith("purge:"):
                _, pattern = action.split(":", 1)
                try:
                    warning = validate_purge_pattern(pattern, allow_backward_compat=True)
                    if warning:
                        converted_str = convert_purge_pattern(pattern)
                        new_action = f"purge:{converted_str}"
                        updates.append((name, action, new_action))
                        needs_conversion = True
                        print(
                            f"Found deprecated pattern for volume '{name}': '{pattern}' -> '{converted_str}'"
                        )
                except Exception:
                    pass

    if not needs_conversion:
        print("No deprecated patterns found in schedule.")
        return True

    # Ask for confirmation
    print(f"\nFound {len(updates)} deprecated pattern(s). Convert them? (y/N): ", end="")
    response = input().strip().lower()

    if response not in ("y", "yes"):
        print("Conversion cancelled.")
        return False

    # Create backup
    backup_file = f"{config}.backup"

    shutil.copy2(config, backup_file)
    print(f"Created backup: {backup_file}")

    # Read and update the file
    lines = []
    with open(config) as f:
        for line in csv.DictReader(f, fieldnames=FIELDS):
            name, action, timer, enabled = line.values()

            # Check if this line needs updating
            for update_name, old_action, new_action in updates:
                if name == update_name and action == old_action:
                    action = new_action
                    break

            lines.append([name, action, timer, enabled])

    # Write updated file
    with open(config, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(lines)

    print(f"Successfully converted {len(updates)} pattern(s).")
    print("Updated schedule file. The scheduler will use the new patterns on next run.")
    return True


def scheduled(args):
    # Handle auto-convert option
    if getattr(args, "auto_convert_old_patterns", False):
        return _auto_convert_old_patterns()

    if args.action == "list":
        urlpath = "/VolumeDriver.Schedule.List"
        resp = Session().get(f"http+unix://{urllib.parse.quote_plus(USOCKET)}{urlpath}")
        scheduled = get_from(resp, "Schedule")
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
                        warning = validate_purge_pattern(pattern, allow_backward_compat=True)
                        if warning:
                            deprecated_patterns.append((job["Name"], action, pattern))
                            status += " (deprecated pattern)"
                    except Exception:
                        pass

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
        resp = Session().post(
            f"http+unix://{urllib.parse.quote_plus(USOCKET)}/VolumeDriver.Schedule.Pause",
        )
        return get_from(resp, "")
    elif args.action == "resume":
        resp = Session().post(
            f"http+unix://{urllib.parse.quote_plus(USOCKET)}/VolumeDriver.Schedule.Resume",
        )
        return get_from(resp, "")


def snapshots(args):
    resp = Session().get(
        f"http+unix://{urllib.parse.quote_plus(USOCKET)}/VolumeDriver.Snapshot.List/{args.name}",
    )
    snapshots = get_from(resp, "Snapshots")
    if snapshots:
        print("\n".join(snapshots))
    return snapshots


def restore(args):
    resp = Session().post(
        f"http+unix://{urllib.parse.quote_plus(USOCKET)}/VolumeDriver.Snapshot.Restore",
        json.dumps({"Name": args.name[0], "Target": args.target}),
    )
    res = get_from(resp, "VolumeBackup")
    if res:
        print(res)
    return res


def clone(args):
    resp = Session().post(
        f"http+unix://{urllib.parse.quote_plus(USOCKET)}/VolumeDriver.Clone",
        json.dumps({"Name": args.name[0], "Target": args.target}),
    )
    res = get_from(resp, "VolumeCloned")
    if res:
        print(res)
    return res


def send(args, test=False):
    urlpath = "/VolumeDriver.Snapshot.Send"
    param = {"Name": args.snapshot[0], "Host": args.host[0]}
    if test:
        param["Test"] = True
        resp = TestApp(app).post(urlpath, json.dumps(param))
    else:
        resp = Session().post(
            f"http+unix://{urllib.parse.quote_plus(USOCKET)}{urlpath}",
            json.dumps(param),
        )
    res = get_from(resp, "")
    if res:
        print(res)
    return res


def sync(args, test=False):
    urlpath = "/VolumeDriver.Volume.Sync"
    param = {"Volumes": args.volumes, "Hosts": args.hosts}
    if test:
        param["Test"] = True
        resp = TestApp(app).post(urlpath, json.dumps(param))
    else:
        resp = Session().post(
            f"http+unix://{urllib.parse.quote_plus(USOCKET)}{urlpath}",
            json.dumps(param),
        )
    res = get_from(resp, "")
    if res:
        print(res)
    return res


def remove(args):
    urlpath = "/VolumeDriver.Snapshot.Remove"
    param = json.dumps({"Name": args.name[0]})
    resp = Session().post((f"http+unix://{urllib.parse.quote_plus(USOCKET)}{urlpath}"), param)
    res = get_from(resp, "")
    if res:
        print(res)
    return res


def purge(args, test=False):
    urlpath = "/VolumeDriver.Snapshots.Purge"
    param = {"Name": args.name[0], "Pattern": args.pattern[0], "Dryrun": args.dryrun}
    if test:
        param["Test"] = True
        resp = TestApp(app).post(urlpath, json.dumps(param))
    else:
        resp = Session().post(
            f"http+unix://{urllib.parse.quote_plus(USOCKET)}{urlpath}",
            json.dumps(param),
        )
    res = get_from(resp, "")
    if res:
        print(res)
    return res


class Arg:
    def __init__(self, *_, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def runjobs(config=SCHEDULE, test=False, schedule_log=None, timer=TIMER):
    if schedule_log is None:
        schedule_log = {"snapshot": {}, "replicate": {}, "synchronize": {}}
    if exists(SCHEDULE_DISABLED):
        log.info("Schedule is globally paused")
    log.info("New scheduler job at %s", datetime.now())
    # open the config and launch the tasks
    if not exists(config):
        if exists(f"{config}.disabled"):
            log.warning("Config file disabled: %s", config)
        else:
            log.warning("No config file %s", config)
        return
    name = action = timer = ""
    # run each action in the schedule if time is elapsed since the last one
    with open(config) as f:
        for line in csv.DictReader(f, fieldnames=FIELDS):
            try:
                name, action, timer, enabled = line.values()
                enabled = enabled != "False"
                if not enabled:
                    log.info(f"{action} of {name} is disabled")
                    continue
                now = datetime.now()
                # just starting, we consider beeing late on snapshots
                schedule_log.setdefault(action, {})
                schedule_log[action].setdefault(name, now - timedelta(1))
                last = schedule_log[action][name]
                if now < last + timedelta(minutes=int(timer)):
                    continue
                if action not in schedule_log:
                    log.warning("Skipping invalid action %s", action)
                    continue
                # choose and run the right action
                if action == "snapshot":
                    log.info("Starting scheduled snapshot of %s", name)
                    snap = snapshot(Arg(name=[name]), test=test)
                    if not snap:
                        log.info("Could not snapshot %s", name)
                        continue
                    log.info("Successfully snapshotted to %s", snap)
                    schedule_log[action][name] = now
                if action.startswith("replicate:"):
                    if name in ReplicationInProgress:
                        log.warning(
                            f"Replication of {name} already in progress, skipping."
                        )
                        continue
                    _, host = action.split(":")
                    log.info("Starting scheduled replication of %s", name)
                    try:
                        ReplicationInProgress.add(name)
                        snap = snapshot(Arg(name=[name]), test=test)
                        if not snap:
                            log.info("Could not snapshot %s", name)
                            continue
                        log.info("Successfully snapshotted to %s", snap)
                        send(Arg(snapshot=[snap], host=[host]), test=test)
                        log.info("Successfully replicated %s to %s", name, snap)
                        schedule_log[action][name] = now
                    except Exception as e:
                        log.warning("Replication failed: %s", e)
                        # remove snapshot that was created for the failed replication
                        if snap:
                            remove(Arg(name=[snap]), test=test)
                            log.info("Removed snapshot %s for failed replication", snap)
                    finally:
                        ReplicationInProgress.remove(name)
                if action.startswith("purge:"):
                    _, pattern = action.split(":", 1)
                    log.info(
                        "Starting scheduled purge of %s with pattern %s",
                        name,
                        pattern,
                    )

                    # Check for deprecated patterns and warn, but continue execution
                    try:
                        warning = validate_purge_pattern(pattern, allow_backward_compat=True)
                        if warning:
                            log.warning(warning)
                            # Use the converted pattern
                            actual_pattern = convert_purge_pattern(pattern)
                        else:
                            actual_pattern = pattern
                    except Exception as e:
                        log.error(f"Invalid purge pattern '{pattern}': {e}")
                        continue

                    purge(Arg(name=[name], pattern=[actual_pattern], dryrun=False), test=test)
                    log.info("Finished purging")
                    schedule_log[action][name] = now
                if action.startswith("synchronize:"):
                    log.info("Starting scheduled synchronization of %s", name)
                    hosts = action.split(":")[1].split(",")
                    # do a snapshot to save state before pulling data
                    snap = snapshot(Arg(name=[name]), test=test)
                    log.debug("Successfully snapshotted to %s", snap)
                    sync(Arg(volumes=[name], hosts=hosts), test=test)
                    log.debug("End of %s synchronization from %s", name, hosts)
                    schedule_log[action][name] = now
            except CalledProcessError as e:
                log.error(
                    "Error processing scheduler action file %s "
                    "name=%s, action=%s, timer=%s, "
                    "exception=%s, stdout=%s, stderr=%s",
                    config,
                    name,
                    action,
                    timer,
                    str(e),
                    e.stdout,
                    e.stderr,
                )
            except Exception as e:
                log.error(
                    "Error processing scheduler action file %s name=%s, action=%s, timer=%s\n%s",
                    config,
                    name,
                    action,
                    timer,
                    str(e),
                )


def scheduler(event, config=SCHEDULE, test=False, timer=TIMER):
    """Read the scheduler config and apply it, then run scheduler again."""
    log.info(f"Starting the scheduler thread. Next jobs will run in {timer} seconds")
    schedule_log = {"snapshot": {}, "replicate": {}, "synchronize": {}}
    while not test and not event.is_set():
        if event.wait(timeout=float(timer)):
            log.info("Terminating the scheduler thread")
            return
        else:
            try:
                runjobs(config, test, schedule_log=schedule_log, timer=timer)
            except Exception:
                log.critical("An exception occured in the scheduling job")
                log.critical(traceback.format_exc())


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


def init_btrfs(args):
    """Initialize BTRFS filesystem for buttervolume"""
    # Default path if no arguments provided
    target_path = "/var/lib/buttervolume"

    if args.file:
        # Mode 1: Create BTRFS image file
        if args.path:
            print("ERROR: --file and --path cannot be used together")
            return False

        image_path = args.file
        image_size = args.size

        print(f"Creating BTRFS image file: {image_path} (size: {image_size})")

        # Check if we can write to the target directory
        parent_dir = os.path.dirname(image_path)
        if not os.access(parent_dir, os.W_OK):
            print(f"ERROR: No write permission to directory: {parent_dir}")
            if parent_dir.startswith(("/var/", "/etc/", "/usr/")):
                print("Try running as root or choose a path in your home directory")
            return False

        # Create the directory if it doesn't exist
        try:
            os.makedirs(parent_dir, exist_ok=True)
        except PermissionError:
            print(f"ERROR: Permission denied creating directory: {parent_dir}")
            print("Try running as root or choose a path in your home directory")
            return False

        try:
            # Create sparse file
            subprocess.run(["truncate", "-s", image_size, image_path], check=True)

            # Format as BTRFS
            subprocess.run(["/usr/sbin/mkfs.btrfs", "-f", image_path], check=True)

            print(f"Successfully created BTRFS image: {image_path}")
            print(f"To use it, mount it to {target_path}:")
            print(f"  sudo mount -o loop {image_path} {target_path}")

        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to create BTRFS image: {e}")
            return False
    elif args.path:
        # Mode 2: Use existing BTRFS partition/mount
        target_path = args.path

        if not os.path.exists(target_path):
            print(f"ERROR: Path does not exist: {target_path}")
            return False

        # Check if we need root for this path
        if target_path.startswith(("/var/", "/etc/", "/usr/")) and os.geteuid() != 0:
            print("ERROR: Root privileges required for system paths")
            print("Try running with sudo or use --file with a user-owned path")
            return False

        # Check if it's a BTRFS filesystem
        try:
            result = subprocess.run(
                ["stat", "-f", "-c", "%T", target_path], capture_output=True, text=True, check=True
            )
            if "btrfs" not in result.stdout.lower():
                print(f"ERROR: {target_path} is not on a BTRFS filesystem")
                print("Either:")
                print("  - Point to a BTRFS partition/mount using --path")
                print("  - Create a BTRFS image file using --file")
                return False
        except subprocess.CalledProcessError:
            print(f"ERROR: Cannot determine filesystem type for {target_path}")
            return False

    else:
        # Mode 3: Default path - check if it's BTRFS
        # Default path requires root
        if os.geteuid() != 0:
            print("ERROR: Root privileges required for default path /var/lib/buttervolume")
            print("Either:")
            print("  - Run with sudo")
            print("  - Use --file ~/my-btrfs.img to create an image in your home directory")
            return False

        if not os.path.exists(target_path):
            print(f"ERROR: Default path does not exist: {target_path}")
            print("Either:")
            print("  - Point to a BTRFS partition/mount using --path")
            print("  - Create a BTRFS image file using --file")
            return False

        # Check if it's a BTRFS filesystem
        try:
            result = subprocess.run(
                ["stat", "-f", "-c", "%T", target_path], capture_output=True, text=True, check=True
            )
            if "btrfs" not in result.stdout.lower():
                print(f"ERROR: {target_path} is not on a BTRFS filesystem")
                print("Either:")
                print("  - Point to a BTRFS partition/mount using --path")
                print("  - Create a BTRFS image file using --file")
                return False
        except subprocess.CalledProcessError:
            print(f"ERROR: Cannot determine filesystem type for {target_path}")
            return False

    # Create required directories (only if we have a valid BTRFS path)
    if not args.file:  # Don't create dirs for image file mode
        required_dirs = [
            os.path.join(target_path, "volumes"),
            os.path.join(target_path, "snapshots"),
            os.path.join(target_path, "config"),
            os.path.join(target_path, "ssh"),
        ]

        print(f"Creating required directories in {target_path}...")
        for dir_path in required_dirs:
            os.makedirs(dir_path, exist_ok=True)
            print(f"  Created: {dir_path}")

        print(f"Successfully initialized buttervolume at {target_path}")
        print("You can now start the plugin with: buttervolume run")

    return True


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
