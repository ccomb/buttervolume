import argparse
import csv
import json
import logging
import os
import signal
import sys
import threading
import traceback
import urllib.parse
from datetime import datetime, timedelta
from os.path import dirname, join, realpath
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
)

VERSION = open(join(dirname(realpath(__file__)), "VERSION")).read().strip()
logging.basicConfig(level=LOGLEVEL)
log = logging.getLogger()
app = app()


class Session(object):
    """wrapper for requests_unixsocket.Session"""

    def __init__(self):
        self.session = requests_unixsocket.Session()

    def post(self, *a, **kw):
        try:
            return self.session.post(*a, **kw)
        except ConnectionError:
            log.error(
                "Failed to connect to Buttervolume. "
                "You can start it with: buttervolume run"
            )
            return

    def get(self, *a, **kw):
        try:
            return self.session.get(*a, **kw)
        except ConnectionError:
            log.error(
                "Failed to connect to Buttervolume. "
                "You can start it with: buttervolume run"
            )


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
        resp = Session().post(
            "http+unix://{}{}".format(urllib.parse.quote_plus(USOCKET), urlpath), param
        )
    res = get_from(resp, "Snapshot")
    if res:
        print(res)
    return res


def schedule(args):
    urlpath = "/VolumeDriver.Schedule"
    param = json.dumps(
        {"Name": args.name[0], "Action": args.action[0], "Timer": args.timer[0]}
    )
    resp = Session().post(
        "http+unix://{}{}".format(urllib.parse.quote_plus(USOCKET), urlpath), param
    )
    return get_from(resp, "")


def scheduled(args):
    if args.action == "list":
        urlpath = "/VolumeDriver.Schedule.List"
        resp = Session().get(
            "http+unix://{}{}".format(urllib.parse.quote_plus(USOCKET), urlpath)
        )
        scheduled = get_from(resp, "Schedule")
        if scheduled:
            print(
                "\n".join(
                    [
                        f"{job['Action']} {job['Timer']} {job['Name']} {'(paused)' if job.get('Active')=='False' else ''}"
                        for job in scheduled
                    ]
                )
            )
        return scheduled
    elif args.action == "pause":
        resp = Session().post(
            "http+unix://{}/VolumeDriver.Schedule.Pause".format(
                urllib.parse.quote_plus(USOCKET)
            ),
        )
        return get_from(resp, "")
    elif args.action == "resume":
        resp = Session().post(
            "http+unix://{}/VolumeDriver.Schedule.Resume".format(
                urllib.parse.quote_plus(USOCKET)
            ),
        )
        return get_from(resp, "")


def snapshots(args):
    resp = Session().get(
        "http+unix://{}/VolumeDriver.Snapshot.List/{}".format(
            urllib.parse.quote_plus(USOCKET), args.name
        ),
    )
    snapshots = get_from(resp, "Snapshots")
    if snapshots:
        print("\n".join(snapshots))
    return snapshots


def restore(args):
    resp = Session().post(
        "http+unix://{}/VolumeDriver.Snapshot.Restore".format(
            urllib.parse.quote_plus(USOCKET)
        ),
        json.dumps({"Name": args.name[0], "Target": args.target}),
    )
    res = get_from(resp, "VolumeBackup")
    if res:
        print(res)
    return res


def clone(args):
    resp = Session().post(
        "http+unix://{}/VolumeDriver.Clone".format(urllib.parse.quote_plus(USOCKET)),
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
            "http+unix://{}{}".format(urllib.parse.quote_plus(USOCKET), urlpath),
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
            "http+unix://{}{}".format(urllib.parse.quote_plus(USOCKET), urlpath),
            json.dumps(param),
        )
    res = get_from(resp, "")
    if res:
        print(res)
    return res


def remove(args):
    urlpath = "/VolumeDriver.Snapshot.Remove"
    param = json.dumps({"Name": args.name[0]})
    resp = Session().post(
        ("http+unix://{}{}").format(urllib.parse.quote_plus(USOCKET), urlpath), param
    )
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
            "http+unix://{}{}".format(urllib.parse.quote_plus(USOCKET), urlpath),
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
    if os.path.exists(SCHEDULE_DISABLED):
        log.info("Schedule is globally paused")
    log.info("New scheduler job at %s", datetime.now())
    # open the config and launch the tasks
    if not os.path.exists(config):
        if os.path.exists(f"{config}.disabled"):
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
                enabled = False if enabled == "False" else True
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
                if action not in schedule_log.keys():
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
                    _, host = action.split(":")
                    log.info("Starting scheduled replication of %s", name)
                    snap = snapshot(Arg(name=[name]), test=test)
                    if not snap:
                        log.info("Could not snapshot %s", name)
                        continue
                    log.info("Successfully snapshotted to %s", snap)
                    send(Arg(snapshot=[snap], host=[host]), test=test)
                    log.info("Successfully replicated %s to %s", name, snap)
                    schedule_log[action][name] = now
                if action.startswith("purge:"):
                    _, pattern = action.split(":", 1)
                    log.info(
                        "Starting scheduled purge of %s with pattern %s",
                        name,
                        pattern,
                    )
                    purge(Arg(name=[name], pattern=[pattern], dryrun=False), test=test)
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
                    "Error processing scheduler action file %s "
                    "name=%s, action=%s, timer=%s\n%s",
                    config,
                    name,
                    action,
                    timer,
                    str(e),
                )


def scheduler(event, config=SCHEDULE, test=False, timer=TIMER):
    """Read the scheduler config and apply it, then run scheduler again."""
    log.info(f"Starting the scheduler thread. Next jobs will run in {timer} seconds")
    while not test and not event.is_set():
        if event.wait(timeout=float(timer)):
            log.info("Terminating the scheduler thread")
            return
        else:
            try:
                runjobs(config, test, timer=timer)
            except Exception:
                log.critical("An exception occured in the scheduling job")
                log.critical(traceback.format_exc())


def shutdown(thread, event):
    log.info("Shutting down buttervolume...")
    event.set()
    thread.join()
    
    # Clean up the socket file to prevent Docker from hanging
    if os.path.exists(SOCKET):
        try:
            os.unlink(SOCKET)
            log.info("Cleaned up socket: %s", SOCKET)
        except OSError as e:
            log.warning("Could not remove socket %s: %s", SOCKET, e)
    
    sys.exit(0)  # Use exit code 0 for clean shutdown


def run(_, test=False):
    if not os.path.exists(VOLUMES_PATH):
        log.info("Creating %s", VOLUMES_PATH)
        os.makedirs(VOLUMES_PATH, exist_ok=True)
    if not os.path.exists(SNAPSHOTS_PATH):
        log.info("Creating %s", SNAPSHOTS_PATH)
        os.makedirs(SNAPSHOTS_PATH, exist_ok=True)

    # Clean up any stale socket from previous unclean shutdown
    if os.path.exists(SOCKET):
        try:
            os.unlink(SOCKET)
            log.info("Removed stale socket: %s", SOCKET)
        except OSError as e:
            log.warning("Could not remove stale socket %s: %s", SOCKET, e)

    # run a thread for the scheduled jobs
    print("Starting scheduler job every {}s".format(TIMER))
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
    print("Listening to requests on %s..." % SOCKET)
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
        help="Schedule, unschedule, pause or resume a periodic snapshot, replication, synchronization or purge",
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
        help="Time span in minutes between two actions. Or: '0' (or 'delete') to 'remove' the schedule, 'pause' to pause, 'resume' to resume",
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
        help=(
            "Name of the action on the scheduled list "
            "(list, pause, resume). Default: list"
        ),
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
    parser_send.add_argument(
        "host", metavar="host", nargs=1, help="Host to send the snapshot to"
    )
    parser_send.add_argument(
        "snapshot", metavar="snapshot", nargs=1, help="Snapshot to send"
    )

    parser_sync = subparsers.add_parser("sync", help="Sync a volume from other host(s)")
    parser_sync.add_argument(
        "volumes", metavar="volumes", nargs=1, help="Volumes to sync (1 max)"
    )
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
    parser_purge = subparsers.add_parser(
        "purge", help="Purge old snapshot using a purge pattern"
    )
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

    args = parser.parse_args()
    if hasattr(args, "func"):
        if args.func(args) is False:
            sys.exit(1)
    else:
        parser.print_help()
