"""How to reach the plugin: one function per endpoint, over the unix socket.

Docker talks to the plugin through that socket, and so does everything else
here: the command line and the scheduler are clients of the same API and read
the same answers. This module is where that call is written, once, so nobody
else has to know the socket path or how an answer is shaped.

Each function takes what the endpoint needs and answers what it said, never an
argparse namespace: printing belongs to ``cli.py`` and deciding to
``scheduler.py``. A call that failed says so and has already been logged, so a
caller can act on it without reading the exception.

The ``test`` flag routes the same call through the Bottle application in this
process instead of the socket, which is how the test suite exercises a whole
command without a daemon. Whether it also travels in the payload is decided
endpoint by endpoint, and copied here from what each one sent before: the send
and the synchronization put it there and ``plugin.py`` reads it, to reach the
next directory rather than another machine. The purge puts it there too and
nobody reads it, which is left exactly as it was found rather than tidied up
in a change that promises to alter nothing.
"""

import json
import logging
import os
import urllib.parse

import requests_unixsocket
from bottle import app
from requests.exceptions import ConnectionError
from webtest import TestApp

import buttervolume.plugin  # noqa: F401  this import is what posts the routes
from buttervolume.config import USOCKET

log = logging.getLogger()

# The Bottle application the plugin has posted its routes on. Importing
# plugin.py is what puts them there, and nothing else in the daemon imports it:
# without the line above, `buttervolume run` serves an application without a
# single route, and says nothing. The test suite cannot see that, because it
# imports plugin.py on its own, which is why one test starts a fresh
# interpreter to check it.
app = app()


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


def _url(urlpath):
    return f"http+unix://{urllib.parse.quote_plus(USOCKET)}{urlpath}"


def _post(urlpath, payload=None, test=False):
    body = json.dumps(payload) if payload is not None else None
    if test:
        return TestApp(app).post(urlpath, body)
    return Session().post(_url(urlpath), body)


def _get(urlpath):
    return Session().get(_url(urlpath))


def snapshot(name, test=False):
    """Snapshot a volume, and answer its name and whether this call took it.

    A volume nobody wrote to is not snapshotted again, so the name can be that
    of a snapshot an earlier round took: a caller that deletes what it created
    has to know which of the two it is holding. A call that failed answers
    False twice, and has already said why.
    """
    resp = _post("/VolumeDriver.Snapshot", {"Name": name}, test)
    snap = get_from(resp, "Snapshot")
    # read a second time only once the first read said the answer carries no
    # error, otherwise the error would be logged twice
    return snap, bool(snap) and get_from(resp, "Created")


def snapshots(name):
    """The snapshots of a volume, or of every volume when the name is empty."""
    return get_from(_get(f"/VolumeDriver.Snapshot.List/{name}"), "Snapshots")


def restore(name, target=None):
    """Restore a snapshot over its volume, and answer where the volume went."""
    return get_from(
        _post("/VolumeDriver.Snapshot.Restore", {"Name": name, "Target": target}),
        "VolumeBackup",
    )


def clone(name, target=None):
    """Clone a snapshot into a new volume, and answer its name."""
    return get_from(_post("/VolumeDriver.Clone", {"Name": name, "Target": target}), "VolumeCloned")


def send(snapshot, host, test=False):
    """Send a snapshot to another host, and answer whether it went."""
    payload = {"Name": snapshot, "Host": host}
    if test:
        # the plugin reads it to send the snapshot next door rather than to
        # another machine
        payload["Test"] = True
    return get_from(_post("/VolumeDriver.Snapshot.Send", payload, test), "") is not False


def receive(volume, host, test=False):
    """Fetch the last snapshot another host has of a volume, and answer its name."""
    payload = {"Name": volume, "Host": host}
    if test:
        # the plugin reads it to fetch the snapshot from next door rather than
        # from another machine
        payload["Test"] = True
    return get_from(_post("/VolumeDriver.Snapshot.Receive", payload, test), "Snapshot")


def sync(volumes, hosts, test=False):
    """Pull these volumes back from these hosts, and answer whether it went."""
    payload = {"Volumes": volumes, "Hosts": hosts}
    if test:
        payload["Test"] = True
    return get_from(_post("/VolumeDriver.Volume.Sync", payload, test), "") is not False


def remove(name, test=False):
    """Delete a snapshot, and answer whether it was deleted."""
    return get_from(_post("/VolumeDriver.Snapshot.Remove", {"Name": name}, test), "") is not False


def purge(name, pattern, dryrun=False, test=False):
    """Delete the snapshots this pattern does not keep, and answer whether it went."""
    payload = {"Name": name, "Pattern": pattern, "Dryrun": dryrun}
    if test:
        payload["Test"] = True
    return get_from(_post("/VolumeDriver.Snapshots.Purge", payload, test), "") is not False


def schedule(name, action, timer):
    """Add, pause, resume or remove a scheduled job."""
    return get_from(
        _post("/VolumeDriver.Schedule", {"Name": name, "Action": action, "Timer": timer}), ""
    )


def scheduled():
    """Every line of the schedule, as the file holds it."""
    return get_from(_get("/VolumeDriver.Schedule.List"), "Schedule")


def schedule_pause():
    """Stop running anything the schedule asks for."""
    return get_from(_post("/VolumeDriver.Schedule.Pause"), "")


def schedule_resume():
    """Run again what the schedule asks for."""
    return get_from(_post("/VolumeDriver.Schedule.Resume"), "")
