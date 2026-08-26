"""The Docker Volume Plugin HTTP API, and where a name becomes a path.

Every endpoint is a module-level ``@route(...)`` below, and that list of
decorators is the authoritative route list. ``@route`` is defined here too, and
is not Bottle's: it decodes the request, logs it, and turns any failure into
the ``Err`` field of a 200 answer, which is the only shape a client can read.

This is also where the directories are configured, so this is where a name
turns into a path on disk, and where it is validated as it does. What a name is
worth is decided in ``names.py``, what a retention pattern says in ``purge.py``,
what a scheduled action asks for in ``schedule.py``; all three are pure and know
nothing of these directories.
"""

import configparser
import csv
import json
import logging
import os
import subprocess
import tempfile
import time
from datetime import datetime
from functools import wraps
from os.path import basename, dirname, join
from subprocess import run

from bottle import request
from bottle import route as bottle_route

from buttervolume import (
    ReplicationError,
    ReplicationTimeoutError,
    SnapshotNotFoundError,
    ValidationError,
    VolumeNotFoundError,
    btrfs,
)
from buttervolume.btrfs import BtrfsError
from buttervolume.names import (
    Snapshot,
    new_snapshot,
    sent_snapshots,
    snapshots_of,
    validate_hostname,
    validate_snapshot_name,
    validate_volume_name,
)
from buttervolume.purge import Pattern, compute_purges
from buttervolume.schedule import Job

config = configparser.ConfigParser()
config.read("/etc/buttervolume/config.ini")


def getconfig(config, var, default):
    """read the var from the environ, then config file, then default"""
    return os.environ.get("BUTTERVOLUME_" + var) or config["DEFAULT"].get(var, default)


# overrideable defaults with config file
VOLUMES_PATH = getconfig(config, "VOLUMES_PATH", "/var/lib/buttervolume/volumes/")
SNAPSHOTS_PATH = getconfig(config, "SNAPSHOTS_PATH", "/var/lib/buttervolume/snapshots/")
TEST_REMOTE_PATH = getconfig(config, "TEST_REMOTE_PATH", "/var/lib/buttervolume/received/")
SCHEDULE = getconfig(config, "SCHEDULE", "/etc/buttervolume/schedule.csv")
SCHEDULE_DISABLED = f"{SCHEDULE}.disabled"
FIELDS = ["Name", "Action", "Timer", "Active"]
# Support both old and new plugin names for backward compatibility
DRIVERNAME = getconfig(config, "DRIVERNAME", "ccomb/buttervolume:latest")
LEGACY_DRIVERNAME = "anybox/buttervolume:latest"
RUNPATH = getconfig(config, "RUNPATH", "/run/docker")
SOCKET = getconfig(config, "SOCKET", os.path.join(RUNPATH, "plugins", "btrfs.sock"))
USOCKET = SOCKET
if not os.path.exists(USOCKET):
    # socket path on the host or another container
    # Try current plugin name first, then legacy name for backward compatibility
    for driver_name in [DRIVERNAME, LEGACY_DRIVERNAME]:
        try:
            plugins = json.loads(
                run(
                    f"docker plugin inspect {driver_name}",
                    shell=True,
                    capture_output=True,
                ).stdout.decode()
                or "[]"
            )
            if plugins:
                plugin = plugins[0]  # can we have several plugins with the same name?
                USOCKET = os.path.join(RUNPATH, "plugins", plugin["Id"], "btrfs.sock")
                break
        except Exception:
            continue  # Try next driver name

TIMER = int(getconfig(config, "TIMER", 60))
# How long each external command may legitimately take, in seconds
SYNC_TIMEOUT = 30
RSYNC_TIMEOUT = 600
# The send crosses the network, so its limit is configurable like the rest
SEND_TIMEOUT = int(getconfig(config, "SEND_TIMEOUT", 600))
DTFORMAT = getconfig(config, "DTFORMAT", "%Y-%m-%dT%H:%M:%S.%f")
LOGLEVEL = getattr(logging, getconfig(config, "LOGLEVEL", "INFO"))

logging.basicConfig(level=LOGLEVEL)
log = logging.getLogger()


def volumepath(name):
    """The path of this volume, whether or not it exists.

    A name becomes a path here and nowhere else, so this is also where it is
    checked: no handler downstream has to remember to do it.
    """
    return join(VOLUMES_PATH, validate_volume_name(name))


def existing_volume(name):
    """The subvolume of this volume, or a clear error when there is none."""
    subvolume = btrfs.Subvolume(volumepath(name))
    if not subvolume.exists():
        raise VolumeNotFoundError(f"Volume '{name}': no such volume")
    return subvolume


def snapshotpath(name):
    """The path of this snapshot, whether or not it exists."""
    return join(SNAPSHOTS_PATH, validate_snapshot_name(name))


def new_snapshot_name(volume_name):
    """Name a new snapshot of this volume, using the configured date format."""
    return str(new_snapshot(volume_name, DTFORMAT, datetime.now()))


def answer(handler, kw):
    """Turn whatever this request does into the response body.

    An error is a non-empty "Err" key, because that is all the client knows
    how to read: nothing here, not even a body that is not JSON, must become
    a 500.
    """
    try:
        req = json.loads(request.body.read().decode() or "{}")
        log.debug("Request: %s %s", request.path, req)
        result = handler(req, **kw)
        return result if isinstance(result, dict) else {"Err": ""}
    except (
        ValidationError,
        VolumeNotFoundError,
        SnapshotNotFoundError,
        ReplicationError,
        BtrfsError,
    ) as e:
        return {"Err": str(e)}
    except Exception as e:
        log.error("Unexpected error in %s: %s", handler.__name__, str(e))
        if hasattr(e, "stderr") and e.stderr:
            return {"Err": e.stderr.decode()}
        return {"Err": f"Unexpected error: {str(e)}"}


def route(path, method="POST"):
    """Serve this path, and hold the contract of the whole API in one place.

    Every endpoint answers 200 with a JSON body where an error is a non-empty
    "Err" key. A handler decorated here receives the decoded request and
    returns the response dict; the decoding, the journal and the error
    contract are no longer its business, so it cannot get them wrong.
    """

    def decorate(handler):
        @bottle_route(path, [method])
        @wraps(handler)
        def serve(**kw):
            resp = json.dumps(answer(handler, kw))
            log.debug("Response: %s", resp)
            return resp

        return serve

    return decorate


def run_btrfs_send_receive(
    snapshot_path, remote_host, remote_snapshots, parent_path=None, port="1122"
):
    """Securely run btrfs send/receive over SSH"""
    # Validate inputs
    validate_hostname(remote_host)

    # First sync the filesystem
    btrfs.run_safe(["btrfs", "filesystem", "sync", SNAPSHOTS_PATH], timeout=SYNC_TIMEOUT)

    # Build btrfs send command
    send_cmd = ["btrfs", "send"]
    if parent_path:
        send_cmd.extend(["-p", parent_path])
    send_cmd.append(snapshot_path)

    # Build SSH receive command
    ssh_cmd = [
        "ssh",
        "-p",
        port,
        "-o",
        "StrictHostKeyChecking=no",
        remote_host,
        f"btrfs receive {remote_snapshots}",
    ]

    # Execute send | ssh receive using subprocess.
    # The send stderr goes to a temporary file rather than a pipe: nobody can
    # read that pipe while waiting for the receive side, and a verbose failure
    # would fill it and deadlock both processes.
    with tempfile.TemporaryFile() as send_stderr_file:
        send_proc = subprocess.Popen(send_cmd, stdout=subprocess.PIPE, stderr=send_stderr_file)
        receive_proc = subprocess.Popen(
            ssh_cmd, stdin=send_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        send_proc.stdout.close()  # Allow send_proc to receive a SIGPIPE if receive_proc exits

        # one deadline for the two waits, so the whole transfer really is
        # bounded by SEND_TIMEOUT and not by twice that
        deadline = time.monotonic() + SEND_TIMEOUT
        try:
            receive_stdout, receive_stderr = receive_proc.communicate(timeout=SEND_TIMEOUT)
            send_proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            send_proc.kill()
            receive_proc.kill()
            send_proc.wait()
            receive_proc.wait()
            send_stderr_file.seek(0)
            raise ReplicationTimeoutError(
                f"btrfs send/receive to {remote_host} timed out after {SEND_TIMEOUT}s: "
                f"{send_stderr_file.read().decode()}"
            ) from None

        if send_proc.returncode != 0 or receive_proc.returncode != 0:
            send_stderr_file.seek(0)
            raise ReplicationError(
                f"btrfs send/receive failed (send: {send_proc.returncode}, "
                f"receive: {receive_proc.returncode}): "
                f"{send_stderr_file.read().decode()} {receive_stderr.decode()}"
            )

    return receive_stdout.decode()


@route("/Plugin.Activate")
def plugin_activate(_):
    return {"Implements": ["VolumeDriver"]}


@route("/VolumeDriver.Create")
def volume_create(req):
    name = req["Name"]
    opts = req.get("Opts", {}) or {}

    volpath = volumepath(name)
    # volume already exists?
    if name in [v["Name"] for v in list_volumes()["Volumes"]]:
        return {"Err": ""}

    cow = opts.get("copyonwrite", "true").lower()
    if cow not in ["true", "false"]:
        raise ValidationError(f'Invalid option for copyonwrite: {cow}. Set to "true" or "false".')

    compression = opts.get("compression", "").lower()
    valid_compression = ["", "false", "true", "zlib", "lzo", "zstd"]
    if compression not in valid_compression:
        return {
            "Err": f"Invalid option for compression: {compression}. Valid options: {', '.join(valid_compression[1:])}"
        }

    btrfs.Subvolume(volpath).create(cow=cow == "true")

    # Enable compression if requested
    if compression and compression != "false":
        try:
            btrfs.run_safe(["chattr", "+c", volpath], timeout=10)
            log.info(f"Enabled compression for volume {name}")
        except Exception as e:
            log.warning(f"Could not enable compression for volume {name}: {e}")
            # Don't fail volume creation if compression setting fails

    return {"Err": ""}


@route("/VolumeDriver.Mount")
def volume_mount(req):
    return {"Mountpoint": existing_volume(req["Name"]).path, "Err": ""}


@route("/VolumeDriver.Path")
def volume_path(req):
    return {"Mountpoint": existing_volume(req["Name"]).path, "Err": ""}


@route("/VolumeDriver.Unmount")
def volume_unmount(_):
    return {"Err": ""}


@route("/VolumeDriver.Get")
def volume_get(req):
    name = req["Name"]
    return {"Volume": {"Name": name, "Mountpoint": existing_volume(name).path}, "Err": ""}


@route("/VolumeDriver.Remove")
def volume_remove(req):
    existing_volume(req["Name"]).delete()
    return {"Err": ""}


@route("/VolumeDriver.List")
def volume_list(_):
    return list_volumes()


def list_volumes():
    volumes = []
    for p in [join(VOLUMES_PATH, v) for v in os.listdir(VOLUMES_PATH) if v != "metadata.db"]:
        if not btrfs.Subvolume(p).exists():
            continue
        volumes.append(p)
    return {"Volumes": [{"Name": basename(v)} for v in volumes], "Err": ""}


@route("/VolumeDriver.Volume.Sync")
def volume_sync(req):
    """Rsync between two nodes"""
    test = req.get("Test", False)
    remote_volumes = VOLUMES_PATH if not test else TEST_REMOTE_PATH
    volumes = req["Volumes"]
    remote_hosts = req["Hosts"]
    port = os.getenv("SSH_PORT", "1122")
    errors = []

    # Validate inputs
    for volume_name in volumes:
        try:
            validate_volume_name(volume_name)
        except ValidationError as e:
            errors.append(f"Invalid volume name {volume_name}: {str(e)}")
            continue

    for remote_host in remote_hosts:
        try:
            validate_hostname(remote_host)
        except ValidationError as e:
            errors.append(f"Invalid hostname {remote_host}: {str(e)}")
            continue

    if errors:
        return {"Err": "\n".join(errors)}

    for volume_name in volumes:
        local_volume_path = volumepath(volume_name)
        remote_volume_path = join(remote_volumes, volume_name)
        for remote_host in remote_hosts:
            log.debug("Rsync volume: %s from host: %s", local_volume_path, remote_host)
            cmd = [
                "rsync",
                "-v",
                "-r",
                "-a",
                "-z",
                "-h",
                "-P",
                "-e",
                f"ssh -p {port} -o StrictHostKeyChecking=no",
                f"{remote_host}:{remote_volume_path}/",
                local_volume_path,
            ]
            log.debug("Running %r", cmd)
            try:
                btrfs.run_safe(cmd, timeout=RSYNC_TIMEOUT)
            except Exception as ex:
                err = getattr(ex, "stderr", str(ex))
                if isinstance(err, bytes):
                    err = err.decode()
                error_message = f"Error while rsync {volume_name} from {remote_host}: {err}"
                log.error(error_message)
                errors.append(error_message)

    return {"Err": "\n".join(errors)}


@route("/VolumeDriver.Capabilities")
def driver_cap(_):
    """butter volumes are local to the active node.
    They only exist as snapshots on the remote nodes.
    """
    return {"Capabilities": {"Scope": "local"}}


@route("/VolumeDriver.Snapshot.Send")
def snapshot_send(req):
    """The last sent snapshot is remembered by adding a suffix with the target"""
    test = req.get("Test", False)
    snapshot_name = req["Name"]
    remote_host = req["Host"]

    snapshot = Snapshot.parse(snapshot_name)
    if snapshot.host:
        # sending a trace would name its own trace, and btrfs would refuse
        # once the transfer is already done
        raise ValidationError(
            f"'{snapshot_name}' is the trace of a send to {snapshot.host}, "
            "not a snapshot that can be sent"
        )
    validate_hostname(remote_host)

    snapshot_path = snapshotpath(snapshot_name)
    remote_snapshots = SNAPSHOTS_PATH if not test else TEST_REMOTE_PATH

    # the previous send to that host left a trace: its snapshot is the parent
    # this one can be sent against
    already_sent = sent_snapshots(snapshot.volume, remote_host, os.listdir(SNAPSHOTS_PATH))
    latest = str(already_sent[-1].without_host()) if already_sent else None
    parent_path = snapshotpath(latest) if latest else None
    port = os.getenv("SSH_PORT", "1122")

    try:
        log.info("Sending snapshot %s to %s", snapshot_path, remote_host)
        run_btrfs_send_receive(snapshot_path, remote_host, remote_snapshots, parent_path, port)
    except ReplicationTimeoutError:
        # the full send below would cross the same stalled link, and wait as
        # long again: a transfer killed for hanging is not retried.
        raise
    except ReplicationError as e:
        log.warning(
            "Failed using parent %s. Sending full snapshot %s: %s", latest, snapshot_path, str(e)
        )
        # Try to remove existing snapshot on remote and send full
        rm_cmd = [
            "ssh",
            "-p",
            port,
            "-o",
            "StrictHostKeyChecking=no",
            remote_host,
            f"btrfs subvolume delete {remote_snapshots}/{snapshot_name} || true",
        ]
        try:
            subprocess.run(rm_cmd, check=False, capture_output=True, timeout=SEND_TIMEOUT)
        except subprocess.TimeoutExpired:
            log.warning("Timed out deleting the remote snapshot %s", snapshot_name)

        # Send without parent
        run_btrfs_send_receive(snapshot_path, remote_host, remote_snapshots, None, port)

    # Create local tracking snapshot
    btrfs.Subvolume(snapshot_path).snapshot(
        snapshotpath(str(snapshot.sent_to(remote_host))), readonly=True
    )

    # Clean up old tracking snapshots
    for old_snapshot in already_sent:
        try:
            btrfs.Subvolume(snapshotpath(str(old_snapshot))).delete()
        except Exception as e:
            log.warning("Failed to delete old snapshot %s: %s", str(old_snapshot), str(e))

    return {"Err": ""}


@route("/VolumeDriver.Snapshot")
def volume_snapshot(req):
    """snapshot a volume in the SNAPSHOTS dir"""
    name = req["Name"]
    volume = existing_volume(name)

    timestamped = new_snapshot_name(name)
    volume.snapshot(snapshotpath(timestamped), readonly=True)
    return {"Err": "", "Snapshot": timestamped}


@route("/VolumeDriver.Snapshot.List", "GET")
def snapshot_list(_):
    snapshots = os.listdir(SNAPSHOTS_PATH)
    return {"Err": "", "Snapshots": snapshots}


@route("/VolumeDriver.Snapshot.List/<name>", "GET")
def snapshot_sublist(_, name=""):
    snapshots = os.listdir(SNAPSHOTS_PATH)
    if name:
        snapshots = snapshots_of(validate_volume_name(name), snapshots)
    return {"Err": "", "Snapshots": snapshots}


@route("/VolumeDriver.Snapshot.Remove")
def snapshot_delete(req):
    name = req["Name"]
    path = snapshotpath(name)
    if not os.path.exists(path):
        raise SnapshotNotFoundError(f"Snapshot '{name}' not found")

    btrfs.Subvolume(path).delete()
    return {"Err": ""}


@route("/VolumeDriver.Schedule")
def schedule(req):
    """Schedule or unschedule a job"""
    name = req["Name"]
    timer = str(req["Timer"])
    action = req["Action"]
    if os.path.exists(SCHEDULE_DISABLED):
        return {"Err": "Schedule is globally paused"}
    if not os.path.exists(SCHEDULE):
        os.makedirs(dirname(SCHEDULE), exist_ok=True)
        with open(SCHEDULE, "w") as f:
            f.write("")
    with open(SCHEDULE) as f:
        schedule = {
            (line["Name"], line["Action"]): line for line in csv.DictReader(f, fieldnames=FIELDS)
        }

    if timer in ("pause", "resume", "0", "delete"):
        # These name a line that is already written, whatever it says: a job
        # this endpoint once accepted must stay possible to pause and to
        # delete. Only the line named is looked at, never the others.
        if (name, action) not in schedule:
            raise ValidationError(f"No '{action}' of '{name}' is scheduled")
        if timer == "pause":
            schedule[(name, action)]["Active"] = False
        elif timer == "resume":
            schedule[(name, action)]["Active"] = True
        else:
            del schedule[(name, action)]
    elif timer.isdecimal() and int(timer) > 0:
        # isdecimal, not isnumeric: "²".isnumeric() is True and int("²")
        # raises, and the scheduler reads this timer back with int()
        validate_volume_name(name)
        Job.parse(action)
        schedule[(name, action)] = {
            "Name": name,
            "Action": action,
            "Timer": timer,
            "Active": True,
        }
    else:
        raise ValidationError(
            f"Invalid timer '{timer}'. It must be a number of minutes, or "
            "'pause', 'resume', or '0' or 'delete' to unschedule"
        )

    with open(SCHEDULE, "w") as f:
        csv.DictWriter(f, fieldnames=FIELDS).writerows(schedule.values())
    return {"Err": ""}


@route("/VolumeDriver.Schedule.List", "GET")
def scheduled(_):
    """List scheduled jobs"""
    if os.path.exists(SCHEDULE_DISABLED):
        return {"Err": "Schedule is globally paused"}
    schedule = []
    if os.path.exists(SCHEDULE):
        with open(SCHEDULE) as f:
            schedule = list(csv.DictReader(f, fieldnames=FIELDS))
    return {"Err": "", "Schedule": schedule}


@route("/VolumeDriver.Schedule.Pause")
def schedule_disable(_):
    """Disable scheduled jobs"""
    if os.path.exists(SCHEDULE):
        os.rename(SCHEDULE, SCHEDULE_DISABLED)
    return {"Err": ""}


@route("/VolumeDriver.Schedule.Resume")
def schedule_enable(_):
    """Enable scheduled jobs"""
    if os.path.exists(SCHEDULE_DISABLED):
        os.rename(SCHEDULE_DISABLED, SCHEDULE)
    return {"Err": ""}


@route("/VolumeDriver.Snapshot.Restore")
def snapshot_restore(req):
    """
    Snapshot a volume and overwrite it with the specified snapshot.
    """
    snapshot_name = req["Name"]
    target_name = req.get("Target")

    if "@" not in snapshot_name:
        # we're passing the name of the volume. Use the latest snapshot.
        volume_name = validate_volume_name(snapshot_name)
        snapshots = snapshots_of(volume_name, os.listdir(SNAPSHOTS_PATH))
        if not snapshots:
            raise SnapshotNotFoundError(f"No snapshots found for volume '{volume_name}'")
        snapshot_name = snapshots[-1]

    snapshot_path = snapshotpath(snapshot_name)
    if not os.path.exists(snapshot_path):
        raise SnapshotNotFoundError(f"Snapshot '{snapshot_name}' not found")

    snapshot = btrfs.Subvolume(snapshot_path)
    target_name = target_name or Snapshot.parse(snapshot_name).volume
    target_path = volumepath(target_name)
    volume = btrfs.Subvolume(target_path)
    res = {"Err": ""}

    if not snapshot.exists():
        raise SnapshotNotFoundError(f"Snapshot '{snapshot_name}' is not a valid BTRFS subvolume")

    if volume.exists():
        # backup and delete
        stamped_name = new_snapshot_name(target_name)
        volume.snapshot(snapshotpath(stamped_name), readonly=True)
        res["VolumeBackup"] = stamped_name
        volume.delete()

    snapshot.snapshot(target_path)
    return res


@route("/VolumeDriver.Clone")
def snapshot_clone(req):
    """
    Create a new volume as clone from another.
    """
    volumename = req["Name"]
    targetname = req.get("Target")

    volume = existing_volume(volumename)
    targetpath = volumepath(targetname)

    # Check if target already exists
    target_volume = btrfs.Subvolume(targetpath)
    if target_volume.exists():
        raise ValidationError(f"Target volume '{targetname}' already exists")

    volume.snapshot(targetpath)
    return {"Err": "", "VolumeCloned": targetname}


@route("/VolumeDriver.Snapshots.Purge")
def snapshots_purge(req):
    """
    Purge snapshots with a retention pattern
    (see cli help)
    """
    volume_name = validate_volume_name(req["Name"])
    dryrun = req.get("Dryrun", False)

    pattern = Pattern.parse(req["Pattern"])
    # An immediate purge refuses the old duplicate spelling instead of guessing
    if pattern.deprecated:
        raise ValidationError(
            f"Invalid pattern '{pattern.deprecated}'. "
            f"Use '{pattern.text}' instead of duplicate components."
        )

    snapshots = snapshots_of(volume_name, os.listdir(SNAPSHOTS_PATH))
    purge_list = compute_purges(snapshots, pattern, datetime.now(), DTFORMAT)

    for snapshot in purge_list:
        if dryrun:
            log.info(f"(Dry run) Would delete snapshot {snapshot}")
        else:
            # Delete the BTRFS subvolume (xattrs are automatically deleted with it)
            btrfs.Subvolume(snapshotpath(snapshot)).delete()
            log.info(f"Deleted snapshot {snapshot}")

    return {"Err": ""}
