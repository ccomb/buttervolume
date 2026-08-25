import configparser
import csv
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from datetime import datetime
from functools import wraps
from os.path import basename, dirname, join
from subprocess import run

from bottle import request
from bottle import route as bottle_route

from buttervolume import btrfs
from buttervolume.btrfs import BtrfsError


# Custom exceptions for better error handling
class ButtervolumeError(Exception):
    """Base exception for Buttervolume errors"""

    pass


class VolumeNotFoundError(ButtervolumeError):
    """Raised when a volume is not found"""

    pass


class SnapshotNotFoundError(ButtervolumeError):
    """Raised when a snapshot is not found"""

    pass


class ValidationError(ButtervolumeError):
    """Raised when input validation fails"""

    pass


class ReplicationError(ButtervolumeError):
    """Raised when replication fails"""

    pass


class ReplicationTimeoutError(ReplicationError):
    """Raised when a replication is killed for taking too long"""

    pass


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


def validate_volume_name(name):
    """Validate volume name for security and correctness"""
    if not name:
        raise ValidationError("Volume name cannot be empty")

    if "@" in name:
        raise ValidationError('"@" is illegal in a volume name')

    # Check for path traversal
    if ".." in name or name.startswith("/"):
        raise ValidationError("Invalid characters in volume name")

    # Check for dangerous shell characters
    dangerous_chars = [
        "`",
        "$",
        "|",
        "&",
        ";",
        ">",
        "<",
        "*",
        "?",
        "[",
        "]",
        "(",
        ")",
        "{",
        "}",
        "\\",
    ]
    if any(char in name for char in dangerous_chars):
        raise ValidationError("Volume name contains dangerous characters")

    # Ensure reasonable length
    if len(name) > 255:
        raise ValidationError("Volume name too long")

    # Only allow alphanumeric, dash, underscore, dot
    if not re.fullmatch(r"[a-zA-Z0-9._-]+", name):
        raise ValidationError("Volume name contains invalid characters")

    return name


def validate_snapshot_name(name):
    """Validate a snapshot name: volume@timestamp, plus @host for sent snapshots.

    Snapshot names come from Docker or from a remote host and end up in a
    path and in a shell command, so they get the same care as volume names.
    """
    if not name:
        raise ValidationError("Snapshot name cannot be empty")

    if len(name) > 255:
        raise ValidationError("Snapshot name too long")

    parts = name.split("@")
    if len(parts) not in (2, 3):
        raise ValidationError("Invalid snapshot name format")

    validate_volume_name(parts[0])
    for part in parts[1:]:
        if not part or not re.fullmatch(r"[a-zA-Z0-9.:_-]+", part):
            raise ValidationError("Snapshot name contains invalid characters")

    return name


def new_snapshot_name(volume_name):
    """Name a new snapshot of this volume, as the API will have to read it back.

    DTFORMAT is configurable, so a format holding a space or a plus sign would
    build a name the validation above rejects: the snapshot would exist and no
    endpoint could name it again. Better to refuse to create it.
    """
    return validate_snapshot_name(f"{volume_name}@{datetime.now().strftime(DTFORMAT)}")


def validate_hostname(hostname):
    """Validate hostname for SSH operations"""
    if not hostname:
        raise ValidationError("Hostname cannot be empty")

    # Basic hostname validation
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", hostname):
        raise ValidationError("Invalid hostname format")

    if len(hostname) > 253:
        raise ValidationError("Hostname too long")

    return hostname


def answer(handler, req, kw):
    """Turn whatever the handler does into the response body.

    An error is a non-empty "Err" key, because that is all the client knows
    how to read: a handler that raises must not become a 500.
    """
    try:
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
            req = json.loads(request.body.read().decode() or "{}")
            log.debug("Request: %s %s", request.path, req)
            resp = json.dumps(answer(handler, req, kw))
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

    validate_volume_name(name)

    volpath = join(VOLUMES_PATH, name)
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


def volumepath(name):
    path = join(VOLUMES_PATH, name)
    if not btrfs.Subvolume(path).exists():
        raise VolumeNotFoundError(f"Volume '{name}': no such volume")
    return path


@route("/VolumeDriver.Mount")
def volume_mount(req):
    name = req["Name"]
    validate_volume_name(name)
    path = volumepath(name)
    return {"Mountpoint": path, "Err": ""}


@route("/VolumeDriver.Path")
def volume_path(req):
    name = req["Name"]
    validate_volume_name(name)
    path = volumepath(name)
    return {"Mountpoint": path, "Err": ""}


@route("/VolumeDriver.Unmount")
def volume_unmount(_):
    return {"Err": ""}


@route("/VolumeDriver.Get")
def volume_get(req):
    name = req["Name"]
    validate_volume_name(name)
    path = volumepath(name)
    return {"Volume": {"Name": name, "Mountpoint": path}, "Err": ""}


@route("/VolumeDriver.Remove")
def volume_remove(req):
    name = req["Name"]
    validate_volume_name(name)
    path = join(VOLUMES_PATH, name)
    if not btrfs.Subvolume(path).exists():
        raise VolumeNotFoundError(f"Volume '{name}': no such volume")
    btrfs.Subvolume(path).delete()
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
        local_volume_path = join(VOLUMES_PATH, volume_name)
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

    validate_snapshot_name(snapshot_name)
    validate_hostname(remote_host)

    snapshot_path = join(SNAPSHOTS_PATH, snapshot_name)
    remote_snapshots = SNAPSHOTS_PATH if not test else TEST_REMOTE_PATH

    # take the latest snapshot suffixed with the target host
    sent_snapshots = sorted(
        [
            s
            for s in os.listdir(SNAPSHOTS_PATH)
            if len(s.split("@")) == 3
            and s.split("@")[0] == snapshot_name.split("@")[0]
            and s.split("@")[2] == remote_host
        ]
    )
    latest = sent_snapshots[-1] if len(sent_snapshots) > 0 else None
    if latest and len(latest.rsplit("@")) == 3:
        latest = latest.rsplit("@", 1)[0]

    parent_path = join(SNAPSHOTS_PATH, latest) if latest else None
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
    btrfs.Subvolume(snapshot_path).snapshot(f"{snapshot_path}@{remote_host}", readonly=True)

    # Clean up old tracking snapshots
    for old_snapshot in sent_snapshots:
        try:
            btrfs.Subvolume(join(SNAPSHOTS_PATH, old_snapshot)).delete()
        except Exception as e:
            log.warning("Failed to delete old snapshot %s: %s", old_snapshot, str(e))

    return {"Err": ""}


@route("/VolumeDriver.Snapshot")
def volume_snapshot(req):
    """snapshot a volume in the SNAPSHOTS dir"""
    name = req["Name"]
    validate_volume_name(name)

    path = join(VOLUMES_PATH, name)
    if not os.path.exists(path) or not btrfs.Subvolume(path).exists():
        raise VolumeNotFoundError(f"Volume '{name}': no such volume")

    timestamped = new_snapshot_name(name)
    snapshot_path = join(SNAPSHOTS_PATH, timestamped)

    btrfs.Subvolume(path).snapshot(snapshot_path, readonly=True)
    return {"Err": "", "Snapshot": timestamped}


@route("/VolumeDriver.Snapshot.List", "GET")
def snapshot_list(_):
    snapshots = os.listdir(SNAPSHOTS_PATH)
    return {"Err": "", "Snapshots": snapshots}


@route("/VolumeDriver.Snapshot.List/<name>", "GET")
def snapshot_sublist(_, name=""):
    # Validate volume name if provided
    if name:
        validate_volume_name(name)

    snapshots = os.listdir(SNAPSHOTS_PATH)
    if name:
        snapshots = [s for s in snapshots if s.startswith(name + "@")]
    return {"Err": "", "Snapshots": snapshots}


@route("/VolumeDriver.Snapshot.Remove")
def snapshot_delete(req):
    name = req["Name"]
    validate_snapshot_name(name)

    path = join(SNAPSHOTS_PATH, name)
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
        if timer == "pause" and (name, action) in schedule:
            schedule[(name, action)]["Active"] = False
        elif timer == "resume" and (name, action) in schedule:
            schedule[(name, action)]["Active"] = True
        elif timer in ("0", "delete") and (name, action) in schedule:
            del schedule[(name, action)]
        elif timer.isnumeric() and timer not in ("0", "delete"):
            schedule[(name, action)] = {
                "Name": name,
                "Action": action,
                "Timer": timer,
                "Active": True,
            }

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
        volume_name = snapshot_name
        validate_volume_name(volume_name)
        snapshots = os.listdir(SNAPSHOTS_PATH)
        snapshots = [s for s in snapshots if s.startswith(volume_name + "@")]
        if not snapshots:
            raise SnapshotNotFoundError(f"No snapshots found for volume '{volume_name}'")
        snapshot_name = sorted(snapshots)[-1]
    else:
        validate_snapshot_name(snapshot_name)

    snapshot_path = join(SNAPSHOTS_PATH, snapshot_name)
    if not os.path.exists(snapshot_path):
        raise SnapshotNotFoundError(f"Snapshot '{snapshot_name}' not found")

    snapshot = btrfs.Subvolume(snapshot_path)
    target_name = target_name or snapshot_name.split("@")[0]
    validate_volume_name(target_name)

    target_path = join(VOLUMES_PATH, target_name)
    volume = btrfs.Subvolume(target_path)
    res = {"Err": ""}

    if not snapshot.exists():
        raise SnapshotNotFoundError(f"Snapshot '{snapshot_name}' is not a valid BTRFS subvolume")

    if volume.exists():
        # backup and delete
        stamped_name = new_snapshot_name(target_name)
        stamped_path = join(SNAPSHOTS_PATH, stamped_name)
        volume.snapshot(stamped_path, readonly=True)
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

    # Validate input names
    validate_volume_name(volumename)
    validate_volume_name(targetname)

    volumepath = join(VOLUMES_PATH, volumename)
    targetpath = join(VOLUMES_PATH, targetname)

    volume = btrfs.Subvolume(volumepath)
    if not volume.exists():
        raise VolumeNotFoundError(f"Source volume '{volumename}': no such volume")

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
    volume_name = req["Name"]
    dryrun = req.get("Dryrun", False)

    # Validate volume name
    validate_volume_name(volume_name)

    # Validate pattern with strict rules (no backward compatibility for immediate purge)
    warning = validate_purge_pattern(req["Pattern"], allow_backward_compat=False)
    if warning:
        raise ValidationError(f"Invalid pattern: {warning}")

    # Parse pattern for compute_purges
    pattern = parse_purge_pattern(req["Pattern"])

    # snapshots related to the volume, more recents first
    snapshots = [s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(volume_name + "@")]

    # Compute which snapshots to purge
    now = datetime.now()
    purge_list = compute_purges(snapshots, pattern, now)

    for snapshot in purge_list:
        if dryrun:
            log.info(f"(Dry run) Would delete snapshot {snapshot}")
        else:
            # Delete the BTRFS subvolume (xattrs are automatically deleted with it)
            btrfs.Subvolume(join(SNAPSHOTS_PATH, snapshot)).delete()
            log.info(f"Deleted snapshot {snapshot}")

    return {"Err": ""}


def validate_purge_pattern(pattern_str, allow_backward_compat=False):
    """Validate purge patterns

    Args:
        pattern_str: Pattern string like "2h:1d" or "2h"
        allow_backward_compat: If True, allow deprecated "2h:2h" patterns with warning

    Returns:
        warning_message_or_none: Warning message for deprecated patterns, None otherwise

    Raises:
        ValidationError: If pattern is invalid
    """
    units = {"m": 1, "h": 60, "d": 60 * 24, "w": 60 * 24 * 7, "y": 60 * 24 * 365}

    try:
        split = pattern_str.split(":")
        assert len(split) >= 1, "Pattern must have at least 1 component"
        assert all(p[:-1].isnumeric() for p in split), (
            "Pattern components must be numeric with unit suffix"
        )

        # Check for deprecated duplicate patterns
        if len(split) == 2 and split[0] == split[1]:
            if allow_backward_compat:
                return (
                    f"Converting deprecated pattern '{pattern_str}' to '{split[0]}'. "
                    f"Please update your schedule using 'buttervolume scheduled --auto-convert-old-patterns'."
                )
            else:
                raise ValidationError(
                    f"Invalid pattern '{pattern_str}'. Use '{split[0]}' instead of duplicate components."
                )

        # Check ascending order for multi-component patterns - by time values, not just units
        if len(split) > 1:
            time_values = [int(p[:-1]) * units[p[-1]] for p in split]
            assert all(x < y for x, y in zip(time_values, time_values[1:])), (
                "Time values must be in ascending order (e.g., 2h:4h:8h or 30m:2h:1d)"
            )

        return None  # Valid pattern, no warning

    except (ValueError, KeyError, AssertionError) as e:
        raise ValidationError(f"Invalid purge pattern: {pattern_str} - {str(e)}") from None


def convert_purge_pattern(pattern_str):
    """Convert deprecated purge patterns to new format

    Args:
        pattern_str: Pattern string like "2h:2h"

    Returns:
        converted_pattern_str: Converted pattern like "2h"
    """
    split = pattern_str.split(":")

    # Convert "2h:2h" to "2h"
    if len(split) == 2 and split[0] == split[1]:
        return split[0]

    # Pattern doesn't need conversion
    return pattern_str


def parse_purge_pattern(pattern_str):
    """Parse purge pattern string into minutes list for compute_purges

    Args:
        pattern_str: Pattern string like "2h:1d" or "2h"

    Returns:
        list: Pattern converted to minutes, sorted in descending order

    Raises:
        ValidationError: If pattern is invalid
    """
    units = {"m": 1, "h": 60, "d": 60 * 24, "w": 60 * 24 * 7, "y": 60 * 24 * 365}

    try:
        split = pattern_str.split(":")
        pattern = sorted(int(i[:-1]) * units[i[-1]] for i in split)
        return pattern
    except (ValueError, KeyError) as e:
        raise ValidationError(f"Invalid purge pattern: {pattern_str} - {str(e)}") from None


def compute_purges(snapshots, pattern, now):
    """Return the list of snapshots to purge,
    given a list of snapshots, a purge pattern and a now time
    """
    snapshots = sorted(snapshots)
    pattern = sorted(pattern, reverse=True)
    purge_list = []
    max_age = pattern[0]
    # Age of the snapshots in minutes.
    # Example : [30, 70, 90, 150, 210, ..., 4000]
    snapshots_age = []
    valid_snapshots = []
    for s in snapshots:
        try:
            snapshots_age.append(
                int((now - datetime.strptime(s.split("@")[1], DTFORMAT)).total_seconds()) / 60
            )
            valid_snapshots.append(s)
        except Exception:
            log.info("Skipping purge of %s with invalid date format", s)
            continue
    if not valid_snapshots:
        return purge_list

    # Handle single pattern case (e.g., "2h" -> [120])
    if len(pattern) == 1:
        # For single pattern, delete everything older than the threshold
        threshold = pattern[0]
        for i, age in enumerate(snapshots_age):
            if age > threshold:
                purge_list.append(valid_snapshots[i])
        return purge_list

    # Handle multi-pattern case (e.g., "2h:1d:1w" -> [120, 1440, 10080])
    # pattern = 3600:180:60
    # age segments = [(3600, 180), (180, 60)]
    for age_segment in [(pattern[i], pattern[i + 1]) for i, _ in enumerate(pattern[:-1])]:
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
