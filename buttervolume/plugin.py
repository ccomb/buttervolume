import configparser
import csv
import json
import logging
import os
import re
from datetime import datetime
from os.path import basename, dirname, join
from subprocess import PIPE, CalledProcessError, run

from bottle import request, route

from buttervolume import btrfs

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
DRIVERNAME = getconfig(config, "DRIVERNAME", "ccomb/buttervolume:latest")
RUNPATH = getconfig(config, "RUNPATH", "/run/docker")
SOCKET = getconfig(config, "SOCKET", os.path.join(RUNPATH, "plugins", "btrfs.sock"))
USOCKET = SOCKET
if not os.path.exists(USOCKET):
    # socket path on the host or another container
    plugins = json.loads(
        run(
            "docker plugin inspect {}".format(DRIVERNAME),
            shell=True,
            stdout=PIPE,
            stderr=PIPE,
        ).stdout.decode()
        or "[]"
    )
    if plugins:
        plugin = plugins[0]  # can we have several plugins with the same name?
        USOCKET = os.path.join(RUNPATH, "plugins", plugin["Id"], "btrfs.sock")

TIMER = int(getconfig(config, "TIMER", 60))
DTFORMAT = getconfig(config, "DTFORMAT", "%Y-%m-%dT%H:%M:%S.%f")
LOGLEVEL = getattr(logging, getconfig(config, "LOGLEVEL", "INFO"))

logging.basicConfig(level=LOGLEVEL)
log = logging.getLogger()


def validate_volume_name(name):
    """Validate volume name for security and correctness"""
    if not name:
        raise ValueError("Volume name cannot be empty")

    if "@" in name:
        raise ValueError('"@" is illegal in a volume name')

    # Check for path traversal
    if ".." in name or name.startswith("/"):
        raise ValueError("Invalid characters in volume name")

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
        raise ValueError("Volume name contains dangerous characters")

    # Ensure reasonable length
    if len(name) > 255:
        raise ValueError("Volume name too long")

    # Only allow alphanumeric, dash, underscore, dot
    if not re.match(r"^[a-zA-Z0-9._-]+$", name):
        raise ValueError("Volume name contains invalid characters")

    return name


def validate_hostname(hostname):
    """Validate hostname for SSH operations"""
    if not hostname:
        raise ValueError("Hostname cannot be empty")

    # Basic hostname validation
    if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        raise ValueError("Invalid hostname format")

    if len(hostname) > 253:
        raise ValueError("Hostname too long")

    return hostname


def run_btrfs_send_receive(
    snapshot_path, remote_host, remote_snapshots, parent_path=None, port="1122"
):
    """Securely run btrfs send/receive over SSH"""
    # Validate inputs
    validate_hostname(remote_host)

    # First sync the filesystem
    btrfs.run_safe(["btrfs", "filesystem", "sync", SNAPSHOTS_PATH])

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

    # Execute send | ssh receive using subprocess
    import subprocess

    send_proc = subprocess.Popen(send_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    receive_proc = subprocess.Popen(
        ssh_cmd, stdin=send_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    send_proc.stdout.close()  # Allow send_proc to receive a SIGPIPE if receive_proc exits

    receive_stdout, receive_stderr = receive_proc.communicate()
    send_proc.wait()

    if send_proc.returncode != 0 or receive_proc.returncode != 0:
        raise CalledProcessError(
            receive_proc.returncode or send_proc.returncode,
            f"btrfs send/receive failed: {receive_stderr.decode()}",
        )

    return receive_stdout.decode()


def add_debug_log(handler):
    def new_handler(*_, **kw):
        req = json.loads(request.body.read().decode() or "{}")
        log.debug("Request: %s %s", request.path, req)
        resp = json.dumps(handler(req, **kw))
        log.debug("Response: %s", resp)
        return resp

    return new_handler


@route("/Plugin.Activate", ["POST"])
@add_debug_log
def plugin_activate(_):
    return {"Implements": ["VolumeDriver"]}


@route("/VolumeDriver.Create", ["POST"])
@add_debug_log
def volume_create(req):
    name = req["Name"]
    opts = req.get("Opts", {}) or {}

    # Validate volume name
    try:
        validate_volume_name(name)
    except ValueError as e:
        return {"Err": str(e)}

    volpath = join(VOLUMES_PATH, name)
    # volume already exists?
    if name in [v["Name"] for v in list_volumes()["Volumes"]]:
        return {"Err": ""}

    cow = opts.get("copyonwrite", "true").lower()
    if cow not in ["true", "false"]:
        return {"Err": f'Invalid option for copyonwrite: {cow}. Set to "true" or "false".'}

    try:
        btrfs.Subvolume(volpath).create(cow=cow == "true")
    except CalledProcessError as e:
        return {"Err": e.stderr.decode()}
    except OSError as e:
        return {"Err": e.strerror}
    except Exception as e:
        return {"Err": str(e)}
    return {"Err": ""}


def volumepath(name):
    path = join(VOLUMES_PATH, name)
    if not btrfs.Subvolume(path).exists():
        return None
    return path


@route("/VolumeDriver.Mount", ["POST"])
@add_debug_log
def volume_mount(req):
    name = req["Name"]

    # Validate volume name
    try:
        validate_volume_name(name)
    except ValueError as e:
        return {"Err": str(e)}

    path = volumepath(name)
    if path is None:
        return {"Err": "{}: no such volume".format(name)}
    return {"Mountpoint": path, "Err": ""}


@route("/VolumeDriver.Path", ["POST"])
@add_debug_log
def volume_path(req):
    name = req["Name"]

    # Validate volume name
    try:
        validate_volume_name(name)
    except ValueError as e:
        return {"Err": str(e)}

    path = volumepath(name)
    if path is None:
        return {"Err": "{}: no such volume".format(name)}
    return {"Mountpoint": path, "Err": ""}


@route("/VolumeDriver.Unmount", ["POST"])
@add_debug_log
def volume_unmount(_):
    return {"Err": ""}


@route("/VolumeDriver.Get", ["POST"])
@add_debug_log
def volume_get(req):
    name = req["Name"]

    # Validate volume name
    try:
        validate_volume_name(name)
    except ValueError as e:
        return {"Err": str(e)}

    path = volumepath(name)
    if path is None:
        return {"Err": "{}: no such volume".format(name)}
    return {"Volume": {"Name": name, "Mountpoint": path}, "Err": ""}


@route("/VolumeDriver.Remove", ["POST"])
@add_debug_log
def volume_remove(req):
    name = req["Name"]

    # Validate volume name
    try:
        validate_volume_name(name)
    except ValueError as e:
        return {"Err": str(e)}

    path = join(VOLUMES_PATH, name)
    try:
        btrfs.Subvolume(path).delete()
    except Exception:
        log.error("%s: no such volume", name)
        return {"Err": "{}: no such volume".format(name)}
    return {"Err": ""}


@route("/VolumeDriver.List", ["POST"])
@add_debug_log
def volume_list(_):
    return list_volumes()


def list_volumes():
    volumes = []
    for p in [join(VOLUMES_PATH, v) for v in os.listdir(VOLUMES_PATH) if v != "metadata.db"]:
        if not btrfs.Subvolume(p).exists():
            continue
        volumes.append(p)
    return {"Volumes": [{"Name": basename(v)} for v in volumes], "Err": ""}


@route("/VolumeDriver.Volume.Sync", ["POST"])
@add_debug_log
def volume_sync(req):
    """Rsync between two nodes"""
    test = req.get("Test", False)
    remote_volumes = VOLUMES_PATH if not test else TEST_REMOTE_PATH
    volumes = req["Volumes"]
    remote_hosts = req["Hosts"]
    port = os.getenv("SSH_PORT", "1122")
    errors = list()

    # Validate inputs
    for volume_name in volumes:
        try:
            validate_volume_name(volume_name)
        except ValueError as e:
            errors.append(f"Invalid volume name {volume_name}: {str(e)}")
            continue

    for remote_host in remote_hosts:
        try:
            validate_hostname(remote_host)
        except ValueError as e:
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
                btrfs.run_safe(cmd, check=True, stdout=PIPE, stderr=PIPE)
            except Exception as ex:
                err = getattr(ex, "stderr", ex)
                error_message = f"Error while rsync {volume_name} from {remote_host}: {err}"
                log.error(error_message)
                errors.append(error_message)

    return {"Err": "\n".join(errors)}


@route("/VolumeDriver.Capabilities", ["POST"])
@add_debug_log
def driver_cap(_):
    """butter volumes are local to the active node.
    They only exist as snapshots on the remote nodes.
    """
    return {"Capabilities": {"Scope": "local"}}


@route("/VolumeDriver.Snapshot.Send", ["POST"])
@add_debug_log
def snapshot_send(req):
    """The last sent snapshot is remembered by adding a suffix with the target"""
    test = req.get("Test", False)
    snapshot_name = req["Name"]
    remote_host = req["Host"]

    # Validate inputs
    try:
        validate_volume_name(snapshot_name.split("@")[0])  # Validate base volume name
        validate_hostname(remote_host)
    except ValueError as e:
        return {"Err": str(e)}

    snapshot_path = join(SNAPSHOTS_PATH, snapshot_name)
    remote_snapshots = SNAPSHOTS_PATH if not test else TEST_REMOTE_PATH

    # take the latest snapshot suffixed with the target host
    sent_snapshots = sorted([
        s
        for s in os.listdir(SNAPSHOTS_PATH)
        if len(s.split("@")) == 3
        and s.split("@")[0] == snapshot_name.split("@")[0]
        and s.split("@")[2] == remote_host
    ])
    latest = sent_snapshots[-1] if len(sent_snapshots) > 0 else None
    if latest and len(latest.rsplit("@")) == 3:
        latest = latest.rsplit("@", 1)[0]

    parent_path = join(SNAPSHOTS_PATH, latest) if latest else None
    port = os.getenv("SSH_PORT", "1122")

    try:
        log.info("Sending snapshot %s to %s", snapshot_path, remote_host)
        run_btrfs_send_receive(snapshot_path, remote_host, remote_snapshots, parent_path, port)
    except CalledProcessError as e:
        log.warning(
            "Failed using parent %s. Sending full snapshot %s: %s", latest, snapshot_path, str(e)
        )
        try:
            # Try to remove existing snapshot on remote and send full
            import subprocess

            rm_cmd = [
                "ssh",
                "-p",
                port,
                "-o",
                "StrictHostKeyChecking=no",
                remote_host,
                f"btrfs subvolume delete {remote_snapshots}/{snapshot_name} || true",
            ]
            subprocess.run(rm_cmd, check=False, stdout=PIPE, stderr=PIPE)

            # Send without parent
            run_btrfs_send_receive(snapshot_path, remote_host, remote_snapshots, None, port)
        except CalledProcessError as e2:
            log.error("Failed sending full snapshot: %s", str(e2))
            return {"Err": str(e2)}

    # Create local tracking snapshot
    btrfs.Subvolume(snapshot_path).snapshot(
        "{}@{}".format(snapshot_path, remote_host), readonly=True
    )

    # Clean up old tracking snapshots
    for old_snapshot in sent_snapshots:
        try:
            btrfs.Subvolume(join(SNAPSHOTS_PATH, old_snapshot)).delete()
        except Exception as e:
            log.warning("Failed to delete old snapshot %s: %s", old_snapshot, str(e))

    return {"Err": ""}


@route("/VolumeDriver.Snapshot", ["POST"])
@add_debug_log
def volume_snapshot(req):
    """snapshot a volume in the SNAPSHOTS dir"""
    name = req["Name"]

    # Validate volume name
    try:
        validate_volume_name(name)
    except ValueError as e:
        return {"Err": str(e)}

    path = join(VOLUMES_PATH, name)
    timestamped = "{}@{}".format(name, datetime.now().strftime(DTFORMAT))
    snapshot_path = join(SNAPSHOTS_PATH, timestamped)
    if not os.path.exists(path):
        return {"Err": "No such volume: {}".format(name)}
    try:
        btrfs.Subvolume(path).snapshot(snapshot_path, readonly=True)
    except Exception as e:
        log.error("Error creating snapshot: %s", str(e))
        return {"Err": str(e)}
    return {"Err": "", "Snapshot": timestamped}


@route("/VolumeDriver.Snapshot.List", ["GET"])
@add_debug_log
def snapshot_list(_):
    snapshots = os.listdir(SNAPSHOTS_PATH)
    return {"Err": "", "Snapshots": snapshots}


@route("/VolumeDriver.Snapshot.List/<name>", ["GET"])
@add_debug_log
def snapshot_sublist(_, name=""):
    # Validate volume name if provided
    if name:
        try:
            validate_volume_name(name)
        except ValueError as e:
            return {"Err": str(e)}

    snapshots = os.listdir(SNAPSHOTS_PATH)
    if name:
        snapshots = [s for s in snapshots if s.startswith(name + "@")]
    return {"Err": "", "Snapshots": snapshots}


@route("/VolumeDriver.Snapshot.Remove", ["POST"])
@add_debug_log
def snapshot_delete(req):
    name = req["Name"]
    path = join(SNAPSHOTS_PATH, name)
    if not os.path.exists(path):
        return {"Err": "No such snapshot"}
    try:
        btrfs.Subvolume(path).delete()
    except Exception as e:
        log.error("Error deleting snapshot: %s", str(e))
        return {"Err": str(e)}
    return {"Err": ""}


@route("/VolumeDriver.Schedule", ["POST"])
@add_debug_log
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


@route("/VolumeDriver.Schedule.List", ["GET"])
@add_debug_log
def scheduled(_):
    """List scheduled jobs"""
    if os.path.exists(SCHEDULE_DISABLED):
        return {"Err": "Schedule is globally paused"}
    schedule = []
    if os.path.exists(SCHEDULE):
        with open(SCHEDULE) as f:
            schedule = list(csv.DictReader(f, fieldnames=FIELDS))
    return {"Err": "", "Schedule": schedule}


@route("/VolumeDriver.Schedule.Pause", ["POST"])
@add_debug_log
def schedule_disable(_):
    """Disable scheduled jobs"""
    if os.path.exists(SCHEDULE):
        os.rename(SCHEDULE, SCHEDULE_DISABLED)
    return {"Err": ""}


@route("/VolumeDriver.Schedule.Resume", ["POST"])
@add_debug_log
def schedule_enable(_):
    """Enable scheduled jobs"""
    if os.path.exists(SCHEDULE_DISABLED):
        os.rename(SCHEDULE_DISABLED, SCHEDULE)
    return {"Err": ""}


@route("/VolumeDriver.Snapshot.Restore", ["POST"])
@add_debug_log
def snapshot_restore(req):
    """
    Snapshot a volume and overwrite it with the specified snapshot.
    """
    snapshot_name = req["Name"]
    target_name = req.get("Target")
    if "@" not in snapshot_name:
        # we're passing the name of the volume. Use the latest snapshot.
        volume_name = snapshot_name
        snapshots = os.listdir(SNAPSHOTS_PATH)
        snapshots = [s for s in snapshots if s.startswith(volume_name + "@")]
        if not snapshots:
            return {"Err": ""}
        snapshot_name = sorted(snapshots)[-1]
    snapshot_path = join(SNAPSHOTS_PATH, snapshot_name)
    snapshot = btrfs.Subvolume(snapshot_path)
    target_name = target_name or snapshot_name.split("@")[0]
    target_path = join(VOLUMES_PATH, target_name)
    volume = btrfs.Subvolume(target_path)
    res = {"Err": ""}
    if snapshot.exists():
        if volume.exists():
            # backup and delete
            timestamp = datetime.now().strftime(DTFORMAT)
            stamped_name = "{}@{}".format(target_name, timestamp)
            stamped_path = join(SNAPSHOTS_PATH, stamped_name)
            volume.snapshot(stamped_path, readonly=True)
            res["VolumeBackup"] = stamped_name
            volume.delete()
        snapshot.snapshot(target_path)
    else:
        res["Err"] = "No such snapshot"
    return res


@route("/VolumeDriver.Clone", ["POST"])
@add_debug_log
def snapshot_clone(req):
    """
    Create a new volume as clone from another.
    """
    volumename = req["Name"]
    targetname = req.get("Target")
    volumepath = join(VOLUMES_PATH, volumename)
    targetpath = join(VOLUMES_PATH, targetname)
    volume = btrfs.Subvolume(volumepath)
    res = {"Err": ""}
    if volume.exists():
        # clone
        volume.snapshot(targetpath)
        res["VolumeCloned"] = targetname
    else:
        res["Err"] = "No such volume"
    return res


@route("/VolumeDriver.Snapshots.Purge", ["POST"])
@add_debug_log
def snapshots_purge(req):
    """
    Purge snapshots with a retention pattern
    (see cli help)
    """
    volume_name = req["Name"]
    dryrun = req.get("Dryrun", False)

    # convert the pattern to seconds, check validity and reorder
    units = {"m": 1, "h": 60, "d": 60 * 24, "w": 60 * 24 * 7, "y": 60 * 24 * 365}
    try:
        pattern = sorted(int(i[:-1]) * units[i[-1]] for i in req["Pattern"].split(":"))
        assert len(pattern) >= 2
    except:
        log.error("Invalid purge pattern: %s", req["Pattern"])
        return {"Err": "Invalid purge pattern"}

    # snapshots related to the volume, more recents first
    snapshots = (s for s in os.listdir(SNAPSHOTS_PATH) if s.startswith(volume_name + "@"))
    try:
        for snapshot in compute_purges(snapshots, pattern, datetime.now()):
            if dryrun:
                log.info("(Dry run) Would delete snapshot {}".format(snapshot))
            else:
                btrfs.Subvolume(join(SNAPSHOTS_PATH, snapshot)).delete()
                log.info("Deleted snapshot {}".format(snapshot))
    except OSError as e:
        log.error("Error purging snapshots: %s", e.strerror)
        return {"Err": e.strerror}
    return {"Err": ""}


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
        except:
            log.info("Skipping purge of %s with invalid date format", s)
            continue
    if not valid_snapshots:
        return purge_list
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
