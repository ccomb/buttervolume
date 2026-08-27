"""The Docker Volume Plugin HTTP API, and where a name becomes a path.

Every endpoint is a module-level ``@route(...)`` below, and that list of
decorators is the authoritative route list. ``@route`` is defined here too, and
is not Bottle's: it decodes the request, logs it, and turns any failure into
the ``Err`` field of a 200 answer, which is the only shape a client can read.

This is where a name turns into a path on disk, and where it is validated as it
does; the directories it is joined to come from ``config.py``. What a name is
worth is decided in ``names.py``, what a retention pattern says in ``purge.py``,
what a scheduled action asks for in ``schedule.py``; none of them knows these
directories, and the schedule file is read and written there rather than here.
"""

import json
import logging
import os
import subprocess
import tempfile
import threading
import time
from dataclasses import replace
from datetime import datetime
from functools import wraps
from os.path import basename, dirname, join

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
from buttervolume.config import (
    DTFORMAT,
    REMOTE_TIMEOUT,
    RSYNC_TIMEOUT,
    SCHEDULE,
    SCHEDULE_DISABLED,
    SEND_TIMEOUT,
    SNAPSHOTS_PATH,
    SYNC_TIMEOUT,
    TEST_REMOTE_PATH,
    VOLUMES_PATH,
)
from buttervolume.names import (
    Snapshot,
    new_snapshot,
    parsed,
    sent_snapshots,
    snapshot_to_fetch,
    snapshots_of,
    validate_hostname,
    validate_snapshot_name,
    validate_volume_name,
)
from buttervolume.purge import Pattern, compute_purges
from buttervolume.schedule import Entry, Job, read_schedule, write_schedule

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


def run_btrfs_receive(remote_host, remote_snapshot_path, remote_parent_path=None, port="1122"):
    """Securely run btrfs send/receive over SSH, the other way round.

    `remote_parent_path` is a path on the other machine, not here: it goes
    into the command that host runs. Its counterpart on the send side is a
    local path, and on a test bench where the two directories sit on the same
    filesystem, one passed for the other goes unnoticed.

    Nothing is synced first, unlike the send side, which syncs because the
    snapshot it is about to send was just taken here. Nothing was written here
    now, and the snapshot over there was committed long ago.
    """
    validate_hostname(remote_host)

    # Build the send command the remote host will run
    send_cmd = ["btrfs", "send"]
    if remote_parent_path:
        send_cmd.extend(["-p", remote_parent_path])
    send_cmd.append(remote_snapshot_path)

    ssh_cmd = [
        "ssh",
        "-p",
        port,
        "-o",
        "StrictHostKeyChecking=no",
        remote_host,
        " ".join(send_cmd),
    ]
    receive_cmd = ["btrfs", "receive", SNAPSHOTS_PATH]

    # Execute ssh send | receive using subprocess.
    # The stderr of the sending side goes to a temporary file rather than a
    # pipe, for the same reason as on the send side: nobody can read that pipe
    # while waiting for the receive side, and a verbose failure would fill it
    # and deadlock both processes.
    with tempfile.TemporaryFile() as send_stderr_file:
        send_proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=send_stderr_file)
        receive_proc = subprocess.Popen(
            receive_cmd, stdin=send_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE
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
                f"btrfs send/receive from {remote_host} timed out after {SEND_TIMEOUT}s: "
                f"{send_stderr_file.read().decode(errors='replace')}"
            ) from None

        if send_proc.returncode != 0 or receive_proc.returncode != 0:
            send_stderr_file.seek(0)
            raise ReplicationError(
                f"btrfs send/receive from {remote_host} failed "
                f"(send: {send_proc.returncode}, receive: {receive_proc.returncode}): "
                f"{send_stderr_file.read().decode(errors='replace')} "
                f"{receive_stderr.decode(errors='replace')}"
            )

    return receive_stdout.decode(errors="replace")


def snapshots_on_remote(remote_host, remote_path, port):
    """The names this host keeps in that directory.

    An empty answer means it answered and keeps nothing there. A host that
    could not answer raises instead, and is never read as a host with nothing:
    acting on "there is nothing over there" when nobody said so is how the
    good copy of a volume gets replaced by an older one.

    The whole directory is listed rather than a `volume@*` pattern. The
    pattern would carry a name into a shell on the other machine, and `ls`
    leaves with the same non-zero status when nothing matches as when it
    failed, which is exactly the difference this function exists to keep.
    """
    validate_hostname(remote_host)
    ssh_cmd = [
        "ssh",
        "-p",
        port,
        "-o",
        "StrictHostKeyChecking=no",
        remote_host,
        f"ls -1 {remote_path}",
    ]
    try:
        listing = subprocess.run(ssh_cmd, capture_output=True, timeout=REMOTE_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ReplicationTimeoutError(
            f"{remote_host} did not say what it keeps within {REMOTE_TIMEOUT}s"
        ) from None
    if listing.returncode != 0:
        raise ReplicationError(
            f"Could not read the snapshots of {remote_host}: "
            f"{listing.stderr.decode(errors='replace')}"
        )
    # nothing is decoded strictly: a name we cannot read is one this host
    # should not have written, and it is refused later by name rather than
    # here by an error nobody expected
    return listing.stdout.decode(errors="replace").splitlines()


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


def keep_trace(snapshot, remote_host):
    """Remember that this host holds this snapshot, and forget the older ones.

    That trace is the whole memory of what is over there: a later send reads it
    to know there is nothing to send, and an incremental one is built on the
    snapshot it was made from. The traces of the previous exchanges with that
    host go, since this one says the same thing about a more recent snapshot;
    the snapshots they were made from stay, and a purge takes them when its
    pattern says so.
    """
    trace = snapshot.sent_to(remote_host)
    if not os.path.exists(snapshotpath(str(trace))):
        btrfs.Subvolume(snapshotpath(str(snapshot))).snapshot(
            snapshotpath(str(trace)), readonly=True
        )
    for old in sent_snapshots(snapshot.volume, remote_host, os.listdir(SNAPSHOTS_PATH)):
        if old == trace:
            continue
        try:
            btrfs.Subvolume(snapshotpath(str(old))).delete()
        except Exception as e:
            log.warning("Failed to delete old snapshot %s: %s", str(old), str(e))


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
    if snapshot in {t.without_host() for t in already_sent}:
        # a trace says this very snapshot is already there. Sending it again
        # would name its own parent, the remote receive would refuse it, and
        # the fallback below would delete the good remote copy before sending
        # the whole volume again. Any of the traces, not just the last one:
        # two of them coexist when a send stopped between writing the new one
        # and deleting the old.
        log.info("Snapshot %s is already on %s, nothing to send", snapshot_name, remote_host)
        return {"Err": ""}
    latest = already_sent[-1].without_host() if already_sent else None
    parent_path = snapshotpath(str(latest)) if latest else None
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

    keep_trace(snapshot, remote_host)

    return {"Err": ""}


# One receive at a time. A `btrfs receive` that stops early leaves behind what
# it was writing, under the name the whole snapshot would have carried, and the
# endpoint below takes that leftover away to try again without a parent. Two
# calls at once would each take away what the other is writing, and neither
# could say the half received copy was its own.
receiving = threading.Lock()


def is_a_whole_snapshot(path):
    """Whether this holds a whole snapshot, and not half of one.

    `btrfs receive` makes what it wrote read-only once it has written all of
    it. A subvolume of the right name that can still be written to is what a
    transfer that stopped early left behind, and nothing in it says how much of
    the volume made it over.
    """
    return "readonly" in btrfs.Subvolume(path).show()["Flags"]


def receive_or_clean(remote_host, remote_snapshot_path, path, remote_parent_path, port):
    """Receive into `path`, and take away what is left there when it fails.

    That leftover is the only thing deleted, and this call is the one that
    created it, which the lock above is what makes true. Leaving it would stop
    every later call, none of them being able to tell that name from a
    snapshot.
    """
    try:
        run_btrfs_receive(remote_host, remote_snapshot_path, remote_parent_path, port)
    except ReplicationError:
        if os.path.exists(path):
            try:
                btrfs.Subvolume(path).delete()
            except BtrfsError as e:
                log.warning("Could not take away the half received %s: %s", basename(path), e)
        raise


@route("/VolumeDriver.Snapshot.Receive")
def snapshot_receive(req):
    """Fetch from another host the most recent snapshot it has of a volume"""
    test = req.get("Test", False)
    volume = req["Name"]
    remote_host = req["Host"]

    validate_volume_name(volume)
    validate_hostname(remote_host)
    remote_snapshots = SNAPSHOTS_PATH if not test else TEST_REMOTE_PATH
    port = os.getenv("SSH_PORT", "1122")

    with receiving:
        # the command names a volume, not a snapshot: whoever receives does not
        # know what the other host has, which is the question being asked here
        found = snapshot_to_fetch(
            volume,
            snapshots_on_remote(remote_host, remote_snapshots, port),
            os.listdir(SNAPSHOTS_PATH),
        )
        if not found:
            raise SnapshotNotFoundError(f"{remote_host} keeps no snapshot of volume '{volume}'")
        snapshot, parent = found
        path = snapshotpath(str(snapshot))

        if os.path.exists(path):
            if not is_a_whole_snapshot(path):
                # the send side reads what the other host holds from a trace
                # written after a transfer went through, so it never says yes
                # by mistake. Here the answer is a name in a directory, which
                # a transfer that failed leaves behind just the same.
                raise ReplicationError(
                    f"'{snapshot}' is here already but holds half a volume, left by a receive "
                    f"that stopped early. Delete it with `buttervolume rm {snapshot}` to fetch "
                    "it again"
                )
            log.info("Snapshot %s is already here, nothing to receive", snapshot)
            keep_trace(snapshot, remote_host)
            return {"Err": "", "Snapshot": str(snapshot)}

        remote_path = join(remote_snapshots, str(snapshot))
        parent_path = join(remote_snapshots, str(parent)) if parent else None
        try:
            log.info("Receiving snapshot %s from %s with parent %s", snapshot, remote_host, parent)
            receive_or_clean(remote_host, remote_path, path, parent_path, port)
        except ReplicationTimeoutError:
            # receiving the whole volume would cross the same stalled link, and
            # wait as long again: a transfer killed for hanging is not retried
            raise
        except ReplicationError as e:
            if not parent_path:
                raise
            log.warning(
                "Failed receiving %s with parent %s, receiving it whole: %s", snapshot, parent, e
            )
            receive_or_clean(remote_host, remote_path, path, None, port)

        # that host holds this snapshot, we have just read it there. Without
        # this trace the first send back would carry the whole volume again.
        keep_trace(snapshot, remote_host)
        return {"Err": "", "Snapshot": str(snapshot)}


# One snapshot at a time. The endpoint below takes a copy, compares it with the
# previous snapshot and deletes it when the two hold the same thing. Two calls
# on the same volume, interleaved, would each compare against the copy of the
# other, find it identical, and delete their own: the volume would come out of
# the two calls with neither, while both answers named one. A single lock for
# every volume is enough, since the scheduler runs its jobs one after the other
# and the only other snapshot is the one somebody asks for.
snapshotting = threading.Lock()


@route("/VolumeDriver.Snapshot")
def volume_snapshot(req):
    """Snapshot a volume in the SNAPSHOTS dir, unless it holds nothing new.

    The answer names the snapshot that holds the state of the volume, and says
    in "Created" whether this call is the one that took it. A volume nobody
    wrote to gives the name of the previous snapshot and takes none, which is
    what keeps a replication scheduled every minute from filling the disk with
    identical copies. A caller that deletes what it created has to read that
    flag: the name alone no longer says whose snapshot it is.
    """
    name = req["Name"]
    volume = existing_volume(name)

    with snapshotting:
        timestamped = new_snapshot_name(name)
        path = snapshotpath(timestamped)
        volume.snapshot(path, readonly=True)

        # BTRFS cannot compare a live volume to a snapshot, since a send needs
        # a readonly subvolume, so the comparison happens after the fact: the
        # copy just taken is deleted when it holds nothing the previous one
        # does not. The traces of the sends are left out: their content is that
        # of their own snapshot, but naming one here would have the next send
        # refuse it.
        previous = max(
            (
                s
                for s in parsed(os.listdir(SNAPSHOTS_PATH))
                if s.volume == name and not s.host and str(s) != timestamped
            ),
            key=str,
            default=None,
        )
        if previous:
            try:
                if btrfs.Subvolume(path).is_same_as(snapshotpath(str(previous))):
                    btrfs.Subvolume(path).delete()
                    log.info("%s has not changed since %s", name, previous)
                    return {"Err": "", "Snapshot": str(previous), "Created": False}
            except BtrfsError as e:
                # neither a comparison we could not make nor a deletion that
                # failed is a reason to lose a snapshot: the copy is kept, and
                # answered as the one this call took
                log.warning(
                    "Keeping %s, which could not be compared with %s or dropped: %s",
                    timestamped,
                    previous,
                    e,
                )
        return {"Err": "", "Snapshot": timestamped, "Created": True}


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
    schedule = {(entry.name, entry.action): entry for entry in read_schedule(SCHEDULE)}

    if timer in ("pause", "resume", "0", "delete"):
        # These name a line that is already written, whatever it says: a job
        # this endpoint once accepted must stay possible to pause and to
        # delete. Only the line named is looked at, never the others.
        if (name, action) not in schedule:
            raise ValidationError(f"No '{action}' of '{name}' is scheduled")
        if timer == "pause":
            schedule[(name, action)] = replace(schedule[(name, action)], active="False")
        elif timer == "resume":
            schedule[(name, action)] = replace(schedule[(name, action)], active="True")
        else:
            del schedule[(name, action)]
    elif timer.isdecimal() and int(timer) > 0:
        # isdecimal, not isnumeric: "²".isnumeric() is True and int("²")
        # raises, and the scheduler reads this timer back with int()
        validate_volume_name(name)
        Job.parse(action)
        schedule[(name, action)] = Entry(name, action, timer, "True")
    else:
        raise ValidationError(
            f"Invalid timer '{timer}'. It must be a number of minutes, or "
            "'pause', 'resume', or '0' or 'delete' to unschedule"
        )

    write_schedule(SCHEDULE, schedule.values())
    return {"Err": ""}


@route("/VolumeDriver.Schedule.List", "GET")
def scheduled(_):
    """List scheduled jobs"""
    if os.path.exists(SCHEDULE_DISABLED):
        return {"Err": "Schedule is globally paused"}
    schedule = []
    if os.path.exists(SCHEDULE):
        schedule = [entry.fields for entry in read_schedule(SCHEDULE)]
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
