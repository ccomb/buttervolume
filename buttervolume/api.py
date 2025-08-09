import os
from bottle import Bottle, request, response

from buttervolume import btrfs

# The Bottle application for the cluster API
cluster_api_app = Bottle()


@cluster_api_app.get("/status")
def status():
    """A simple status endpoint to check if the API server is running."""
    response.content_type = "application/json"
    return '{"status": "ok"}'


@cluster_api_app.post("/api/v1/volumes/<vol_name>/receive-snapshot")
def receive_snapshot(vol_name):
    """Receives a btrfs snapshot stream and applies it."""
    # Note: The auth plugin will have already validated the request.
    # We can add more volume-specific authorization here later if needed.

    # We stream the request body directly to the btrfs receive command
    # to avoid loading the whole snapshot into memory.
    try:
        # The snapshot path is determined by the plugin's config, not user input
        receive_path = btrfs.SNAPSHOTS_PATH
        p = btrfs.run_safe(
            ["btrfs", "receive", receive_path],
            stdin=request.body,
            capture_output=True,
        )
        return {"Err": ""}
    except btrfs.BtrfsError as e:
        response.status = 500
        return {"Err": str(e)}


@cluster_api_app.get("/api/v1/volumes/<vol_name>/send-snapshot")
def send_snapshot(vol_name):
    """Sends a btrfs snapshot stream."""
    parent = request.query.get("parent")
    snapshot = request.query.get("snapshot")

    if not snapshot:
        response.status = 400
        return {"Err": "Missing snapshot parameter"}

    try:
        snapshot_path = os.path.join(btrfs.SNAPSHOTS_PATH, snapshot)
        cmd = ["btrfs", "send"]
        if parent:
            parent_path = os.path.join(btrfs.SNAPSHOTS_PATH, parent)
            cmd.extend(["-p", parent_path])
        cmd.append(snapshot_path)

        p = btrfs.run_safe(cmd, stream=True)
        return p.stdout
    except btrfs.BtrfsError as e:
        response.status = 500
        return {"Err": str(e)}


@cluster_api_app.get("/api/v1/volumes/<vol_name>/snapshots")
def list_snapshots(vol_name):
    """Lists all local snapshots for a given volume."""
    try:
        snapshots = [s for s in os.listdir(btrfs.SNAPSHOTS_PATH) if s.startswith(vol_name + "@")]
        return {"Snapshots": snapshots, "Err": ""}
    except FileNotFoundError:
        return {"Snapshots": [], "Err": ""}
    except Exception as e:
        response.status = 500
        return {"Err": str(e)}


@cluster_api_app.post("/api/v1/volumes/<vol_name>/rsync-proxy")
def rsync_proxy(vol_name):
    """Proxies the rsync protocol over the secure API."""
    try:
        # We are the server in this scenario. We run rsync in server mode
        # and pipe the client's request body into it, and stream the
        # server's response back to the client.
        p = btrfs.run_safe(
            ["rsync", "--server", "--sender", ".", os.path.join(btrfs.VOLUMES_PATH, vol_name)],
            stdin=request.body,
            stream=True,
        )
        return p.stdout
    except btrfs.BtrfsError as e:
        response.status = 500
        return {"Err": str(e)}


@cluster_api_app.post("/api/v1/volumes/<vol_name>/acquire-lock")
def acquire_lock(vol_name, state_manager):
    """Attempts to acquire an exclusive lock to become the new master for a volume."""
    req = json.loads(request.body.read().decode() or "{}")
    term = req.get("term")
    candidate = req.get("candidate")

    if not term or not candidate:
        response.status = 400
        return {"Err": "Missing term or candidate"}

    return state_manager.acquire_lock(vol_name, term, candidate)


@cluster_api_app.post("/api/v1/volumes/<vol_name>/commit-state")
def commit_state(vol_name, state_manager):
    """Informs all peers of the final, successful state change."""
    req = json.loads(request.body.read().decode() or "{}")
    term = req.get("term")
    active_node = req.get("active_node")

    if not term or not active_node:
        response.status = 400
        return {"Err": "Missing term or active_node"}

    return state_manager.commit_state(vol_name, term, active_node)


@cluster_api_app.post("/api/v1/volumes/<vol_name>/abort-promotion")
def abort_promotion(vol_name, state_manager):
    """Instructs peers to release a lock from a failed promotion."""
    req = json.loads(request.body.read().decode() or "{}")
    term = req.get("term")
    candidate = req.get("candidate")

    if not term or not candidate:
        response.status = 400
        return {"Err": "Missing term or candidate"}

    return state_manager.abort_promotion(vol_name, term, candidate)