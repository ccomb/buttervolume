# Buttervolume Distributed Architecture Specification

## 1. Overview

This document specifies a distributed, multi-master, active-passive architecture for Buttervolume on a per-volume basis. The goal is to provide high availability and data durability without relying on external consensus systems like etcd or Consul.

The architecture is based on the following core principles:
- **HTTP-Only Communication**: All inter-node communication for control and data transfer occurs over a secure, internal REST API. SSH is not used for cluster operations.
- **Quorum-Based Consensus**: Critical state changes, such as promoting a new master for a volume, require agreement from a majority of nodes (`(N/2) + 1`) to prevent split-brain scenarios.
- **Per-Volume Master**: Each volume has exactly one Active (master) node at any given time. All other nodes act as passive replicas for that volume. A single node can be the master for some volumes and passive for others.
- **Implicit Demotion**: Promoting a new master for a volume automatically and safely demotes the old master, simplifying failover operations.

## 2. Core Concepts

### 2.1. The Cluster State File

Each node maintains a local file, `cluster_state.json`, which represents its view of the cluster's state. This file is the single source of truth for that node.

**Example `cluster_state.json`:**
```json
{
  "peers": [
    "https://10.0.0.1:8723",
    "https://10.0.0.2:8723",
    "https://10.0.0.3:8723"
  ],
  "volumes": {
    "web-data": {
      "term": 5,
      "active_node": "https://10.0.0.2:8723",
      "lock": null
    },
    "db-data": {
      "term": 2,
      "active_node": "https://10.0.0.1:8723",
      "lock": null
    }
  }
}
```
- **`peers`**: A list of the base URLs for all nodes in the cluster.
- **`volumes.{volume_name}.term`**: A monotonically increasing integer representing the current "reign" of the active node. It acts as a logical clock to prevent acting on stale information.
- **`volumes.{volume_name}.active_node`**: The address of the node currently responsible for the volume.
- **`volumes.{volume_name}.lock`**: A temporary, transient lock used during a promotion process. See the *Promotion Failure and Rollback* section for details.

### 2.2. The Term (Epoch)

The `term` is the primary mechanism for ensuring consistency.
- Any time a node wants to initiate a promotion for a volume, it must propose a new `term` that is strictly greater than the current `term` for that volume.
- Any node receiving a request with a higher `term` than its own must yield to it. It knows its own state is outdated.
- This prevents a partitioned node from continuing to act as master after a new master has been elected by the majority.

### 2.3. Quorum

A quorum is a majority of nodes, calculated as `floor(N/2) + 1`, where `N` is the total number of nodes in the cluster. No critical, state-changing operation (like a promotion) can be finalized until the initiating node has received acknowledgment from a quorum of its peers.

## 3. Inter-Node API Endpoints

All communication happens over a new, internal Bottle server running on a dedicated TCP port, secured by TLS and a shared bearer token.

### Control Plane

- **`GET /api/v1/status`**: Returns the node's current status and its view of the cluster state.
- **`GET /api/v1/volumes/{vol_name}/snapshots`**: Returns a list of all local snapshots for a given volume, including their UUIDs and parent UUIDs.
- **`POST /api/v1/volumes/{vol_name}/acquire-lock`**: (For promotion) Attempts to acquire an exclusive lock to become the new master for a volume.
  - **Request Body**: `{ "term": <new_term>, "candidate": "<candidate_url>" }`
  - **Success**: `200 OK` if the lock is granted.
  - **Failure**: `409 Conflict` if the term is not new or a lock is already held.
- **`POST /api/v1/volumes/{vol_name}/commit-state`**: (For promotion) Informs all peers of the final, successful state change.
  - **Request Body**: `{ "term": <new_term>, "active_node": "<new_master_url>" }`
- **`POST /api/v1/volumes/{vol_name}/abort-promotion`**: (For rollback) Instructs peers to release a lock from a failed promotion.
  - **Request Body**: `{ "term": <failed_term>, "candidate": "<candidate_url>" }`
- **`POST /api/v1/cluster/join`**: Endpoint for a new node to securely join the cluster.
- **`POST /api/v1/cluster/add-peer`**: Internal endpoint for informing nodes of a new peer that has successfully joined.

### Data Plane

- **`POST /api/v1/volumes/{vol_name}/receive-snapshot`**: Receives a raw `btrfs send` stream in the request body and pipes it to `btrfs receive`.
- **`GET /api/v1/volumes/{vol_name}/send-snapshot?parent=<p>&snapshot=<s>`**: Streams the output of `btrfs send -p <p> <s>` in the response body.
- **`POST /api/v1/volumes/{vol_name}/rsync-proxy`**: Proxies the `rsync` protocol over the secure API. The client-side `rsync` output is sent in the request body, and the server-side `rsync` output is streamed in the response body.

## 4. Key Workflows

### 4.1. Volume Promotion (Failover)

This is a two-phase commit process initiated by an admin via the CLI.

**Phase 1: Acquire Quorum Lock**
1.  The admin runs `buttervolume volume promote <vol_name> --new-master <candidate_node>`.
2.  The candidate node increments the volume's `term`.
3.  The candidate sends `acquire-lock` to all peers.
4.  The old master receives the request. Seeing a higher `term`, it enters a "demoted" state for that volume, grants the lock, and awaits the final outcome.
5.  Other nodes grant the lock if the `term` is new.

**Phase 2: Sync Data and Commit**
1.  The candidate, upon receiving a quorum of locks, knows it has exclusive control.
2.  It performs a final data sync by pulling the final snapshot from the now-demoted old master using the `/send-snapshot` endpoint.
3.  Once synced, the candidate sends `commit-state` to all peers.
4.  All peers update their `cluster_state.json` file. The candidate is now the new master and begins serving the volume.

### 4.2. The Demoted State (Read-Only Enforcement)

To prevent split-brain, a demoted master must stop all write operations. This is enforced with a hybrid approach:

1.  **Filesystem-Level (Primary):** Upon receiving an `acquire-lock` request with a higher `term`, the node immediately makes the volume read-only using `btrfs property set -ts /path/to/volume_subvolume ro true`. This provides a strong, kernel-level guarantee against writes from any process.
2.  **Application-Level (Secondary):** The Buttervolume application logic also checks the node's state before any write operation (e.g., `Mount`, `CreateSnapshot`). If the node is not the `active_node` for the volume, it will return an error. This provides defense-in-depth and allows for cleaner error handling.

When a promotion is successfully rolled back (see below), the `ro` property is set back to `false`.

### 4.3. Promotion Failure and Rollback

Graceful failure handling is critical. The system uses a combination of explicit aborts and automatic timeouts.

**The Lock Object**
The `lock` object in `cluster_state.json` is structured as follows:
```json
"lock": {
  "term": 6,
  "candidate": "https://10.0.0.3:8723",
  "expires_at": "2025-08-06T14:30:00Z"
}
```
- **`expires_at`**: An ISO 8601 timestamp. When granting a lock, nodes set this to a value in the near future (e.g., 120 seconds).

**Scenario 1: Failure to Achieve Quorum (Explicit Abort)**
1.  The candidate fails to get a quorum.
2.  It immediately sends an `abort-promotion` request to all peers.
3.  Peers validate the `term` and `candidate` in the request, then remove the `lock` object from their state file.
4.  The old master, upon removing the lock, reverts to being the active, read-write master and makes the volume writable again.

**Scenario 2: Candidate Fails After Quorum (Automatic Timeout)**
1.  The candidate gets a quorum but crashes before sending `commit-state`.
2.  The lock remains on all peers. The volume is temporarily stuck in a read-only state.
3.  Once the current time passes the `expires_at` timestamp, all nodes consider the lock expired and invalid.
4.  The old master, seeing the lock has expired, automatically reverts to its active, read-write master role. This is safe because the `term` number prevents the crashed candidate from committing a stale state if it recovers later.

### 4.4. Steady-State Replication

1.  The active node for a volume periodically creates a local snapshot.
2.  It determines the correct incremental parent for each passive peer by querying their `/snapshots` endpoint.
3.  It pushes the new incremental snapshot to each peer via the `/receive-snapshot` endpoint.

### 4.5. Cluster Lifecycle: Bootstrap and Node Join

#### Initial Cluster Bootstrap

A cluster is created with an explicit, one-time command on the first node. This avoids ambiguity and potential race conditions.

1.  **`buttervolume cluster init --self-addr <url>`**: An admin runs this on the first node.
    - The `--self-addr` parameter is mandatory and must be the network-accessible URL of the node (e.g., `https://10.0.0.1:8723`).
2.  The command generates a new `ClusterSharedSecret` and creates the initial `cluster_state.json` file, containing only the first node in its `peers` list.
3.  The node is now a fully functional, single-node cluster, ready to accept new peers.

#### Node Join

1.  An admin generates a single-use join token from an existing node.
2.  The new node uses this token to make a `/join` request to the existing node.
3.  The existing node validates the token, sends back the cluster secrets (peer list, bearer token) over TLS, and then broadcasts the new peer's address to all other nodes.

## 5. Security

- **Transport Security**: All inter-node API communication MUST be over TLS.
- **Authentication**: All API endpoints MUST be protected by a shared secret bearer token, which is passed in the `Authorization` header. This secret is provisioned during the node join process.