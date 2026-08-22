# Buttervolume Distributed Feature: Implementation Plan

This document outlines the step-by-step plan to implement the distributed, multi-master architecture specified in `ARCHITECTURE.md`. Each major step includes sub-tasks for implementation and testing.

## Where this actually stands

The phase headings below describe the intent. This is what the code does today,
checked against the branch rather than against the commit messages.

- **Phase 1 and 2 work.** The cluster API answers on its own thread and port,
  behind TLS and a bearer token.
- **Phase 3 is a skeleton.** Every data plane handler in `api.py` reads
  `btrfs.SNAPSHOTS_PATH` and `btrfs.VOLUMES_PATH`, which do not exist, and calls
  `run_safe` with `stdin`, `stream` and `capture_output` arguments it does not
  accept. None of these endpoints has ever run. Scheduled replication and `sync`
  still go over SSH, untouched.
- **Phase 4 holds together for the state part.** The lock, commit and abort
  endpoints and the `StateManager` behind them work, and a demoted master is now
  really made read-only. The candidate side of the two-phase commit is not
  proven by any test.
- **Phase 5 is one command out of four.** `cluster init` exists. There is no
  join token, no `cluster join`, and no `/cluster/join` or `/add-peer` endpoint,
  so a cluster cannot grow past its first node.

Nothing in `api.py` or `state.py` is covered by `test.py`.

## Phase 1: The Foundation - Inter-Node Communication

**Goal:** Establish a secure, threaded, network-facing API server in each node, separate from the Docker plugin socket.

1.  **Implementation Tasks:**
    -   [ ] Create a new `buttervolume/api.py` file.
    -   [ ] Define a new Bottle application instance (`cluster_api_app`) in this file.
    -   [ ] Add a basic, unauthenticated `GET /status` endpoint to the new app.
    -   [ ] Modify `buttervolume/cli.py`:
        -   [ ] Refactor the `run` function to be able to launch a server in a thread.
        -   [ ] Launch the existing Docker plugin server in one thread (on the Unix socket).
        -   [ ] Launch the new `cluster_api_app` in a second thread (on a hardcoded TCP port like 8723 for now).

2.  **Testing:**
    -   **Unit Tests:** N/A for this phase.
    -   **Integration Tests:**
        -   [ ] Manually start two `buttervolume run` processes on the same host with different config paths.
        -   [ ] Verify that both processes start without crashing.
        -   [ ] Use `curl` to hit the `http://localhost:8723/status` endpoint of the second process and verify it returns a success message.
        -   [ ] Verify that the Docker plugin functionality is unaffected by creating a volume (`docker volume create -d ccomb/buttervolume ...`).

## Phase 2: Securing the API

**Goal:** Implement TLS and Bearer Token authentication for the Cluster API.

1.  **Implementation Tasks:**
    -   [ ] Add configuration options to `config.ini` for `TlsCertPath`, `TlsKeyPath`, and `ClusterSharedSecret`.
    -   [ ] Modify the `run_cluster_server` function in `cli.py` to wrap the server socket with TLS if the cert/key paths are provided.
    -   [ ] Create a Bottle plugin or decorator that checks for the `Authorization: Bearer <token>` header on all `/api/v1/*` routes and validates it against the shared secret.

2.  **Testing:**
    -   **Unit Tests:**
        -   [ ] Write a test for the authentication decorator to ensure it correctly allows valid tokens and rejects invalid ones.
    -   **Integration Tests:**
        -   [ ] Start a server with TLS enabled.
        -   [ ] Verify that `curl http://...` fails.
        -   [ ] Verify that `curl https://... --insecure` without a token returns `401 Unauthorized`.
        -   [ ] Verify that `curl https://... --insecure` with the correct token returns `200 OK`.

## Phase 3: Basic State Management & Replication

**Goal:** Implement the `cluster_state.json` file and the basic push replication logic for a single, hardcoded volume master.

1.  **Implementation Tasks:**
    -   [ ] Define the structure of `cluster_state.json`.
    -   [ ] Create functions to read from and write to this file atomically.
    -   [ ] Implement the Data Plane endpoints:
        -   [ ] `POST /api/v1/volumes/{vol_name}/receive-snapshot`
        -   [ ] `GET /api/v1/volumes/{vol_name}/send-snapshot`
    -   [ ] Create a new scheduler job in `cli.py` that runs periodically:
        -   [ ] If the node is the designated master for a volume (hardcoded for now), it creates a snapshot.
        -   [ ] It then iterates through the peers in `cluster_state.json` and pushes the snapshot to them.
    -   [ ] **Modernize Existing Replication and Sync:**
        -   [ ] Modify the scheduled `replicate` action in `cli.py` to use the new HTTP-based BTRFS push mechanism instead of the old SSH-based `send` command.
        -   [ ] Implement the `POST /api/v1/volumes/{vol_name}/rsync-proxy` endpoint.
        -   [ ] Re-implement the `sync` command and scheduler action to use the new `rsync-proxy` endpoint, removing the SSH dependency entirely.

2.  **Testing:**
    -   **Unit Tests:**
        -   [ ] Test the snapshot send/receive logic in isolation.
    -   **Integration Tests:**
        -   [ ] Set up a two-node cluster with one master and one passive.
        -   [ ] Create a file in a volume on the master.
        -   [ ] Wait for the replication cycle to run.
        -   [ ] Verify that the corresponding snapshot appears on the passive node and contains the correct file.

## Phase 4: The Promotion Protocol (The Core Logic)

**Goal:** Implement the full, two-phase commit promotion workflow.

1.  **Implementation Tasks:**
    -   [ ] Implement the Control Plane endpoints:
        -   [ ] `POST /api/v1/volumes/{vol_name}/acquire-lock`
        -   [ ] `POST /api/v1/volumes/{vol_name}/commit-state`
    -   [ ] Implement the `volume promote` command in the `buttervolume` CLI.
    -   [ ] The CLI command should orchestrate the two-phase commit by calling the API on the candidate node.
    -   [ ] The candidate node must implement the full logic: increment term, send `acquire-lock` to all peers, wait for quorum, sync data, and finally send `commit-state`.
    -   [ ] The logic on receiving `acquire-lock` must be implemented: check term, take final snapshot, and enter read-only mode if demoted.

2.  **Testing:**
    -   **Unit Tests:**
        -   [ ] Test the lock acquisition logic in isolation (e.g., what happens with term conflicts, existing locks, etc.).
    -   **Integration Tests (Crucial):**
        -   [ ] Set up a three-node cluster.
        -   [ ] Promote a new master for a volume.
        -   [ ] Verify that the old master was demoted and its volume is read-only.
        -   [ ] Verify that the new master has all the latest data.
        -   [ ] Verify that all three nodes have the correct, updated state in their `cluster_state.json`.
        -   [ ] Test failure scenarios: what happens if the candidate cannot get a quorum? It should abort gracefully.

## Phase 5: Cluster Lifecycle Management

**Goal:** Implement the full cluster lifecycle, from initial bootstrap to adding new nodes.

1.  **Implementation Tasks:**
    -   [ ] Implement the `cluster init --self-addr <url>` CLI command.
        -   This command should perform safety checks, generate a shared secret, and create the initial `cluster_state.json`.
    -   [ ] Implement the `cluster create-join-token` CLI command.
    -   [ ] Implement the `cluster join` CLI command.
    -   [ ] Implement the `/api/v1/cluster/join` and `/api/v1/cluster/add-peer` API endpoints.

2.  **Testing:**
    -   **Integration Tests:**
        -   [ ] **Init:** Run `cluster init` on a fresh node. Verify the `cluster_state.json` and config files are created correctly. Verify the command fails if run a second time.
        -   [ ] **Join:** Start a second node. Use the `join` command to connect it to the first node.
        -   [ ] Verify that the new node is successfully added to the peer list on both nodes.
        -   [ ] Verify the new node can receive snapshots from an active master.
