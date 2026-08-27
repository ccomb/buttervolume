"""Everything that is decided once, at startup, and never again.

An environment variable wins over `/etc/buttervolume/config.ini`, which wins
over the default written here; `getconfig` is that rule, and nobody else has to
know it. What lives here is a value read at import time: a directory, a delay,
the socket to answer on. Nothing that touches BTRFS, a volume or a request.

Every other module reads its settings here rather than from `plugin.py`, so
that knowing where the snapshots live no longer means importing the whole HTTP
server. They import the names, never the module, because the test suite
replaces some of these names in the namespace of the module that reads them.
"""

import configparser
import json
import logging
import os
from subprocess import run

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
LAST_RUNS = getconfig(config, "LAST_RUNS", "/var/lib/buttervolume/lastruns.csv")
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
# How long each external command may legitimately take, in seconds. These three
# are not read from the configuration file, but they are delays like the next
# one and are read next to it.
SYNC_TIMEOUT = 30
RSYNC_TIMEOUT = 600
# How long a remote host has to answer a question that is not a transfer, such
# as saying which snapshots it keeps. Not SEND_TIMEOUT: waiting ten minutes for
# a listing would hold up whoever asked for it just as long.
REMOTE_TIMEOUT = 30
# The send crosses the network, so its limit is configurable like the rest
SEND_TIMEOUT = int(getconfig(config, "SEND_TIMEOUT", 600))
DTFORMAT = getconfig(config, "DTFORMAT", "%Y-%m-%dT%H:%M:%S.%f")
LOGLEVEL = getattr(logging, getconfig(config, "LOGLEVEL", "INFO"))

logging.basicConfig(level=LOGLEVEL)
