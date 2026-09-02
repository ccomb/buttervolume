.. image:: https://travis-ci.org/ccomb/buttervolume.svg?branch=master
   :target: https://travis-ci.org/ccomb/buttervolume
   :alt: Travis state


BTRFS Volume plugin for Docker
==============================

**What will Buttervolume allow you to do?**

- Quickly recover recent data after an exploit or failure of your web sites or applications
- Quickly rollback your data to a previous version after a failed upgrade
- Implement automatic upgrade of your applications without fear
- Keep an history of your data
- Make many backups without consuming more disk space than needed
- Build a resilient hosting cluster with data replication
- Quickly move your applications between nodes
- Create preconfigured or templated applications to deploy in seconds

**What can Buttervolume do?**

- Snapshot your Docker volumes
- Restore a snapshot to its original volume or under a new volume
- List and remove existing snapshots of your volumes
- Clone your Docker volumes
- Replicate a volume to another host, to move an application or survive a
  host failure
- Synchronize a volume between several hosts that all write to it at once
- Run periodic snapshots, sync or replication of your volumes
- Remove your old snapshots periodically
- Pause or resume the periodic jobs, either individually or globally

**How does it work?**

Buttervolume is a Docker Volume Plugin that stores each Docker volume as a
BTRFS subvolume.


.. contents::


Introduction
************

`BTRFS <https://btrfs.wiki.kernel.org/>`_ is a next-generation copy-on-write
filesystem with subvolume and snapshot support. A BTRFS `subvolume
<https://btrfs.wiki.kernel.org/index.php/SysadminGuide#Subvolumes>`_ can be
seen as an independant file namespace that can live in a directory and can be
mounted as a filesystem and snapshotted individually.

On the other hand, `Docker volumes
<https://docs.docker.com/storage/volumes/>`_ are commonly used
to store persistent data of stateful containers, such as a MySQL/PostgreSQL
database or an upload directory of a CMS. By default, Docker volumes are just
local directories in the host filesystem.  A number of `Volume plugins
<https://docs.docker.com/engine/extend/legacy_plugins/#/volume-plugins>`_
already exist for various storage backends, including distributed filesystems,
but small clusters often can't afford to deploy a distributed filesystem.

We believe BTRFS subvolumes are a powerful and lightweight storage solution for
Docker volumes, allowing fast and easy replication (and backup) across several
nodes of a small cluster.

Prerequisites
*************

Make sure the directory ``/var/lib/buttervolume/`` is living in a BTRFS
filesystem. It can be a BTRFS mountpoint or a BTRFS subvolume or both.

**Initial Setup**

Use the ``buttervolume init`` command to easily set up the BTRFS environment::

    # Default setup - checks /var/lib/buttervolume is on BTRFS and creates required directories
    sudo buttervolume init
    
    # Custom BTRFS path - uses existing BTRFS filesystem at specified path
    sudo buttervolume init --path /custom/btrfs/path
    
    # Image file - creates a new BTRFS image file
    sudo buttervolume init --file /var/lib/docker/btrfs.img --size 20G

The init command must be run as root and automatically creates the required directory structure (config, ssh, volumes, snapshots).

**Manual Setup (Alternative)**

If you prefer manual setup, create the directories for the config and ssh on the host::

    sudo mkdir /var/lib/buttervolume
    sudo mkdir /var/lib/buttervolume/config
    sudo mkdir /var/lib/buttervolume/ssh


Build and run as a contributor
******************************

If you want to be a contributor, read this chapter. Otherwise jump to the next section.

You first need to create a root filesystem for the plugin, using the provided Dockerfile::

    git clone https://github.com/ccomb/buttervolume
    ./build.sh

By default the plugin is built for the latest commit (HEAD). You can build another version by specifying it like this::

    ./build.sh 3.7

At this point, you can set the SSH_PORT option for the plugin by running::

    docker plugin set ccomb/buttervolume SSH_PORT=1122

Note that this option is only relevant if you use the replication feature between two nodes.

Now you can enable the plugin, which should start buttervolume in the plugin
container::

    docker plugin enable ccomb/buttervolume:HEAD

You can check it is responding by running a buttervolume command using aliases::

    export RUNCROOT=/run/docker/runtime-runc/plugins.moby/ # or /run/docker/plugins/runtime-root/plugins.moby/
    alias drunc="sudo runc --root $RUNCROOT"
    alias buttervolume="drunc exec -t $(drunc list|tail -n+2|awk '{print $1}') buttervolume"
    buttervolume scheduled

Increase the log level by writing a `/var/lib/buttervolume/config/config.ini` file with::

    [DEFAULT]
    TIMER = 120

Then check the logs with::

    sudo journalctl -f -u docker.service

You can also locally install and run the plugin in the foreground with::

    uv venv
    uv sync --extra dev
    sudo .venv/bin/buttervolume run

Then you can use the buttervolume CLI that was installed in developer mode in the venv::

    .venv/bin/buttervolume --version


Install and run as a user
*************************

If the plugin is already pushed to the image repository, you can install it with::

    docker plugin install ccomb/buttervolume

Check it is running::

    docker plugin ls

Find your runc root, then define useful aliases or functions.

**Option 1: Using aliases (quick setup)**::

    export RUNCROOT=/run/docker/runtime-runc/plugins.moby/ # or /run/docker/plugins/runtime-root/plugins.moby/
    alias drunc="sudo runc --root $RUNCROOT"
    alias buttervolume="drunc exec -t $(drunc list|tail -n+2|awk '{print $1}') buttervolume"

**Option 2: Using functions (recommended for .bash_profile)**::

    function drunc () {
      RUNCROOT=/run/docker/runtime-runc/plugins.moby/ # or /run/docker/plugins/runtime-root/plugins.moby/
      sudo runc --root $RUNCROOT $@
    }
    function buttervolume () {
      drunc exec -t $(docker plugin ls --no-trunc  | grep 'ccomb/buttervolume:latest' |  awk '{print $1}') buttervolume $@
    }

And try a buttervolume command::

    buttervolume scheduled

Or create a volume with the driver. Note that the name of the driver is the
name of the plugin::

    docker volume create -d ccomb/buttervolume:latest myvolume


Upgrade
*******

You must force disable it before reinstalling it (as explained in the docker documentation)::

    docker plugin disable -f ccomb/buttervolume
    docker plugin rm -f ccomb/buttervolume
    docker plugin install ccomb/buttervolume


Using buttervolume CLI in a container
*************************************

If you need to run the buttervolume CLI from within a Docker container, you need to ensure proper access to the Docker daemon and plugin sockets.

**Method 1: Mount required directories**::

    docker run --rm -it \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v /run/docker/plugins:/run/docker/plugins \
      your-container-with-buttervolume buttervolume scheduled

**Method 2: Override socket path**::

    # If you know the exact socket path
    docker run --rm -it \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v /run/docker/plugins:/run/docker/plugins \
      -e BUTTERVOLUME_SOCKET=/run/docker/plugins/<plugin-id>/btrfs.sock \
      your-container-with-buttervolume buttervolume scheduled

**Creating a CLI container**::

    # Dockerfile
    FROM python:alpine
    RUN pip install buttervolume
    COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker

    # Usage
    docker build -t buttervolume-cli .
    docker run --rm -it \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v /run/docker/plugins:/run/docker/plugins \
      buttervolume-cli buttervolume scheduled


Migrating existing Docker volumes
**********************************

To migrate existing Docker volumes to buttervolume, the approach depends on whether your volumes are already on a BTRFS filesystem.

**If /var/lib/docker/volumes is on the same BTRFS partition as /var/lib/buttervolume:**

You can efficiently move or snapshot existing volumes::

    # Stop containers using the volumes first
    docker stop <container-using-volume>
    
    # Method 1: Move the volume (fastest)
    sudo mv /var/lib/docker/volumes/<volume-name>/_data /var/lib/buttervolume/volumes/<volume-name>
    
    # Method 2: Create BTRFS snapshot (preserves original)
    sudo btrfs subvolume snapshot /var/lib/docker/volumes/<volume-name>/_data /var/lib/buttervolume/volumes/<volume-name>

**If /var/lib/docker/volumes is NOT on BTRFS:**

You need to copy the data::

    # Stop containers using the volumes first
    docker stop <container-using-volume>
    
    # Create buttervolume and copy data
    docker volume create -d ccomb/buttervolume:latest <volume-name>
    sudo cp -ar /var/lib/docker/volumes/<volume-name>/_data/* /var/lib/buttervolume/volumes/<volume-name>/
    
    # Remove old volume after verifying data integrity
    docker volume rm <volume-name>

**Update your containers:**

After migration, update your containers to use the new buttervolume driver::

    # In docker-compose.yml
    volumes:
      my-data:
        driver: ccomb/buttervolume:latest
    
    # Or with docker run
    docker run -v my-data:/data --volume-driver=ccomb/buttervolume:latest myimage

**Verification:**

Test that your migrated volumes work correctly before removing the originals::

    # Check volume exists
    docker volume ls -f driver=ccomb/buttervolume:latest
    
    # Test with a temporary container
    docker run --rm -v <volume-name>:/test --volume-driver=ccomb/buttervolume:latest alpine ls -la /test


Configure
*********

You can configure the following variables:

    * ``DRIVERNAME``: the full name of the driver (with the tag)
    * ``VOLUMES_PATH``: the path where the BTRFS volumes are located
    * ``SNAPSHOTS_PATH``: the path where the BTRFS snapshots are located
    * ``TEST_REMOTE_PATH``: the path during unit tests where the remote BTRFS snapshots are located
    * ``SCHEDULE``: the path of the scheduler configuration
    * ``LAST_RUNS``: the path of the file where the scheduler writes down the date
      of the last successful run of each scheduled job, so that a restart does not
      run everything again
    * ``RUNPATH``: the path of the docker run directory (/run/docker)
    * ``SOCKET``: the path of the unix socket where buttervolume listens
    * ``TIMER``: the number of seconds between two runs of the scheduler jobs
    * ``SEND_TIMEOUT``: the number of seconds a snapshot send to another node may take before being killed
    * ``DTFORMAT``: the format of the datetime in the logs and in the snapshot
      names. As a snapshot name has to remain usable in a path and in a command,
      the format may only produce letters, digits, dot, colon, underscore and dash
    * ``LOGLEVEL``: the Python log level (INFO, DEBUG, etc.)

The configuration can be done in this order of priority:

    #. from an environment variable prefixed with ``BUTTERVOLUME_`` (ex: ``BUTTERVOLUME_TIMER=120``)
    #. from the [DEFAULT] section of the ``/etc/buttervolume/config.ini`` file
       inside the container or ``/var/lib/buttervolume/config/config.ini`` on the
       host

Example of ``config.ini`` file::

    [DEFAULT]
    TIMER = 120

If none of this is configured, the following default values are used:

    * ``DRIVERNAME = ccomb/buttervolume:latest``
    * ``VOLUMES_PATH = /var/lib/buttervolume/volumes/``
    * ``SNAPSHOTS_PATH = /var/lib/buttervolume/snapshots/``
    * ``TEST_REMOTE_PATH = /var/lib/buttervolume/received/``
    * ``SCHEDULE = /etc/buttervolume/schedule.csv``
    * ``LAST_RUNS = /var/lib/buttervolume/lastruns.csv``
    * ``RUNPATH = /run/docker``
    * ``SOCKET = $RUNPATH/plugins/btrfs.sock`` # only if run manually
    * ``TIMER = 60``
    * ``SEND_TIMEOUT = 600``
    * ``DTFORMAT = %Y-%m-%dT%H:%M:%S.%f``
    * ``LOGLEVEL = INFO``


Usage
*****

Running the plugin
------------------

The normal way to run it is as a new-style Docker Plugin as described above in
the "Install and run" section, which will start it automatically.  This will
create a ``/run/docker/plugins/<uuid>/btrfs.sock`` file to be used by the
Docker daemon. The ``<uuid>`` is the unique identifier of the `runc/OCI`
container running it.  This means you can probably run several versions of the
plugin simultaneously but this is currently not recommended unless you keep in
mind the volumes and snapshots are in the same place for the different
versions. Otherwise you can configure a different path for the volumes and
snapshots of each different versions using the ``config.ini`` file.

Then the name of the volume driver is the name of the plugin::

    docker volume create -d ccomb/buttervolume:latest myvolume

or::

    docker volume create --volume-driver=ccomb/buttervolume:latest

When creating a volume, you can choose to disable copy-on-write or enable compression
on a per-volume basis. Just use the `-o` or `--opt` option as defined in the `Docker documentation
<https://docs.docker.com/engine/reference/commandline/volume_create/#options>`_ ::

    docker volume create -d ccomb/buttervolume -o copyonwrite=false myvolume
    docker volume create -d ccomb/buttervolume -o compression=true myvolume
    docker volume create -d ccomb/buttervolume -o compression=zlib myvolume

Available options:

- ``copyonwrite``: ``true`` (default) or ``false`` - enables/disables copy-on-write
- ``compression``: ``false`` (default), ``true``, ``zlib``, ``lzo``, or ``zstd`` - enables BTRFS compression for new files

Copy-On-Write is enabled by default. You can disable it if you really want.
Why disabling copy-on-write? If your docker volume stores databases such as
PostgreSQL or MariaDB, the copy-on-write feature may hurt performance, though
the latest kernels have improved a lot. The good news is that disabling
copy-on-write does not prevent from doing snaphots.

Running the plugin locally or in legacy mode
--------------------------------------------

If you installed it locally as a Python distribution, you can also
start it manually with::

    sudo buttervolume run

In this case it will create a unix socket in ``/run/docker/plugins/btrfs.sock``
for use by Docker with the legacy plugin system. Then the name of the volume
driver is the name of the socket file::

    docker volume create -d btrfs myvolume

or::

    docker create --volume-driver=btrfs

When started, the plugin will also start its own scheduler to run periodic jobs
(such as a snapshot, replication, purge or synchronization)


Creating and deleting volumes
-----------------------------

Once the plugin is running, whenever you create a container you can specify the
volume driver with ``docker create --volume-driver=ccomb/buttervolume --name <name>
<image>``.  You can also manually create a BTRFS volume with ``docker volume
create -d ccomb/buttervolume``. It also works with docker-compose, by specifying the
``ccomb/buttervolume`` driver in the ``volumes`` section of the compose file.

When you delete the volume with ``docker rm -v <container>`` or ``docker volume
rm <volume>``, the BTRFS subvolume is deleted. If you snapshotted the volume
elsewhere in the meantime, the snapshots won't be deleted.


Managing volumes and snapshots
------------------------------

When buttervolume is installed, it provides a command line tool
``buttervolume``, with the following subcommands::

    init                Initialize BTRFS filesystem for buttervolume
    run                 Run the plugin in foreground
    snapshot            Snapshot a volume
    snapshots           List snapshots
    schedule            Schedule, unschedule, pause or resume a periodic snapshot, replication, synchronization or purge
    scheduled           List, pause or resume all the scheduled actions
    restore             Restore a snapshot (optionally to a different volume)
    clone               Clone a volume as new volume
    send                Send a snapshot to another host
    replicate           Snapshot a volume and send the snapshot to another host
    receive             Receive from another host its last snapshot of a volume
    sync                Synchronise a volume from a remote host volume
    rm                  Delete a snapshot
    purge               Purge old snapshot using a purge pattern


Create a snapshot
-----------------

You can create a readonly snapshot of the volume with::

    buttervolume snapshot <volume>

The volumes are currently expected to live in ``/var/lib/buttervolume/volumes`` and
the snapshot will be created in ``/var/lib/buttervolume/snapshots``, by appending the
datetime to the name of the volume, separated with ``@``.

A volume nobody wrote to since its last snapshot is not snapshotted again: the
command prints the name of the existing snapshot, which is the one holding the
state of the volume. So a snapshot scheduled every minute on a volume at rest
costs one subvolume, not one per minute.


List the snapshots
------------------

You can list all the snapshots::

    buttervolume snapshots

or just the snapshots corresponding to a volume with::

    buttervolume snapshots <volume>

``<volume>`` is the name of the volume, not the full path. It is expected
to live in ``/var/lib/buttervolume/volumes``.


Restore a snapshot
------------------

You can restore a snapshot as a volume. What the volume holds is kept as a
snapshot first, then the volume is deleted and replaced with the snapshot. If
you provide a volume name instead of a snapshot, the **latest snapshot** is
restored. So no data is lost if you do something wrong. Please take care of
stopping the container before restoring a snapshot::

    buttervolume restore <snapshot>

The command prints the name of the snapshot that holds what the volume held.
That is a new one only when the volume had changed since its last snapshot:
when it had not, that last snapshot is the one, and nothing is written. An
empty volume has nothing to keep, and a volume that already holds exactly the
snapshot asked for is left alone.

``<snapshot>`` is the name of the snapshot, not the full path. It is expected
to live in ``/var/lib/buttervolume/snapshots``.

By default, the volume name corresponds to the volume the snapshot was created
from. But you can optionally restore the snapshot to a different volume name by
adding the target as the second argument::

    buttervolume restore <snapshot> <volume>


Clone a volume
------------------

You can clone a volume as a new volume. The current volume will be cloned
as a new volume name given as parameter. Please take care of stopping the
container before cloning a volume::

    buttervolume clone <volume> <new_volume>

``<volume>`` is the name of the volume to be cloned, not the full path. It is expected
to live in ``/var/lib/buttervolume/volumes``.
``<new_volume>`` is the name of the new volume to be created as clone of previous one,
not the full path. It is expected to be created in ``/var/lib/buttervolume/volumes``.


Delete a snapshot
-----------------

You can delete a snapshot with::

    buttervolume rm <snapshot>

``<snapshot>`` is the name of the snapshot, not the full path. It is expected
to live in ``/var/lib/buttervolume/snapshots``.


Choosing between replication and synchronization
------------------------------------------------

Buttervolume offers two ways to carry the data of a volume to another host,
and they are not two flavours of the same thing: one replaces, the other
merges. Picking the wrong one either loses data or corrupts it, so the choice
is worth a minute.

Say the volume ``filestore`` exists on both ``host1`` and ``host2``, with a
container running on each. ``host1`` has just written ``a.txt``, and ``host2``
has just written ``b.txt``.

**Replication** sends a snapshot of the volume of ``host1`` to ``host2``.
Restoring it there gives ``host2`` exactly what ``host1`` holds, and ``b.txt``
is gone. What travels is the volume as a whole, as it stood at one instant.

**Synchronization** pulls the files of the volume of ``host1`` into the live
volume of ``host2``, which then holds both ``a.txt`` and ``b.txt``. No file is
deleted, but a file that exists on both hosts is replaced by the copy that
comes in, even when the local one is the newer of the two.

So the question to ask is not which one is faster. It is how many hosts write
to the volume.

**One host writes at a time: replicate.** This is the failover case, and the
"move this application to another node" case. It works with any data,
including a database, because a BTRFS snapshot is a coherent image of the
whole volume at one instant. What replication cannot do is merge: two hosts
replicating to each other and restoring would each throw away the work of the
other, and the last one to speak would win.

**Several hosts write at the same time: synchronize.** Each host pulls from
all the others, so they converge. This only holds for one shape of data: a
directory of files that are added and never modified in place, such as a store
of attachments named after their checksum, where the file ``3f2a9c...`` has
the same content everywhere and the direction of the copy does not matter.
``rsync`` merges file by file, and data whose coherence is global cannot
survive that: a PostgreSQL data directory synchronized this way is destroyed.

Synchronization never deletes, and that is deliberate. There is no
``--delete`` in the ``rsync`` command, because when you pull from several
hosts, a file deleted on another host and a file never created there look
exactly the same: absent. Deleting on that evidence would make the pull of
each host erase the contributions of the others. So a file you delete locally
comes back at the next synchronization, and emptying such a volume for good
means removing the scheduled jobs on every host first.

The two can serve the same volume: synchronize between the hosts that run the
application, and replicate to a host that runs nothing and keeps the history.


Replicate a snapshot to another host
------------------------------------

You can incrementally send snapshots to another host, so that data is
replicated to several machines, allowing to quickly move a stateful docker
container to another host. The first snapshot is first sent as a whole, then
the next snapshots are used to only send the difference between the current one
and the previous one. This allows to replicate snapshots very often without
consuming a lot of bandwith or disk space::

    buttervolume send <host> <snapshot>

``<snapshot>`` is the name of the snapshot, not the full path. It is expected
to live in ``/var/lib/buttervolume/snapshots`` and is replicated to the same path on
the remote host.

To snapshot a volume and send that snapshot in one step, which is what a
scheduled replication does at each round, name the volume instead::

    buttervolume replicate <host> <volume>

It prints the name of the snapshot the remote host now holds. A volume
unchanged since its last snapshot sends that one, and sends nothing when the
remote host already has it.

What the remote host already holds is read from the trace kept locally,
named ``<volume>@<datetime>@<host>``. That trace is written after each send,
and after each receive from that host, since a snapshot that has just arrived
from a host is a snapshot that host holds. So a snapshot whose trace is there
is not sent a second time, and a copy deleted on the remote host behind
Buttervolume's back goes unnoticed: delete the trace as well, and the next
send carries the whole volume again.

Before a snapshot is sent, the remote host is asked what the last snapshot of
that volume to appear there is. When that one is unknown here, neither held
nor traced, the volume over there has moved on without this host: another
host sent its work there, or somebody restored an older snapshot there. A send
over that would make this host's copy pass for the most recent one on every
host and bury the other history under it, so it is refused, and the error
says which snapshot to receive first, or to delete over there.

A replication scheduled on a volume at rest costs nothing at all: the snapshot
it would take is not taken, its trace says the remote host already has it, and
nothing crosses the network, not even that question. Replicating the same
volume to two hosts every minute is a reasonable thing to schedule.


``<host>`` is the hostname or IP address of the remote host. The snapshot is
currently sent using BTRFS send/receive through ssh, with an ssh server direcly
included in the plugin. 

**SSH Configuration Requirements:**

- SSH keys and configuration must be in ``/var/lib/buttervolume/ssh/`` (NOT in ``~/.ssh/``)
- SSH keys must be present and authorized on target hosts  
- Enable ``StrictHostKeyChecking no`` in ``/var/lib/buttervolume/ssh/config``
- **Important**: Restart Docker daemons after any SSH configuration changes

The ssh server's own host keys are made on the first start, in
``/var/lib/buttervolume/ssh/``, and kept from one restart to the next. They are
deliberately not part of the plugin image: an image is public, so a key built
into it would be the same one on every installation that pulls it, and anyone
holding it could pass for the host a snapshot is being sent to.

Versions up to 3.13 did build the host keys into the image. On the first start
after upgrading, this plugin presents a new key, and every host replicating to
it reports a changed host key until its ``known_hosts`` is refreshed. Those
published keys should be treated as known to everyone.

The default SSH_PORT of the ssh server included in the plugin is **1122**. You can
change it with `docker plugin set ccomb/buttervolume SSH_PORT=<PORT>` before
enabling the plugin.

Receive a snapshot from another host
------------------------------------

The other direction, for a host that wants back what another one holds::

    buttervolume receive <host> <volume>

It names a **volume**, where ``send`` names a snapshot: whoever receives does
not know what the other host has, which is precisely the question this asks.
The last snapshot of that volume that appeared on that host, taken there or
received there, is fetched into ``/var/lib/buttervolume/snapshots``, and its
name is printed. Only the difference crosses the network when the two hosts
still share an older snapshot to build on.

The command **does not restore anything**. It brings a snapshot over, and
which snapshot becomes the volume stays a separate, explicit decision::

    buttervolume receive node2 www
    buttervolume restore www

A host that keeps no snapshot of that volume and a host that could not answer
are two different answers, and never the same one. An unreachable host, a
refused connection, an ssh that takes too long: each is reported as the error
it is. Only a host that answered and holds nothing is reported as holding
nothing. Reading silence as "there is nothing over there" is how the good copy
of a volume gets replaced by an older one.

A snapshot carries in its name the moment it was taken, by the clock of the
machine that took it, and that date is not what decides which one is the last.
BTRFS numbers subvolumes in the order it creates them, and a received snapshot
is created on arrival, so "the last one" is read from that order on the host
that answers. A host whose clock runs ahead does not pass its copy off as the
most recent one.


Synchronize a volume from another host volume
---------------------------------------------

Synchronization pulls the files of a remote volume of the **same name** into
the local volume, merging them with what is already there. Read `Choosing
between replication and synchronization`_ first: this is the right tool only
when several hosts write to the volume at the same time, and only for data
that survives a file by file merge::

    buttervolume sync <volume> <host1> [<host2>][...]

The intent is to synchronize a volume between several hosts running
containers, so you should schedule that action on each node, from all the
other hosts.

The local volume has to exist before it can be synchronized: a synchronization
pulls files into a volume, it does not create one. Create it on the new host
first, with ``docker volume create`` or by starting the container that uses
it.

A scheduled synchronization snapshots the volume before it pulls, and logs the
name of that snapshot, so that a transfer stopped halfway can be recovered
from. The one-shot ``buttervolume sync`` command does not: it writes straight
into the live volume.

.. note::

   As we are pulling data from multiple hosts we never remove data, consider
   removing scheduled actions before removing data on each hosts.

.. warning::

   Make sure your application is able to handle such synchronisation. A file
   by file merge cannot keep globally coherent data coherent: do not
   synchronize the volume of a database, replicate it instead.


Purge old snapshots
-------------------

You can purge old snapshot corresponding to the specified volume, using a retention pattern::

    buttervolume purge <pattern> <volume>

If you're unsure whether you retention pattern is correct, you can run the
purge with the ``--dryrun`` option, to inspect what snapshots would be deleted,
without deleting them::

    buttervolume purge --dryrun <pattern> <volume>

``<volume>`` is the name of the volume, not the full path. It is expected
to live in ``/var/lib/buttervolume/volumes``.

``<pattern>`` is the snapshot retention pattern. It is a colon-separated
list of time length specifiers with a unit. Units can be ``m`` for minutes,
``h`` for hours, ``d`` for days, ``w`` for weeks, ``y`` for years. The
specifiers must be given from the shortest to the longest, and a pattern of a
single specifier is allowed.

Here are a few examples of retention patterns:

- ``4h:1d:2w:2y``
    Keep all snapshots in the last four hours, then keep only one snapshot
    every four hours during the first day, then one snapshot per day during
    the first two weeks, then one snapshot every two weeks during the first
    two years, then delete everything after two years.

- ``4h:1w``
    keep all snapshots during the last four hours, then one snapshot every
    four hours during the first week, then delete older snapshots.

- ``2h``
    keep all snapshots during the last two hours, then delete older snapshots.
    Older versions of Buttervolume wrote this pattern ``2h:2h``, which is now
    refused, and which ``buttervolume scheduled --auto-convert-old-patterns``
    rewrites in the schedule.

Whatever the pattern says, a purge never deletes what a replication needs: the
trace of the last send to a host, named ``<volume>@<datetime>@<host>``, and the
snapshot it was made from, which is the parent the next incremental send is
built on. Deleting them would send the whole volume over the network again. So
when you stop replicating a volume to a host, delete that pair by hand,
otherwise it stays there for good.


Schedule a job
--------------

You can schedule, pause or resume a periodic job, such as a snapshot, a
replication, a synchronization or a purge. The schedule it self is stored in
``/etc/buttervolume/schedule.csv``.

**Schedule a snapshot** of a volume every 60 minutes::

    buttervolume schedule snapshot 60 <volume>

Pause this schedule::

  buttervolume schedule snapshot pause <volume>

Resume this schedule::

  buttervolume schedule snapshot resume <volume>

Remove this schedule by specifying a timer of 0 min (or `delete`)::

    buttervolume schedule snapshot 0 <volume>

**Schedule a replication** of volume ``foovolume`` to ``remote_host``::

    buttervolume schedule replicate:remote_host 3600 foovolume

Remove the same schedule::

    buttervolume schedule replicate:remote_host 0 foovolume

**Schedule a purge** every hour of the snapshots of volume ``foovolume``, but
keep all the snapshots in the last 4 hours, then only one snapshot every 4
hours during the first week, then one snapshot every week during one year, then
delete all snapshots after one year::

    buttervolume schedule purge:4h:1w:1y 60 foovolume

Remove the same schedule::

    buttervolume schedule purge:4h:1w:1y 0 foovolume

Using the right combination of snapshot schedule timer, purge schedule timer
and purge retention pattern, you can create you own backup strategy, from the
simplest ones to more elaborate ones. A common one is the following::

    buttervolume schedule snapshot 1440 <volume>
    buttervolume schedule purge:1d:4w:1y 1440 <volume>

It should create a snapshot every day, then purge snapshots everydays while
keeping all snapshots in the last 24h, then one snapshot per day during one
month, then one snapshot per month during only one year.

**Schedule a synchronization** of volume ``foovolume`` from ``remote_host1``
and ``remote_host2``::

    buttervolume schedule synchronize:remote_host1,remote_host2 60 foovolume

Remove the same schedule::

    buttervolume schedule synchronize:remote_host1,remote_host2 0 foovolume


List, pause or resume all scheduled jobs
----------------------------------------

You can list all the scheduled job with::

    buttervolume scheduled

or::

    buttervolume scheduled list

It will display the schedule in the same format used for adding the schedule,
which is convenient to remove an existing schedule or add a similar one.

Pause all the scheduled jobs::

  buttervolume scheduled pause

Resume all the scheduled jobs::

  buttervolume scheduled resume

The global job pause/resume feature is implemented separately from the
individual job pause/resume. So it will not affect your individual
pause/resume settings.

Copy-on-write
-------------

Copy-On-Write is enabled by default. You can disable it if you really want.

Why disabling copy-on-write? If your docker volume stores databases such as
PostgreSQL or MariaDB, the copy-on-write feature may hurt performance, though
the latest kernels have improved a lot. The good news is that disabling
copy-on-write does not prevent from doing snaphots.


Testing
*******

If your volumes directory is a BTRFS partition or volume, tests can be run
with::

    ./test.sh


Working without a BTRFS partition
*********************************

If you have no BTRFS partitions or volumes you can setup a virtual partition
in a file as follows (tested on Debian 8):

Setup BTRFS virtual partition::

    sudo qemu-img create /var/lib/docker/btrfs.img 10G
    sudo mkfs.btrfs /var/lib/docker/btrfs.img

.. note::

   you can ignore the error, in fact the new FS is formatted

Mount the partition somewhere temporarily to create 3 new BTRFS subvolumes::

    sudo -s
    mkdir /tmp/btrfs_mount_point
    mount -o loop /var/lib/docker/btrfs.img /tmp/btrfs_mount_point/
    btrfs subvolume create /tmp/btrfs_mount_point/snapshots
    btrfs subvolume create /tmp/btrfs_mount_point/volumes
    btrfs subvolume create /tmp/btrfs_mount_point/received
    umount /tmp/btrfs_mount_point/
    rm -r /tmp/btrfs_mount_point/

Stop docker, create required mount point and restart docker::

    systemctl stop docker
    mkdir -p /var/lib/buttervolume/volumes
    mkdir -p /var/lib/buttervolume/snapshots
    mkdir -p /var/lib/buttervolume/received
    mount -o loop,subvol=volumes /var/lib/docker/btrfs.img /var/lib/buttervolume/volumes
    mount -o loop,subvol=snapshots /var/lib/docker/btrfs.img /var/lib/buttervolume/snapshots
    mount -o loop,subvol=received /var/lib/docker/btrfs.img /var/lib/buttervolume/received
    systemctl start docker

Once you are done with your test, you can unmount those volumes and you will
find back your previous docker volumes::


    systemctl stop docker
    umount /var/lib/buttervolume/volumes
    umount /var/lib/buttervolume/snapshots
    umount /var/lib/buttervolume/received
    systemctl start docker
    rm /var/lib/docker/btrfs.img


Migrate to version 3
********************

If you're currently using Buttervolume 1.x or 2.0 in production, you must
carefully follow the guidelines below to migrate to version 3.

First copy the ssh and config files and disable the scheduler::

    sudo -s
    docker cp buttervolume_plugin_1:/etc/buttervolume /var/lib/buttervolume/config
    docker cp buttervolume_plugin_1:/root/.ssh /var/lib/buttervolume/ssh
    mv /var/lib/buttervolume/config/schedule.csv /var/lib/buttervolume/config/schedule.csv.disabled

Then stop all your containers, excepted buttervolume

Now snapshot and delete all your volumes::

    volumes=$(docker volume ls -f driver=ccomb/buttervolume:latest --format "{{.Name}}")
    # or: # volumes=$(docker volume ls -f driver=ccomb/buttervolume:latest|tail -n+2|awk '{print $2}')
    echo $volumes
    for v in $volumes; do docker exec buttervolume_plugin_1 buttervolume snapshot $v; done
    for v in $volumes; do docker volume rm $v; done

Then stop the buttervolume container, **remove the old btrfs.sock file**, and
restart docker::

    docker stop buttervolume_plugin_1
    docker rm -v buttervolume_plugin_1
    rm /run/docker/plugins/btrfs.sock
    systemctl stop docker

If you were using Buttervolume 1.x, you must move your snapshots to the new location::

    mkdir /var/lib/buttervolume/snapshots
    cd /var/lib/docker/snapshots
    for i in *; do btrfs subvolume snapshot -r $i /var/lib/buttervolume/snapshots/$i; done

Restore /var/lib/docker/volumes as the original folder::

    cd /var/lib/docker
    mkdir volumes.new
    mv volumes/* volumes.new/
    umount volumes  # if this was a mounted btrfs subvolume
    mv volumes.new/* volumes/
    rmdir volumes.new
    systemctl start docker

Change your volume configurations (in your compose files) to use the new
``ccomb/buttervolume:latest`` driver name instead of ``btrfs``

Then start the new buttervolume 3.x as a managed plugin and check it is started::

    docker plugin install ccomb/buttervolume:latest
    docker plugin ls

Then recreate all your volumes with the new driver and restore them from the snapshots::

    for v in $volumes; do docker volume create -d ccomb/buttervolume:latest $v; done
    export RUNCROOT=/run/docker/runtime-runc/plugins.moby/ # or /run/docker/plugins/runtime-root/plugins.moby/
    alias drunc="sudo runc --root $RUNCROOT"
    alias buttervolume="drunc exec -t $(drunc list|tail -n+2|awk '{print $1}') buttervolume"
    # WARNING : check the the volume you will restore are the correct ones
    for v in $volumes; do buttervolume restore $v; done

Then restart your containers, check they are ok with the correct data.

Reenable the schedule::

    mv /var/lib/buttervolume/config/schedule.csv.disabled /var/lib/buttervolume/config/schedule.csv

Credits
*******

Thanks to:

- Christophe Combelles
- Pierre Verkest
- Marcelo Ochoa
- Christoph Rist
- Philip Nagler-Frank
- Yoann MOUGNIBAS

