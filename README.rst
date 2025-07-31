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
- Replicate or Sync your volumes to another host
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

You should also create the directories for the config and ssh on the host::

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

    python3 -m venv venv
    ./venv/bin/python setup.py develop
    sudo ./venv/bin/buttervolume run

Then you can use the buttervolume CLI that was installed in developer mode in the venv::

    ./venv/bin/buttervolume --version


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


Configure
*********

You can configure the following variables:

    * ``DRIVERNAME``: the full name of the driver (with the tag)
    * ``VOLUMES_PATH``: the path where the BTRFS volumes are located
    * ``SNAPSHOTS_PATH``: the path where the BTRFS snapshots are located
    * ``TEST_REMOTE_PATH``: the path during unit tests where the remote BTRFS snapshots are located
    * ``SCHEDULE``: the path of the scheduler configuration
    * ``RUNPATH``: the path of the docker run directory (/run/docker)
    * ``SOCKET``: the path of the unix socket where buttervolume listens
    * ``TIMER``: the number of seconds between two runs of the scheduler jobs
    * ``DTFORMAT``: the format of the datetime in the logs
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
    * ``RUNPATH = /run/docker``
    * ``SOCKET = $RUNPATH/plugins/btrfs.sock`` # only if run manually
    * ``TIMER = 60``
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

    run                 Run the plugin in foreground
    snapshot            Snapshot a volume
    snapshots           List snapshots
    schedule            Schedule, unschedule, pause or resume a periodic snapshot, replication, synchronization or purge
    scheduled           List, pause or resume all the scheduled actions
    restore             Restore a snapshot (optionally to a different volume)
    clone               Clone a volume as new volume
    send                Send a snapshot to another host
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

You can restore a snapshot as a volume. The current volume will first
be snapshotted, deleted, then replaced with the snapshot.  If you provide a
volume name instead of a snapshot, the **latest snapshot** is restored. So no
data is lost if you do something wrong. Please take care of stopping the
container before restoring a snapshot::

    buttervolume restore <snapshot>

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


``<host>`` is the hostname or IP address of the remote host. The snapshot is
currently sent using BTRFS send/receive through ssh, with an ssh server direcly
included in the plugin. This requires that ssh keys be present and already
authorized on the target host (under ``/var/lib/buttervolume/ssh``), and that
the ``StrictHostKeyChecking no`` option be enabled in
``/var/lib/buttervolume/ssh/config`` on local host.

Please note you have to restart you docker daemons each time you change ssh configuration.

The default SSH_PORT of the ssh server included in the plugin is **1122**. You can
change it with `docker plugin set ccomb/buttervolume SSH_PORT=<PORT>` before
enabling the plugin.

Synchronize a volume from another host volume
---------------------------------------------

You can receive data from a remote volume, so in case there is a volume on
the remote host with the **same name**, it will get new and most recent data
from the distant volume and replace in the local volume. Before running the
``rsync`` command a snapshot is made on the local machine to manage recovery::

    buttervolume sync <volume> <host1> [<host2>][...]

The intent is to synchronize a volume between multi hosts on running
containers, so you should schedule that action on each nodes from all remote
hosts.

.. note::

   As we are pulling data from multiple hosts we never remove data, consider
   removing scheduled actions before removing data on each hosts.

.. warning::

   Make sure your application is able to handle such synchronisation


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

``<pattern>`` is the snapshot retention pattern. It is a semicolon-separated
list of time length specifiers with a unit. Units can be ``m`` for minutes,
``h`` for hours, ``d`` for days, ``w`` for weeks, ``y`` for years. The pattern
should have at least 2 items.

Here are a few examples of retention patterns:

- ``4h:1d:2w:2y``
    Keep all snapshots in the last four hours, then keep only one snapshot
    every four hours during the first day, then one snapshot per day during
    the first two weeks, then one snapshot every two weeks during the first
    two years, then delete everything after two years.

- ``4h:1w``
    keep all snapshots during the last four hours, then one snapshot every
    four hours during the first week, then delete older snapshots.

- ``2h:2h``
    keep all snapshots during the last two hours, then delete older snapshots.


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

**Schedule a syncrhonization** of volume ``foovolume`` from ``remote_host1``
abd ``remote_host2``::

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

