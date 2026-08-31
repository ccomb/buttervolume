CHANGELOG
=========

4.0 (unreleased)
****************

- A synchronization of a volume that does not exist locally is refused
  instead of creating one that cannot work. ``rsync`` creates the path it is
  given, so a mistyped name left a plain directory among the subvolumes: the
  volume list did not show it, no snapshot could be taken of it, and the
  volume of that name could never be created afterwards, ``btrfs`` refusing a
  subvolume where a directory already stood. Removing it meant deleting the
  directory by hand.

- The plugin starts again, and the ``buttervolume`` command can be run inside
  it. A docker plugin is not started from the image configuration, so the
  ``PATH`` and ``PYTHONPATH`` the Dockerfile sets were not there and the
  command was not found. The install now lands in ``/usr/bin`` and in the
  interpreter's site-packages directory, where the shell and Python already
  look, so nothing has to be set for it to be found: not for the plugin, not
  for a plain container, and not for a ``runc exec`` into the running plugin,
  which is how the command is called by hand.

  Since the install now writes where apk installs too, the Python packages come
  from one place only: ``pytest`` and ``webtest`` are taken with the others
  rather than from ``py3-pytest`` and ``py3-webtest``, which carried their own
  copy of ``waitress`` next to the one buttervolume asks for.

- The ssh server inside the plugin starts again. Alpine's sshd refuses to run
  unless ``/var/empty`` belongs to root, and that directory arrives owned by
  whoever unpacked the rootfs while building the plugin. The entrypoint gives
  it back to root.

- The ssh server inside the plugin now makes its own host keys on the first
  start, in ``/var/lib/buttervolume/ssh/``, instead of carrying the ones built
  into the image.

  Up to 3.13 those keys were made while the image was built, so they were part
  of the published plugin. Everyone pulling a given tag ran the same ssh
  identity, and anyone could read its private keys out of the image. Someone
  able to redirect the connection between two hosts could then pass for the
  host a snapshot was being sent to, and receive the contents of the volume,
  since the sender's ``known_hosts`` check would pass. Logging in to a plugin
  was never possible this way: that needs the client key, which has always been
  made per installation.

  On the first start after upgrading, the plugin presents a new host key, and
  every host replicating to it reports a changed host key until its
  ``known_hosts`` is refreshed. The keys published up to 3.13 should be treated
  as known to everyone.

- The plugin image is built on Alpine rather than Debian 12, and goes from
  185 MB to 72 MB. Nothing of buttervolume changed: the weight was the base
  system. Debian brought coreutils, perl, bash, dpkg, apt, util-linux and
  systemd, around 90 MB that a volume plugin never calls, systemd arriving as a
  dependency of the ssh server. Busybox and apk do the same work in 2 MB.

  Alpine packages tini, so the Dockerfile no longer downloads it from GitHub at
  build time, and curl leaves with it since nothing else used it. It packages
  uv too, so the build stage no longer runs an installer script either.

  The entrypoint is plain sh instead of bash, which Alpine does not carry, and
  starts sshd directly since there is no ``service`` command.

  The application is installed under a staging prefix in the build stage and
  copied over ``/usr``, so the Dockerfile no longer writes a Python version
  down anywhere and the next base system upgrade is one line.

  The image asks for ``e2fsprogs-extra`` by name, because busybox otherwise
  leaves its own smaller ``chattr`` and ``lsattr`` in place, and ``chattr`` is
  how the ``nocow`` and ``compression`` options are applied to a volume.

  Alpine 3.22 carries Python 3.12 and btrfs-progs 6.14, where Debian 12 carried
  Python 3.11. Buttervolume asks for 3.11 or later, so this changes nothing,
  but it is worth knowing.

- A volume asked to do without copy on write is now checked by a test. The
  plugin asks ``chattr`` for the C flag and swallows a failure, so an image
  missing ``chattr``, or carrying one that does not know that flag, would have
  produced ordinary volumes and said nothing.

- Buttervolume can now receive a snapshot from another host, where it could
  only send one. ``buttervolume receive <host> <volume>`` fetches the most
  recent snapshot that host keeps of that volume, incrementally when the two
  still share an older one, and prints its name. It restores nothing: which
  snapshot becomes the volume stays a separate decision.

  A host that keeps no snapshot of the volume and a host that could not answer
  are two different answers. The listing raises when ssh fails or takes too
  long, so an empty answer only ever means a host that answered and holds
  nothing. Reading silence as "there is nothing over there" is how the good
  copy of a volume gets replaced by an older one.

  The trace ``<volume>@<datetime>@<host>`` is written after a receive as it is
  after a send, since a snapshot that just arrived from a host is a snapshot
  that host holds. Without it, the first send back would carry the whole
  volume again.

- A purge no longer deletes what a replication needs. The trace of the last
  send to a host is a snapshot like any other, with a date the purge could
  read, so a retention pattern would delete it along with the snapshot it was
  made from. The next send then found no parent and carried the whole volume
  over the network again, which is exactly what an incremental send is there to
  avoid. The pair is now kept whatever the pattern says, and the README says
  that a host you stop replicating to leaves a pair to delete by hand.

- A volume nobody wrote to is no longer snapshotted again. A snapshot or a
  replication scheduled every minute wrote one identical subvolume per minute,
  for as long as the volume stayed at rest, and replicating to two hosts wrote
  two. The endpoint now compares the copy it just took with the previous
  snapshot and deletes it when it carries nothing new, answering the name of
  that previous snapshot. BTRFS cannot compare a live volume to a snapshot, so
  the copy has to be taken before it can be judged; it is the only thing this
  ever deletes, and it holds nothing that is not already elsewhere.

  The answer of ``/VolumeDriver.Snapshot`` carries a new ``Created`` field, and
  ``api.snapshot`` now returns the name and that flag. The scheduler needs it:
  a replication that fails deletes the snapshot it took for the occasion, and
  without the flag a network outage would have deleted a snapshot from an
  earlier round. ``buttervolume snapshot`` still prints one name and nothing
  else.

- Sending a snapshot the remote host already holds no longer destroys the copy
  it has. ``buttervolume send`` sends whatever snapshot it is named, and naming
  the same one twice made it its own parent: the send succeeded, the remote
  receive refused the result, and the fallback deleted the good remote copy
  before sending the whole volume again. Between the deletion and the end of
  that transfer the remote host held nothing. The trace of the previous send is
  now what answers the question, and a snapshot that is already there is
  refused with an empty error rather than sent.

- The README now says which of replication and synchronization to reach for,
  and why. The two were listed side by side as if they were two ways of doing
  the same thing, and they are opposites: a replication carries the volume
  whole and replaces it, a synchronization merges files into the live volume
  and never deletes any. Reading one as a cheaper version of the other costs
  data either way, so the choice has its own section now, and the two sections
  it chooses between point back at it. The synchronization section also
  promised that ``buttervolume sync`` snapshots the volume before pulling,
  which only the scheduled synchronization does: the one-shot command writes
  straight into the live volume, so whoever ran it by hand believed they had a
  recovery point they did not have.

- Buttervolume now says it needs Python 3.11 or later. Nothing declared it, so
  each version of ``uv`` invented its own floor and rewrote ``uv.lock`` on the
  next command it was given, and an installation on an older Python failed on
  the code instead of failing on the requirement. The plugin image has been
  running 3.11 all along, which is the floor now written down; the classifiers
  that still announced 3.8, 3.9 and 3.10 go with it.

- The scheduler now names the schedule line it could not read, instead of the
  one before it. The name, the action and the timer are only filled once a line
  has been read whole, so a line nobody could read was reported with the fields
  of the last one that went through, which is precisely the line that gave no
  trouble. The message now carries the line at fault, column by column,
  including the ``Active`` one those three fields left out.

- The scheduler now remembers between two daemons when each job last ran. That
  date lived in memory alone, and since a job the running daemon has never run
  starts at once, every restart ran everything that was scheduled: a daily
  purge on each reboot, a replication on each update of the plugin. It is now
  written to ``/var/lib/buttervolume/lastruns.csv``, one line per volume and
  action, next to the volumes rather than in the configuration. The restart
  that brings this version still runs everything once, since there is no file
  to read that day, and the ones after it pick the jobs up where they were
  left. A job that leaves the schedule, or whose deprecated purge pattern is
  converted, leaves its date behind: it costs a line, and that date is what
  comes back if the job comes back.

- A scheduled job the running daemon has never run now runs at once, instead
  of starting a day late. The scheduler kept in memory when each job last ran
  and forgot it when it stopped, and for a job it had never seen it pretended
  the last run was exactly one day old. A job of a shorter period therefore
  started immediately, while a weekly one waited six days after every restart
  and a monthly one twenty-nine, without a word.

- A scheduled purge that failed, and a scheduled synchronization that could
  not pull the data back, are now tried again at the next scheduler round.
  Their date was written down whether they had worked or not, so a failure
  meant waiting a whole period, usually a day, before anything tried again,
  while a failed snapshot or replication came back a minute later. A purge
  leaves nothing behind when it fails, so there is nothing to gain from
  waiting. A synchronization is the one job that still spends its turn on a
  failure, because it takes a snapshot of the volume before rsync overwrites
  it, and retrying every minute would leave one snapshot per minute behind
  while the other host is away.

- Saving a scheduled job no longer risks losing the whole schedule.
  ``schedule.csv`` was emptied before being written back, and it is rewritten
  in full every time a job is added, paused, resumed or removed, so an
  interruption in that window left an empty or half-written file. Nobody would
  notice: the next scheduler run reported no config file, or read half of the
  jobs, and the scheduled snapshots stopped in silence. The file is now written
  beside itself and renamed over the old one, which happens in one go.

- The scheduler now reports a line of ``schedule.csv`` whose action it does
  not know, instead of skipping it silently at every run. The guard meant to
  do this could never fire, so a misspelled ``replicat:host`` looked exactly
  like a replication that ran on time.

- A scheduled replication whose send failed is no longer reported as a
  success. The send answered with an error, the client logged it and returned
  a value nobody read, and the scheduler logged "Successfully replicated"
  right after, kept the snapshot it had taken for the occasion, and considered
  the job done until the next period. It now takes the same road as a
  replication that raised: the failure is reported and the snapshot removed.
  A purge and a synchronization that failed are reported as well.

- A scheduled replication or synchronization naming a host that Buttervolume
  refuses, such as an SSH alias with an underscore, now stops and says so at
  every run. Such a line could be written by an older version, and it never
  replicated anything, because the send refused that host too; but it went on
  snapshotting the volume every period while reporting a success.

- Scheduling a job that nobody could run is now refused instead of answered
  with a success. A misspelled action such as ``replicat:host``, an unreadable
  retention pattern, an invalid volume name or a timer that is not a number of
  minutes used to be accepted, and the command reported nothing while either
  writing a line the scheduler would silently ignore, or writing nothing at
  all. Unscheduling, pausing or resuming a job that is not in the schedule is
  refused for the same reason. A line already written stays possible to pause
  and to delete, whatever it says.

- Every endpoint now goes through a single decorator that decodes the request,
  logs it and turns any failure into the ``Err`` field of a 200 answer. Six
  routes, among them the scheduling ones and the snapshot send, used to answer
  a bare HTTP 500 on an unexpected error, which no client of this API knows how
  to read.

- A purge pattern that cannot be applied now says why. ``5x`` is answered
  ``unknown unit 'x'`` rather than a bare ``'x'``, and a component such as
  ``²h`` is refused as not numeric rather than reported as a failed conversion.

- The chattr call enabling compression no longer goes through a shell with the
  volume path interpolated in the command line.
- Snapshot names received through the API are now validated like volume names:
  a name containing a path traversal or shell characters is rejected instead
  of reaching the filesystem and the btrfs command. A ``DTFORMAT`` producing a
  name that this validation would reject is refused at snapshot time, instead
  of creating a snapshot no endpoint could name again.
- Fixed the cleanup of the snapshot created for a failed scheduled replication:
  it crashed instead of deleting the snapshot, leaving it behind.
- A snapshot send to another node is now killed after a configurable timeout
  (``SEND_TIMEOUT``, 10 minutes by default) instead of hanging forever, and a
  verbose failure of the send side can no longer deadlock the transfer. A
  transfer killed this way is reported as such and not sent again in full over
  the same link.
- Fixed the purge tests, which passed or failed depending on how long they took
  to run.
- Fixed the tests: create a BTRFS filesystems in a loop device if there is no BTRFS during tests.
- Fixed the show command
- Updated dependencies
- Fixed a freeze in front mode (#47)
- Fixed critical #51 `schedule not working` 
- Allow using volumes created with legacy plugin anybox/buttervolume (fix #52)
- Fixed deletion of old sent snapshots
- Added support for compression (fix #36)
- A failing BTRFS command is now always reported the same way, naming the command
  and keeping the original error. Deleting a subvolume no longer has a silent
  failure mode.

3.12 (2024-11-05)
*****************

- Updated the Docker image to Debian 12
- changed requests-unixsocket to requests-unixsocket2

3.11 (2024-10-12)
*****************

- updated the doc to link to the new name
- Updated the Docker image

3.10 (2023-04-09)
*****************

- updated dependencies
- fixed bug #45

3.9 (2022-10-11)
****************

- Fixed a crash when option_copyonwrite is not set
- Restored the test suite
- Improved and simplified the build script and test script

3.8 (2022-10-07)
****************

- Switched to copy-on-write by default
- Allow to choose to enable/disable copy-on-write for each volume
- Allow to change the default SSH_PORT in the plugin config
- Updated the base docker image and dependencies
- Added an option to show the version number
- Improved documentation

3.7 (2018-12-13)
****************

- Unpinned urllib3

3.6 (2018-12-11)
****************

- Fixed zombie sshd processes inside the plugin
- Minor documentation change

3.5 (2018-06-07)
****************

- Improved documentation

3.4 (2018-04-27)
****************

- Fix rights at startup so that ssh works

3.3 (2018-04-27)
****************

- Fixed a bug preventing a start in certain conditions

3.2 (2018-04-27)
****************

- Fixed the socket path for startup

3.1 (2018-04-27)
****************

- Fixed a declaration in Python 3.6
- Automatically detects the btrfs.sock path
- Made the runpath and drivername configurable

3.0 (2018-04-24)
****************

- Now use the docker *managed plugin* system
- Stop the scheduler before shutdown to avoid a 5s timeout
- Improved logging
- Improved the migration doc from version 1 or 2

2.0 (2018-03-24)
****************

- BREAKING CHANGE: Please read the migration path from version 1 to version 2:
    BTRFS volumes and snapshots are now stored by default in different directories under ``/var/lib/buttervolume``
- Configuration possible through environment variables or a ``config.ini`` file
- implemented ``VolumeDriver.Capabilities`` and just return ``'local'``
- other minor fixes and improvements

1.4 (2018-02-01)
****************

- Add clone command
- replace sync by `btrfs filesystem sync`

1.3.1 (2017-10-22)
******************

- fixed packaging (missing README)

1.3 (2017-07-30)
****************

- fixed the cli for the restore command

1.2 (2017-07-16)
****************

- fixed the purge algorithm

1.1 (2017-07-13)
****************

- allow to restore a snapshot to a different volume name

1.0 (2017-05-24)
****************

- initial release, used in production

