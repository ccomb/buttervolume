CHANGELOG
=========

3.13 (unreleased)
*****************

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

