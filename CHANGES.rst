CHANGELOG
=========

3.13 (2025-08-03)
*****************

- Fixed the tests: create a BTRFS filesystems in a loop device if there is no BTRFS during tests.
- Fixed the show command
- Updated dependencies
- Fixed a freeze in front mode (#47)
- Fixed critical #51 `schedule not working` 
- Allow using volumes created with legacy plugin anybox/buttervolume (fix #52)
- Fixed deletion of old sent snapshots
- Added support for compression (fix #36)

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

