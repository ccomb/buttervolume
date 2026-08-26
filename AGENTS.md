# AGENTS.md

Buttervolume is a Docker Volume Plugin that manages Docker volumes as BTRFS
subvolumes: snapshot, restore, clone, replicate. Python, Bottle, argparse.

## Finding your way around

Every module opens with a docstring saying what it is for and what belongs in
it. Read that one before adding to the module, and correct it there rather than
describing the module here. This file holds the practices; a map of the code
here would go stale the first time someone forgets to update it.

- `README.rst` is the user manual: install, CLI usage, configuration, volume
  migration. Never duplicate it here; fix it there when it is wrong.
- `CHANGES.rst` is the changelog, one entry per user-visible change.

## Commands

```bash
uv venv && uv sync --extra dev
./test_local.sh [test_name]   # tests against a local BTRFS dir, no Docker
./test.sh [VERSION]           # tests the built plugin in Docker
./build.sh [VERSION]          # build the Docker plugin
sudo .venv/bin/buttervolume run
uv run ruff check . && uv run ruff format .
```

## Engineering rules

- **No silent success, no silent failure.** Never a fallback value, an empty
  list or an optimistic log when a step failed. Raise a `ButtervolumeError`
  subclass (or `BtrfsError` in `btrfs.py`) and let it reach the caller. A wrong
  answer is worse than a clear error, because the caller cannot tell.
- **A snapshot only exists the day it was restored.** Any change to the
  snapshot, send or restore paths must be proven by a test that restores.
- **Destruction stays deliberate.** Nothing deletes a volume or a snapshot on
  its own initiative; only an explicit command or the purge pattern the user
  asked for.
- **Fix the root cause, at the shared function.** Before editing a handler,
  check its siblings: one guard in a helper beats a guard in every caller.
- **Pure inside, effects at the edges.** Pattern parsing, name validation and
  state transitions are pure functions, testable without a filesystem. Shelling
  out and writing files happen at the boundary.
- **Validate at the trust boundary.** Volume and snapshot names come from
  Docker or from a remote host, and they end up in a path and in a shell
  command. `validate_volume_name` is where that is decided, not the caller.
- **The right level of tooling.** A volume plugin is managed with the standard
  library, Bottle and BTRFS. Every added dependency is one more thing that can
  lie; check the standard library first.
- **Simplicity: perfection is when nothing is left to remove.** Most complexity
  is accidental. Minimize mutable state, separate state from computation.
- Nothing is committed that does not compile and pass `test_local.sh`.

## Commits and pull requests

- Every change goes through a pull request, on a branch starting from `master`.
  Never commit to `master` directly, and never open a pull request from a
  long-lived work branch that carries unrelated commits.
- One pull request, one subject. If the description needs the word "and", it is
  two pull requests.
- Atomic commits: one subject each. Writing "and also" in a message means the
  commit must be split.
- The message explains why, in plain sentences, not what the diff already
  shows. No em dashes.
- `git add` names its files; never `git add -A`.
- Re-read this file and `README.rst` before an important commit, and correct
  them as soon as a sentence contradicts the code. Adding a module, an endpoint
  or a command is not a reason to grow this file: say it in the module's
  docstring, and here only when it changes a practice.
