import os
from subprocess import PIPE
from subprocess import run as _run


def run(cmd, shell=True, check=True, stdout=PIPE, stderr=PIPE):
    return _run(
        cmd, shell=shell, check=check, stdout=stdout, stderr=stderr
    ).stdout.decode()


class Subvolume(object):
    """basic wrapper around the CLI"""

    def __init__(self, path):
        self.path = path

    def show(self):
        """Parse btrfs subvolume show output with flexible format handling"""
        raw = run('btrfs subvolume show "{}"'.format(self.path))
        lines = raw.split("\n")
        output = {}
        
        # Parse key-value pairs until we find the Snapshot(s) section or end
        line_idx = 1
        while line_idx < len(lines):
            line = lines[line_idx].strip()
            if not line:
                line_idx += 1
                continue
            if line == "Snapshot(s):":
                break
            if ":" in line:
                k, v = line.split(":", 1)
                output[k.strip()] = v.strip()
            line_idx += 1
        
        # Find and parse snapshots section
        snapshots = []
        for i in range(line_idx + 1, len(lines)):
            snapshot = lines[i].strip()
            if snapshot:
                snapshots.append(snapshot)
        
        output["Snapshot(s)"] = snapshots
        return output

    def exists(self):
        if not os.path.exists(self.path):
            return False
        try:
            self.show()
        except Exception:
            return False
        return True

    def snapshot(self, target, readonly=False):
        r = "-r" if readonly else ""
        return run('btrfs subvolume snapshot {} "{}" "{}"'.format(r, self.path, target))

    def create(self, cow=False):
        out = run('btrfs subvolume create "{}"'.format(self.path))
        if not cow:
            run('chattr +C "{}"'.format(self.path))
        return out

    def delete(self, check=True):
        """

        :param check: if True, in case btrfs subvolume fails (exit code != 0)
                      an exception will raised
        :return: btrfs output string
        """
        return run("btrfs subvolume delete {}".format(self.path), check=check)


class Filesystem(object):
    def __init__(self, path):
        self.path = path

    def label(self, label=None):
        if label is None:
            return run('btrfs filesystem label "{}"'.format(self.path))
        else:
            return run('btrfs filesystem label "{}" "{}"'.format(self.path, label))
