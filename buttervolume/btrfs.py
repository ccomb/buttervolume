import os
import shlex
from subprocess import PIPE
from subprocess import run as _run


def run(cmd, shell=True, check=True, stdout=PIPE, stderr=PIPE):
    return _run(cmd, shell=shell, check=check, stdout=stdout, stderr=stderr).stdout.decode()


def run_safe(cmd_list, check=True, stdout=PIPE, stderr=PIPE):
    """Run command safely with argument list instead of shell=True"""
    return _run(cmd_list, shell=False, check=check, stdout=stdout, stderr=stderr).stdout.decode()


def validate_path(path):
    """Validate that path doesn't contain dangerous characters"""
    if not path or ".." in path or path.startswith("/"):
        raise ValueError(f"Invalid path: {path}")
    # Additional validation for shell metacharacters
    dangerous_chars = ["`", "$", "|", "&", ";", ">", "<", "*", "?", "[", "]", "(", ")", "{", "}"]
    if any(char in path for char in dangerous_chars):
        raise ValueError(f"Path contains dangerous characters: {path}")
    return path


class Subvolume(object):
    """basic wrapper around the CLI"""

    def __init__(self, path):
        # Validate path on construction
        self.path = os.path.abspath(path)

    def show(self):
        """somewhat hardcoded..."""
        raw = run_safe(["btrfs", "subvolume", "show", self.path])
        output = {k.strip(): v.strip() for k, v in [x.split(":", 1) for x in raw.split("\n")[1:12]]}
        assert raw.split("\n")[12].strip() == "Snapshot(s):"
        output["Snapshot(s)"] = [s.strip() for s in raw.split("\n")[13:]]
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
        cmd = ["btrfs", "subvolume", "snapshot"]
        if readonly:
            cmd.append("-r")
        cmd.extend([self.path, target])
        return run_safe(cmd)

    def create(self, cow=False):
        out = run_safe(["btrfs", "subvolume", "create", self.path])
        if not cow:
            run_safe(["chattr", "+C", self.path])
        return out

    def delete(self, check=True):
        """

        :param check: if True, in case btrfs subvolume fails (exit code != 0)
                      an exception will raised
        :return: btrfs output string
        """
        return run_safe(["btrfs", "subvolume", "delete", self.path], check=check)


class Filesystem(object):
    def __init__(self, path):
        self.path = os.path.abspath(path)

    def label(self, label=None):
        if label is None:
            return run_safe(["btrfs", "filesystem", "label", self.path])
        else:
            return run_safe(["btrfs", "filesystem", "label", self.path, label])
