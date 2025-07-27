import os
import shlex
from subprocess import PIPE, CalledProcessError
from subprocess import run as _run


# Custom exceptions for BTRFS operations
class BtrfsError(Exception):
    """Base exception for BTRFS operations"""

    pass


class BtrfsSubvolumeError(BtrfsError):
    """Raised when BTRFS subvolume operations fail"""

    pass


class BtrfsFilesystemError(BtrfsError):
    """Raised when BTRFS filesystem operations fail"""

    pass


class InvalidPathError(BtrfsError):
    """Raised when path validation fails"""

    pass


def run(cmd, shell=True, check=True, stdout=PIPE, stderr=PIPE):
    try:
        return _run(cmd, shell=shell, check=check, stdout=stdout, stderr=stderr).stdout.decode()
    except CalledProcessError as e:
        raise BtrfsError(
            f"BTRFS command failed: {cmd}\nStderr: {e.stderr.decode() if e.stderr else 'No error output'}"
        )


def run_safe(cmd_list, check=True, stdout=PIPE, stderr=PIPE):
    """Run command safely with argument list instead of shell=True"""
    try:
        return _run(
            cmd_list, shell=False, check=check, stdout=stdout, stderr=stderr
        ).stdout.decode()
    except CalledProcessError as e:
        cmd_str = " ".join(cmd_list)
        raise BtrfsError(
            f"BTRFS command failed: {cmd_str}\nStderr: {e.stderr.decode() if e.stderr else 'No error output'}"
        )


def validate_path(path):
    """Validate that path doesn't contain dangerous characters"""
    if not path:
        raise InvalidPathError("Path cannot be empty")
    if ".." in path:
        raise InvalidPathError(f"Path traversal not allowed: {path}")
    if path.startswith("/") and not path.startswith("/var/lib/buttervolume"):
        raise InvalidPathError(f"Absolute paths outside buttervolume directory not allowed: {path}")
    # Additional validation for shell metacharacters
    dangerous_chars = ["`", "$", "|", "&", ";", ">", "<", "*", "?", "[", "]", "(", ")", "{", "}"]
    if any(char in path for char in dangerous_chars):
        raise InvalidPathError(f"Path contains dangerous characters: {path}")
    return path


class Subvolume(object):
    """basic wrapper around the CLI"""

    def __init__(self, path):
        # Store absolute path - validation happens at the plugin layer
        self.path = os.path.abspath(path)

    def show(self):
        """Parse btrfs subvolume show output"""
        try:
            raw = run_safe(["btrfs", "subvolume", "show", self.path])
            lines = raw.split("\n")

            if len(lines) < 13:
                raise BtrfsSubvolumeError(
                    f"Unexpected output format from 'btrfs subvolume show {self.path}'"
                )

            # Parse key-value pairs from lines 1-12
            output = {}
            for line in lines[1:12]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    output[k.strip()] = v.strip()

            # Check for snapshots section
            if len(lines) > 12 and "Snapshot(s):" in lines[12]:
                output["Snapshot(s)"] = [s.strip() for s in lines[13:] if s.strip()]
            else:
                output["Snapshot(s)"] = []

            return output
        except BtrfsError:
            raise  # Re-raise BTRFS errors
        except Exception as e:
            raise BtrfsSubvolumeError(f"Failed to parse subvolume info for {self.path}: {str(e)}")

    def exists(self):
        """Check if this path is a valid BTRFS subvolume"""
        if not os.path.exists(self.path):
            return False
        if not os.path.isdir(self.path):
            return False
        try:
            self.show()
            return True
        except BtrfsError:
            return False
        except Exception:
            # Unexpected error - could indicate system issues
            return False

    def snapshot(self, target, readonly=False):
        """Create a snapshot of this subvolume"""
        try:
            cmd = ["btrfs", "subvolume", "snapshot"]
            if readonly:
                cmd.append("-r")
            cmd.extend([self.path, target])
            return run_safe(cmd)
        except BtrfsError as e:
            raise BtrfsSubvolumeError(
                f"Failed to create snapshot from {self.path} to {target}: {str(e)}"
            )
        except Exception as e:
            raise BtrfsSubvolumeError(f"Unexpected error creating snapshot: {str(e)}")

    def create(self, cow=False):
        """Create a new BTRFS subvolume"""
        try:
            out = run_safe(["btrfs", "subvolume", "create", self.path])
            if not cow:
                try:
                    run_safe(["chattr", "+C", self.path])
                except BtrfsError as e:
                    # chattr failure is not critical, subvolume was created successfully
                    # The plugin layer can decide whether to log this or not
                    pass
            return out
        except BtrfsError as e:
            raise BtrfsSubvolumeError(f"Failed to create subvolume {self.path}: {str(e)}")
        except Exception as e:
            raise BtrfsSubvolumeError(f"Unexpected error creating subvolume: {str(e)}")

    def delete(self, check=True):
        """Delete this BTRFS subvolume

        :param check: if True, in case btrfs subvolume fails (exit code != 0)
                      an exception will be raised
        :return: btrfs output string
        """
        try:
            return run_safe(["btrfs", "subvolume", "delete", self.path], check=check)
        except BtrfsError as e:
            if check:
                raise BtrfsSubvolumeError(f"Failed to delete subvolume {self.path}: {str(e)}")
            return ""  # Silent failure when check=False
        except Exception as e:
            if check:
                raise BtrfsSubvolumeError(f"Unexpected error deleting subvolume: {str(e)}")
            return ""


class Filesystem(object):
    def __init__(self, path):
        self.path = os.path.abspath(path)

    def label(self, label=None):
        """Get or set filesystem label"""
        try:
            if label is None:
                return run_safe(["btrfs", "filesystem", "label", self.path])
            else:
                return run_safe(["btrfs", "filesystem", "label", self.path, label])
        except BtrfsError as e:
            raise BtrfsFilesystemError(
                f"Failed to {'get' if label is None else 'set'} filesystem label for {self.path}: {str(e)}"
            )
        except Exception as e:
            raise BtrfsFilesystemError(f"Unexpected error with filesystem label: {str(e)}")
