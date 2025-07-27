import os
from subprocess import PIPE, CalledProcessError, TimeoutExpired
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


def btrfs_operation(error_type, error_msg, timeout=60):
    """Decorator that runs BTRFS commands with timeout and converts exceptions to specific types."""
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            # Call the function to get the command
            cmd_list = func(self, *args, **kwargs)
            
            try:
                return _run(
                    cmd_list, shell=False, check=True, capture_output=True, timeout=timeout
                ).stdout.decode()
            except CalledProcessError as e:
                cmd_str = " ".join(cmd_list)
                stderr_output = e.stderr.decode() if e.stderr else 'No error output'
                raise error_type(
                    f"{error_msg}: BTRFS command failed: {cmd_str}\nStderr: {stderr_output}"
                )
            except TimeoutExpired:
                cmd_str = " ".join(cmd_list)
                raise error_type(
                    f"{error_msg}: BTRFS command timed out after {timeout}s: {cmd_str}"
                )
            except Exception as e:
                raise error_type(f"{error_msg} - unexpected error: {str(e)}")
        return wrapper
    return decorator

def run_safe(cmd_list, check=True, stdout=PIPE, stderr=PIPE, timeout=60):
    """Simple run_safe for basic operations without error type conversion"""
    try:
        return _run(
            cmd_list, shell=False, check=check, stdout=stdout, stderr=stderr, timeout=timeout
        ).stdout.decode()
    except CalledProcessError as e:
        cmd_str = " ".join(cmd_list)
        stderr_output = e.stderr.decode() if e.stderr else 'No error output'
        raise BtrfsError(
            f"BTRFS command failed: {cmd_str}\nStderr: {stderr_output}"
        )
    except TimeoutExpired:
        cmd_str = " ".join(cmd_list)
        raise BtrfsError(f"BTRFS command timed out after {timeout}s: {cmd_str}")


def run(cmd, shell=True, check=True, stdout=PIPE, stderr=PIPE):
    try:
        return _run(cmd, shell=shell, check=check, stdout=stdout, stderr=stderr).stdout.decode()
    except CalledProcessError as e:
        stderr_output = e.stderr.decode() if e.stderr else 'No error output'
        raise BtrfsError(
            f"BTRFS command failed: {cmd}\nStderr: {stderr_output}"
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


class Subvolume:
    """basic wrapper around the CLI"""

    def __init__(self, path):
        # Store absolute path - validation happens at the plugin layer
        self.path = os.path.abspath(path)

    def show(self):
        """Parse btrfs subvolume show output"""
        raw = run_safe(["btrfs", "subvolume", "show", self.path], timeout=15)
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

    @btrfs_operation(BtrfsSubvolumeError, "Failed to create snapshot", timeout=120)
    def snapshot(self, target, readonly=False):
        """Create a snapshot of this subvolume"""
        cmd = ["btrfs", "subvolume", "snapshot"]
        if readonly:
            cmd.append("-r")
        cmd.extend([self.path, target])
        return cmd

    @btrfs_operation(BtrfsSubvolumeError, "Failed to create subvolume", timeout=120)
    def _create_subvolume(self):
        """Create the BTRFS subvolume"""
        return ["btrfs", "subvolume", "create", self.path]
    
    def create(self, cow=False):
        """Create a new BTRFS subvolume"""
        out = self._create_subvolume()
        if not cow:
            try:
                run_safe(["chattr", "+C", self.path], timeout=10)
            except BtrfsError:
                # chattr failure is not critical, subvolume was created successfully
                pass
        return out

    @btrfs_operation(BtrfsSubvolumeError, "Failed to delete subvolume", timeout=300)
    def _delete_subvolume(self):
        """Delete the BTRFS subvolume"""
        return ["btrfs", "subvolume", "delete", self.path]
    
    def delete(self, check=True):
        """Delete this BTRFS subvolume

        :param check: if True, in case btrfs subvolume fails (exit code != 0)
                      an exception will be raised
        :return: btrfs output string
        """
        if check:
            return self._delete_subvolume()
        else:
            # Silent failure mode
            try:
                return run_safe(
                    ["btrfs", "subvolume", "delete", self.path], check=False, timeout=300
                )
            except Exception:
                return ""


class Filesystem:
    def __init__(self, path):
        self.path = os.path.abspath(path)

    @btrfs_operation(BtrfsFilesystemError, "Failed to manage filesystem label", timeout=10)
    def label(self, label=None):
        """Get or set filesystem label"""
        cmd = ["btrfs", "filesystem", "label", self.path]
        if label is not None:
            cmd.append(label)
        return cmd
