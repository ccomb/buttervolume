"""Preparing the place the volumes will live, before any daemon exists.

``buttervolume init`` is run once, by hand, on a host that has nothing yet. It
either checks that a directory already sits on a BTRFS filesystem and creates
the four directories the plugin expects there, or it creates an image file
formatted as BTRFS for the administrator to mount. It never mounts anything
itself and it never writes into a filesystem it has not recognized as BTRFS.

It is alone in shelling out to ``truncate``, ``mkfs.btrfs`` and ``stat``:
``btrfs.py`` speaks to a filesystem that is already there, this speaks to the
one that is not. Being the command run before the plugin works, it reports by
printing and by returning ``False`` rather than by raising, so the terminal
gets the reason and the exit code, and the two ways out of every check say
what to do next: point at a BTRFS partition, or ask for an image file.
"""

import os
import subprocess

DEFAULT_PATH = "/var/lib/buttervolume"
REQUIRED_DIRS = ("volumes", "snapshots", "config", "ssh")
ADVICE = (
    "Either:\n"
    "  - Point to a BTRFS partition/mount using --path\n"
    "  - Create a BTRFS image file using --file"
)


def needs_root(path):
    """Whether writing there is the system's business rather than the user's"""
    return path.startswith(("/var/", "/etc/", "/usr/"))


def is_btrfs(path):
    """Whether that path sits on a BTRFS filesystem, saying why when it does not"""
    try:
        fstype = subprocess.run(
            ["stat", "-f", "-c", "%T", path], capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError:
        print(f"ERROR: Cannot determine filesystem type for {path}")
        return False
    if "btrfs" not in fstype.lower():
        print(f"ERROR: {path} is not on a BTRFS filesystem")
        print(ADVICE)
        return False
    return True


def create_image(image_path, size):
    """Create a sparse file formatted as BTRFS, for the caller to mount"""
    print(f"Creating BTRFS image file: {image_path} (size: {size})")

    parent_dir = os.path.dirname(image_path)
    if not os.access(parent_dir, os.W_OK):
        print(f"ERROR: No write permission to directory: {parent_dir}")
        if needs_root(parent_dir):
            print("Try running as root or choose a path in your home directory")
        return False
    try:
        os.makedirs(parent_dir, exist_ok=True)
    except PermissionError:
        print(f"ERROR: Permission denied creating directory: {parent_dir}")
        print("Try running as root or choose a path in your home directory")
        return False

    try:
        subprocess.run(["truncate", "-s", size, image_path], check=True)
        subprocess.run(["/usr/sbin/mkfs.btrfs", "-f", image_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to create BTRFS image: {e}")
        return False

    print(f"Successfully created BTRFS image: {image_path}")
    print(f"To use it, mount it to {DEFAULT_PATH}:")
    print(f"  sudo mount -o loop {image_path} {DEFAULT_PATH}")
    return True


def prepare_path(target_path):
    """Create the directories the plugin expects on an existing BTRFS filesystem"""
    if needs_root(target_path) and os.geteuid() != 0:
        print(f"ERROR: Root privileges required for {target_path}")
        print("Try running with sudo, or use --file with a user-owned path")
        return False
    if not os.path.exists(target_path):
        print(f"ERROR: Path does not exist: {target_path}")
        print(ADVICE)
        return False
    if not is_btrfs(target_path):
        return False

    print(f"Creating required directories in {target_path}...")
    for name in REQUIRED_DIRS:
        dir_path = os.path.join(target_path, name)
        os.makedirs(dir_path, exist_ok=True)
        print(f"  Created: {dir_path}")

    print(f"Successfully initialized buttervolume at {target_path}")
    print("You can now start the plugin with: buttervolume run")
    return True


def init_btrfs(args):
    """The ``init`` command: an image file to mount, or a path to prepare"""
    if args.file:
        return create_image(args.file, args.size)
    return prepare_path(args.path or DEFAULT_PATH)
