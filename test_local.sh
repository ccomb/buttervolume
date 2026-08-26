#!/bin/bash
# Local test runner for BTRFS systems
# Run buttervolume tests directly on a local BTRFS filesystem

set -e

# Create local test directories (adjust path as needed)
LOCAL_TEST_DIR="${BUTTERVOLUME_TEST_DIR:-/tmp/buttervolume_test}"

# The tests leave BTRFS subvolumes behind, and rm cannot delete those: the
# snapshots are read-only, and everything the tests made belongs to root.
# Each one has to go through btrfs subvolume delete first.
cleanup_test_dir() {
    [ -d "$LOCAL_TEST_DIR" ] || return 0
    echo "Cleaning up test directory: $LOCAL_TEST_DIR"
    # -depth walks children before parents, which is the order nested
    # subvolumes have to be deleted in. Directories that are not subvolumes
    # simply refuse, and rm takes care of them below.
    sudo find "$LOCAL_TEST_DIR" -mindepth 1 -depth -type d \
        -exec btrfs subvolume delete {} \; > /dev/null 2>&1 || true
    sudo rm -rf "$LOCAL_TEST_DIR"/volumes "$LOCAL_TEST_DIR"/snapshots \
        "$LOCAL_TEST_DIR"/received "$LOCAL_TEST_DIR"/lastruns.csv
    # Left alone when it is a mount point, which is what the help text above
    # tells people to set up.
    rmdir "$LOCAL_TEST_DIR" 2> /dev/null || true
}

cleanup_test_dir

mkdir -p "$LOCAL_TEST_DIR"/{volumes,snapshots,received}

echo "Using test directory: $LOCAL_TEST_DIR"

# Check if the directory is actually on a BTRFS filesystem
if ! stat -f -c %T "$LOCAL_TEST_DIR" | grep -q btrfs; then
    echo "ERROR: $LOCAL_TEST_DIR is not on a BTRFS filesystem!"
    echo "Current filesystem: $(stat -f -c %T "$LOCAL_TEST_DIR")"
    echo ""
    echo "Please set BUTTERVOLUME_TEST_DIR to a path on a BTRFS filesystem:"
    echo "  BUTTERVOLUME_TEST_DIR=/path/to/btrfs/dir ./test_local.sh"
    echo ""
    echo "Or create a BTRFS filesystem in a file:"
    echo "  sudo truncate -s 1G /tmp/btrfs.img"
    echo "  sudo mkfs.btrfs /tmp/btrfs.img"
    echo "  sudo mkdir -p /mnt/btrfs_test"
    echo "  sudo mount -o loop /tmp/btrfs.img /mnt/btrfs_test"
    echo "  BUTTERVOLUME_TEST_DIR=/mnt/btrfs_test ./test_local.sh"
    exit 1
fi

echo "✓ Directory is on BTRFS filesystem"

# Export environment variables for the test
export BUTTERVOLUME_SKIP_BTRFS_CHECK=1
export BUTTERVOLUME_LOCAL_TEST=1
export BUTTERVOLUME_VOLUMES_PATH="$LOCAL_TEST_DIR/volumes/"
export BUTTERVOLUME_SNAPSHOTS_PATH="$LOCAL_TEST_DIR/snapshots/"
export BUTTERVOLUME_TEST_REMOTE_PATH="$LOCAL_TEST_DIR/received/"
export BUTTERVOLUME_LAST_RUNS="$LOCAL_TEST_DIR/lastruns.csv"

# Setup virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    uv venv
    uv sync --extra test
fi

# Run specific test if provided, otherwise run all tests
if [ "$1" != "" ]; then
    echo "Running specific test: $1"
    sudo -E .venv/bin/python -m pytest test.py::TestCase::$1 -v
else
    echo "Running all tests..."
    sudo -E .venv/bin/python -m pytest test.py -v
fi

cleanup_test_dir