#!/bin/bash

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "❌ Aborting: you have uncommitted changes (staged or unstaged). Please git stash your changes first."
  git status
  exit 1
fi

set -e
VERSION=$1
rm -f buttervolume.zip
pushd $( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd ) > /dev/null
if [ "$VERSION" == "" ]; then
    VERSION="HEAD"
    echo "#####################"
    echo "Testing version $VERSION"
    echo "You can test another version with: ./test.sh <VERSION>"
    echo "#####################"
fi
git archive -o buttervolume.zip $VERSION

# Use cache for development (HEAD), clean build for specific versions
if [ "$1" == "" ]; then
    echo "Using Docker cache for faster development builds"
    docker build --build-arg VERSION=$VERSION -t ccomb/buttervolume_test:$VERSION .
else
    echo "Clean build for version $VERSION"
    docker build --build-arg VERSION=$VERSION -t ccomb/buttervolume_test:$VERSION . --no-cache
fi
# The tests need a BTRFS filesystem, and the container makes one on a loop
# device when it does not find one. A kernel that hands out no loop device
# leaves them with nothing, so BUTTERVOLUME_TEST_DIR names a BTRFS directory
# to work in instead, as it does for ./test_local.sh.
testdir=""
if [ -n "$BUTTERVOLUME_TEST_DIR" ]; then
    # It has to be where the filesystem is mounted, not a directory inside it.
    # Giving a subdirectory hides the rest of the tree from the container, and
    # "btrfs receive" then cannot find the parent it was given, so the two
    # tests of an incremental transfer fail without saying why.
    if ! mountpoint -q "$BUTTERVOLUME_TEST_DIR"; then
        echo "❌ BUTTERVOLUME_TEST_DIR must be where a BTRFS filesystem is mounted"
        exit 1
    fi
    mkdir -p "$BUTTERVOLUME_TEST_DIR"/{volumes,snapshots,received}
    testdir="-v $BUTTERVOLUME_TEST_DIR:/var/lib/buttervolume"
fi
test="sudo docker run --rm --privileged $testdir -v /var/lib/docker:/var/lib/docker -v $PWD:/usr/src/buttervolume -w /usr/src/buttervolume ccomb/buttervolume_test:$VERSION test"
$test
echo "#############################"
echo "You can run tests again with:"
echo "$test"
echo "#############################"
popd
