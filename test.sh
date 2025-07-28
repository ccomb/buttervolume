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
    git archive -o buttervolume.zip $VERSION
fi

# Use cache for development (HEAD), clean build for specific versions
if [ "$1" == "" ]; then
    echo "Using Docker cache for faster development builds"
    docker build --build-arg VERSION=$VERSION -t ccomb/buttervolume_test:$VERSION .
else
    echo "Clean build for version $VERSION"
    docker build --build-arg VERSION=$VERSION -t ccomb/buttervolume_test:$VERSION . --no-cache
fi
test="sudo docker run -it --rm --privileged -v /var/lib/docker:/var/lib/docker -v $PWD:/usr/src/buttervolume -w /usr/src/buttervolume ccomb/buttervolume_test:HEAD test"
$test
echo "#############################"
echo "You can run tests again with:"
echo "$test"
echo "#############################"
popd
