#!/bin/bash

set -e

# version found in VERSION file
VERSION=$(python -c 'print(open("buttervolume/VERSION").read().strip())')

# last version found in the changelog
CHANGES_VERSION=$(grep '^[0-9].*(.*)' CHANGES.rst | head -1 | cut -d' ' -f1)

# last date found in the changelog
LASTDATE=$(grep '^[0-9].*(.*)' CHANGES.rst | head -1 | cut -d' ' -f2 | tr -d '(' | tr -d ')')


if [ "$VERSION" == "" ]; then echo "Check version number"; exit 1; fi
if [ "$VERSION" != "$CHANGES_VERSION" ]; then echo "Check version in VERSION (=$VERSION) and CHANGES.rst (=$CHANGES_VERSION)"; exit 1; fi
if ! date --date=$LASTDATE "+%d-%B-%Y" > /dev/null; then echo "Check the last date in the CHANGES.rst"; exit 1; fi
if ! cat README.rst CHANGES.rst | rst2html > /dev/null; then echo "Check the rst syntax"; exit 1; fi
echo "OK"
echo "##################"
echo "Release Check List"
echo "##################"
echo "- check the changelog"
echo "- git tag <tag>"
echo "- build.sh <tag>"
echo "- build.sh"
echo "- docker plugin push ccomb/buttervolume:<tag>"
echo "- docker plugin push ccomb/buttervolume"
echo "- publish to PyPI : pip install build twine && python3 -m build && python3 -m twine upload --repository pypi dist/*"
echo "- publish the Docker Hub page : python3 publish_dockerhub_description.py"
