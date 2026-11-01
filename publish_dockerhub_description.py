"""Publish the Docker Hub page of ccomb/buttervolume from README.rst.

Docker Hub refuses a description over 25000 characters and the manual is
longer, so the page carries the README up to its Usage section, then a link
to the full manual on GitHub. Needs pandoc and a prior `docker login`.
"""

import base64
import json
import os
import subprocess
import urllib.request

REPOSITORY = "https://hub.docker.com/v2/repositories/ccomb/buttervolume/"
SUMMARY = "BTRFS volume plugin for Docker: snapshot, restore, clone and replicate volumes"
FULL_MANUAL = """
Full manual
***********

Usage, snapshots, replication, synchronization, scheduling and configuration
are described in the `full manual on GitHub
<https://github.com/ccomb/buttervolume#usage>`_.
"""
# Directives that mean nothing outside the full manual.
DROPPED = (".. contents::", ".. _the buttervolume function:")


def page(readme):
    """The README up to its Usage section, in Markdown."""
    head = readme.split("\nUsage\n*****\n")[0]
    kept = [line for line in head.splitlines() if not line.startswith(DROPPED)]
    rst = "\n".join(kept) + "\n" + FULL_MANUAL
    return subprocess.run(
        ["pandoc", "-f", "rst", "-t", "gfm"],
        input=rst,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def credentials():
    with open(os.path.expanduser("~/.docker/config.json")) as f:
        auths = json.load(f).get("auths", {})
    auth = auths.get("https://index.docker.io/v1/", {}).get("auth")
    if not auth:
        raise SystemExit("No Docker Hub credentials in ~/.docker/config.json: run docker login")
    return base64.b64decode(auth).decode().split(":", 1)


def call(method, url, body, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, json.dumps(body).encode(), headers, method=method)
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def main():
    with open("README.rst") as f:
        description = page(f.read())
    if len(description) > 25000:
        raise SystemExit(f"The Docker Hub page is {len(description)} characters, over 25000")
    user, password = credentials()
    login = "https://hub.docker.com/v2/users/login"
    token = call("POST", login, {"username": user, "password": password})["token"]
    body = {"description": SUMMARY, "full_description": description}
    call("PATCH", REPOSITORY, body, token)
    print(f"Docker Hub page published, {len(description)} characters")


if __name__ == "__main__":
    main()
