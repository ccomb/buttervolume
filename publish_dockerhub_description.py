"""Publish the Docker Hub page of ccomb/buttervolume from README.rst.

Whoever reads the Docker Hub page has already chosen the plugin and is setting
it up, so the page carries the README sections that serve that: what the plugin
does, then installing, creating volumes and configuring it, and a link to the
full manual for the rest. Taking them from the README, by title, keeps one
manual to maintain. Needs pandoc and a prior `docker login`.
"""

import base64
import json
import os
import subprocess
import urllib.request

REPOSITORY = "https://hub.docker.com/v2/repositories/ccomb/buttervolume/"
SUMMARY = "BTRFS volume plugin for Docker: snapshot, restore, clone and replicate volumes"
LIMIT = 25000  # characters Docker Hub accepts in a full description
TITLE = "BTRFS Volume plugin for Docker"
BLOCKS = ("What can Buttervolume do?", "How does it work?")
SECTIONS = (
    "Prerequisites",
    "Install and run as a user",
    "Upgrade",
    "Running the plugin",
    "Creating and deleting volumes",
    "Configure",
)
FULL_MANUAL = """\
Full manual
***********

Snapshots, replication, synchronization and scheduling are described in the
`full manual on GitHub <https://github.com/ccomb/buttervolume#usage>`_.
"""
UNDERLINES = "=*-~^"


def underline(lines, i):
    """The character underlining line i when it is a title, else None."""
    if i + 1 >= len(lines) or not lines[i].strip():
        return None
    below = lines[i + 1]
    char = below[:1]
    if char in UNDERLINES and below == char * len(below) and len(below) >= len(lines[i]):
        return char
    return None


def section(lines, title):
    """The lines of the section with this title, its title underlined as a top section."""
    for i in range(len(lines)):
        char = underline(lines, i)
        if lines[i] == title and char:
            end = next(
                (
                    j
                    for j in range(i + 2, len(lines))
                    if underline(lines, j)
                    and UNDERLINES.index(underline(lines, j)) <= UNDERLINES.index(char)
                ),
                len(lines),
            )
            return [title, "*" * len(title)] + lines[i + 2 : end]
    raise ValueError(f"README.rst has no section titled {title!r}")


def block(lines, bold):
    """The lines of the paragraph introduced by **bold**, up to the next one."""
    start = lines.index(f"**{bold}**")  # raises ValueError when the README lost it
    end = next(
        (j for j in range(start + 1, len(lines)) if lines[j].startswith(("**", ".. "))),
        len(lines),
    )
    return lines[start:end]


def rst_page(readme):
    """The Docker Hub page in reStructuredText, assembled from the README."""
    lines = readme.splitlines()
    parts = [[TITLE, "=" * len(TITLE), ""]]
    parts += [block(lines, bold) for bold in BLOCKS]
    parts += [section(lines, title) for title in SECTIONS]
    return "\n".join(line for part in parts for line in part) + "\n\n" + FULL_MANUAL


def markdown(rst):
    return subprocess.run(
        ["pandoc", "--fail-if-warnings", "-f", "rst", "-t", "gfm"],
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
        raise SystemExit(
            "No Docker Hub credentials in ~/.docker/config.json: run docker login, "
            "without a credsStore there, which keeps them out of this file"
        )
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
        description = markdown(rst_page(f.read()))
    if len(description) > LIMIT:
        raise SystemExit(f"The Docker Hub page is {len(description)} characters, over {LIMIT}")
    user, password = credentials()
    login = "https://hub.docker.com/v2/users/login"
    token = call("POST", login, {"username": user, "password": password})["token"]
    body = {"description": SUMMARY, "full_description": description}
    call("PATCH", REPOSITORY, body, token)
    print(f"Docker Hub page published, {len(description)} characters")


if __name__ == "__main__":
    main()
