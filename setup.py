import sys
from os.path import dirname, join, realpath

from setuptools import find_packages, setup

VERSION = (
    open(join(dirname(realpath(__file__)), "buttervolume", "VERSION")).read().strip()
)

if sys.version_info < (3, 5):
    sys.exit(
        "Buttervolume currently works only with Python >= 3.5. "
        "We will accept any contribution to support older versions"
    )

setup(
    name="buttervolume",
    version=VERSION,
    author="Christophe Combelles",
    author_email="ccomb@free.fr",
    url="https://github.com/ccomb/buttervolume",
    license="Apache License, Version 2.0",
    description="Docker plugin to manage Docker Volumes as BTRFS subvolumes",
    long_description=open("README.rst").read() + "\n" + open("CHANGES.rst").read(),
    packages=find_packages(),
    package_data={"": ["VERSION"]},
    entry_points={
        "console_scripts": [
            "buttervolume = buttervolume.cli:main",
        ],
    },
    install_requires=[
        "bottle",
        "urllib3<3.0,>=2.3.0",
        "requests-unixsocket2",
        "waitress",
        "webtest",
    ],
    tests_require=[],
    test_suite="test",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Clustering",
    ],
)
