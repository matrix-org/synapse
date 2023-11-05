#!/usr/bin/env python3

# Build the Debian packages using Docker images.
#
# This script builds the Docker images and then executes them sequentially, each
# one building a Debian package for the targeted operating system. It is
# designed to be a "single command" to produce all the images.
#
# By default, builds for all known distributions, but a list of distributions
# can be passed on the commandline for debugging.

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import FrameType
from typing import Collection, Optional, Sequence, Set

# These are expanded inside the dockerfile to be a fully qualified image name.
# e.g. docker.io/library/debian:bullseye
#
# If an EOL is forced by a Python version and we're dropping support for it, make sure
# to remove references to the distibution across Synapse (search for "bullseye" for
# example)
DISTS = (
    "debian:bullseye",  # (EOL ~2024-07) (our EOL forced by Python 3.9 is 2025-10-05)
    "debian:bookworm",  # (EOL not specified yet) (our EOL forced by Python 3.11 is 2027-10-24)
    "debian:sid",  # (EOL not specified yet) (our EOL forced by Python 3.11 is 2027-10-24)
    "ubuntu:focal",  # 20.04 LTS (EOL 2025-04) (our EOL forced by Python 3.8 is 2024-10-14)
    "ubuntu:jammy",  # 22.04 LTS (EOL 2027-04) (our EOL forced by Python 3.10 is 2026-10-04)
    "ubuntu:lunar",  # 23.04 (EOL 2024-01) (our EOL forced by Python 3.11 is 2027-10-24)
    "ubuntu:mantic",  # 23.10 (EOL 2024-07) (our EOL forced by Python 3.11 is 2027-10-24)
    "debian:trixie",  # (EOL not specified yet)
)

DESC = """\
Builds .debs for synapse, using a Docker image for the build environment.

By default, builds for all known distributions, but a list of distributions
can be passed on the commandline for debugging.
"""

projdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


class Builder:
    def __init__(
        self,
        redirect_stdout: bool = False,
        docker_build_args: Optional[Sequence[str]] = None,
    ):
        self.redirect_stdout = redirect_stdout
        self._docker_build_args = tuple(docker_build_args or ())
        self.active_containers: Set[str] = set()
        self._lock = threading.Lock()
        self._failed = False

    def run_build(self, dist: str, skip_tests: bool = False) -> None:
        """Build deb for a single distribution"""

        if self._failed:
            print("not building %s due to earlier failure" % (dist,))
            raise Exception("failed")

        try:
            self._inner_build(dist, skip_tests)
        except Exception as e:
            print("build of %s failed: %s" % (dist, e), file=sys.stderr)
            self._failed = True
            raise

    def _inner_build(self, dist: str, skip_tests: bool = False) -> None:
        tag = dist.split(":", 1)[1]

        # Make the dir where the debs will live.
        #
        # Note that we deliberately put this outside the source tree, otherwise
        # we tend to get source packages which are full of debs. (We could hack
        # around that with more magic in the build_debian.sh script, but that
        # doesn't solve the problem for natively-run dpkg-buildpakage).
        debsdir = os.path.join(projdir, "../debs")
        os.makedirs(debsdir, exist_ok=True)

        if self.redirect_stdout:
            logfile = os.path.join(debsdir, "%s.buildlog" % (tag,))
            print("building %s: directing output to %s" % (dist, logfile))
            stdout = open(logfile, "w")
        else:
            stdout = None

        # first build a docker image for the build environment
        build_args = (
            (
                "docker",
                "build",
                "--tag",
                "dh-venv-builder:" + tag,
                "--build-arg",
                "distro=" + dist,
                "-f",
                "docker/Dockerfile-dhvirtualenv",
            )
            + self._docker_build_args
            + ("docker",)
        )

        subprocess.check_call(
            build_args,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            cwd=projdir,
        )

        container_name = "synapse_build_" + tag
        with self._lock:
            self.active_containers.add(container_name)

        # then run the build itself
        subprocess.check_call(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--volume=" + projdir + ":/synapse/source:ro",
                "--volume=" + debsdir + ":/debs",
                "-e",
                "TARGET_USERID=%i" % (os.getuid(),),
                "-e",
                "TARGET_GROUPID=%i" % (os.getgid(),),
                "-e",
                "DEB_BUILD_OPTIONS=%s" % ("nocheck" if skip_tests else ""),
                "dh-venv-builder:" + tag,
            ],
            stdout=stdout,
            stderr=subprocess.STDOUT,
        )

        with self._lock:
            self.active_containers.remove(container_name)

        if stdout is not None:
            stdout.close()
            print("Completed build of %s" % (dist,))

    def kill_containers(self) -> None:
        with self._lock:
            active = list(self.active_containers)

        for c in active:
            print("killing container %s" % (c,))
            subprocess.run(
                [
                    "docker",
                    "kill",
                    c,
                ],
                stdout=subprocess.DEVNULL,
            )
            with self._lock:
                self.active_containers.remove(c)


def run_builds(
    builder: Builder, dists: Collection[str], jobs: int = 1, skip_tests: bool = False
) -> None:
    def sig(signum: int, _frame: Optional[FrameType]) -> None:
        print("Caught SIGINT")
        builder.kill_containers()

    signal.signal(signal.SIGINT, sig)

    with ThreadPoolExecutor(max_workers=jobs) as e:
        res = e.map(lambda dist: builder.run_build(dist, skip_tests), dists)

    # make sure we consume the iterable so that exceptions are raised.
    for _ in res:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=DESC,
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=1,
        help="specify the number of builds to run in parallel",
    )
    parser.add_argument(
        "--no-check",
        action="store_true",
        help="skip running tests after building",
    )
    parser.add_argument(
        "--docker-build-arg",
        action="append",
        help="specify an argument to pass to docker build",
    )
    parser.add_argument(
        "--show-dists-json",
        action="store_true",
        help="instead of building the packages, just list the dists to build for, as a json array",
    )
    parser.add_argument(
        "dist",
        nargs="*",
        default=DISTS,
        help="a list of distributions to build for. Default: %(default)s",
    )
    args = parser.parse_args()
    if args.show_dists_json:
        print(json.dumps(DISTS))
    else:
        builder = Builder(
            redirect_stdout=(args.jobs > 1), docker_build_args=args.docker_build_arg
        )
        run_builds(
            builder,
            dists=args.dist,
            jobs=args.jobs,
            skip_tests=args.no_check,
        )
