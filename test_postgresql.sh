#!/usr/bin/env bash

# This script builds the Docker image to run the PostgreSQL tests, and then runs
# the tests. It uses a dedicated tox environment so that we don't have to
# rebuild it each time.

# Command line arguments to this script are forwarded to "tox" and then to "trial".

set -e

# Build, and tag
docker build docker/ -f docker/Dockerfile-pgtests -t synapsepgtests

# Create a place to persist tox's environment so reruns are faster.
# NB: I'm using a separate docker volume here, because you may have already run
# "tox -e py36-postgres" on your system. You might not be using the distro used
# in Dockerfile-pgtests, and so might be using a different CPython build! I don't
# want there to be any accidental clashes
docker volume create synapse-pg-test-tox

# Run, mounting the current directory into /src
docker run --rm -it -v "$(pwd):/src" -v synapse-pg-test-tox:/tox synapsepgtests "$@"
