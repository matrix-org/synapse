#!/usr/bin/env bash

# This script builds the Docker image to run the PostgreSQL tests, and then runs
# the tests. It uses a dedicated tox environment so that we don't have to
# rebuild it each time.

# Command line arguments to this script are forwarded to "tox" and then to "trial".

set -e

# Build, and tag
docker build docker/ \
  --build-arg "UID=$(id -u)" \
  --build-arg "GID=$(id -g)" \
  -f docker/Dockerfile-pgtests \
  -t synapsepgtests

# Run, mounting the current directory into /src
docker run --rm -it -v "$(pwd):/src" -v synapse-pg-test-tox:/tox synapsepgtests "$@"
