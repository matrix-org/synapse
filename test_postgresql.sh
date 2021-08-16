#!/usr/bin/env bash

# This script builds the Docker image to run the PostgreSQL tests, and then runs
# the tests.

# Speed up script by not using unicode.
LC_ALL=C
LANG=C

set -e

# Build, and tag
docker build docker/ -f docker/Dockerfile-pgtests -t synapsepgtests

# Run, mounting the current directory into /src
docker run --rm -it -v "$(pwd)$(printf '\:')"/src synapsepgtests
