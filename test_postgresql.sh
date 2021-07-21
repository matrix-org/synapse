#!/usr/bin/env bash

# This script builds the Docker image to run the PostgreSQL tests, and then runs
# the tests.

set -e

# Build, and tag
docker build docker/ -f docker/Dockerfile-pgtests -t synapsepgtests

# Run, mounting the current directory into /src
docker run --rm -it -v $(pwd)\:/src synapsepgtests
