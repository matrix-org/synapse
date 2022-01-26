#!/usr/bin/env bash

# This script runs the PostgreSQL tests inside a Docker container. It expects
# the relevant source files to be mounted into /src (done automatically by the
# caller script). It will set up the database, run it, and then use the tox
# configuration to run the tests.

set -e

# Set PGUSER so Synapse's tests know what user to connect to the database with
export PGUSER=postgres

# Start the database
sudo -u postgres /usr/lib/postgresql/10/bin/pg_ctl -w -D /var/lib/postgresql/data start

# Run the tests
cd /src
export TRIAL_FLAGS="-j 4"
tox --workdir=./.tox-pg-container -e py37-postgres "$@"
