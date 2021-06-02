#!/usr/bin/env bash

# This script runs the PostgreSQL tests inside a Docker container. It expects
# the relevant source files to be mounted into /src (done automatically by the
# caller script). It will set up the database, run it, and then use the tox
# configuration to run the tests.

set -e

# Set PGUSER so Synapse's tests know what user to connect to the database with
export PGUSER=postgres

# Initialise & start the database
su -c '/usr/lib/postgresql/9.6/bin/initdb -D /var/lib/postgresql/data -E "UTF-8" --lc-collate="en_US.UTF-8" --lc-ctype="en_US.UTF-8" --username=postgres' postgres
su -c '/usr/lib/postgresql/9.6/bin/pg_ctl -w -D /var/lib/postgresql/data start' postgres

# Run the tests
cd /src
export TRIAL_FLAGS="-j 4"
tox --workdir=/tmp -e py35-postgres
