#!/usr/bin/env bash
#
# Test script for 'synapse_port_db'.
#   - sets up synapse and deps
#   - runs the port script on a prepopulated test sqlite db
#   - also runs it against an new sqlite db


set -xe
cd `dirname $0`/../..

echo "--- Install dependencies"

# Install dependencies for this test.
pip install psycopg2 coverage coverage-enable-subprocess

# Install Synapse itself. This won't update any libraries.
pip install -e .

echo "--- Generate the signing key"

# Generate the server's signing key.
python -m synapse.app.homeserver --generate-keys -c .buildkite/sqlite-config.yaml

echo "--- Prepare test database"

# Make sure the SQLite3 database is using the latest schema and has no pending background update.
scripts-dev/update_database --database-config .buildkite/sqlite-config.yaml

# Create the PostgreSQL database.
./.buildkite/scripts/postgres_exec.py "CREATE DATABASE synapse"

echo "+++ Run synapse_port_db against test database"
coverage run scripts/synapse_port_db --sqlite-database .buildkite/test_db.db --postgres-config .buildkite/postgres-config.yaml

# We should be able to run twice against the same database.
echo "+++ Run synapse_port_db a second time"
coverage run scripts/synapse_port_db --sqlite-database .buildkite/test_db.db --postgres-config .buildkite/postgres-config.yaml

#####

# Now do the same again, on an empty database.

echo "--- Prepare empty SQLite database"

# we do this by deleting the sqlite db, and then doing the same again.
rm .buildkite/test_db.db

scripts-dev/update_database --database-config .buildkite/sqlite-config.yaml

# re-create the PostgreSQL database.
./.buildkite/scripts/postgres_exec.py \
  "DROP DATABASE synapse" \
  "CREATE DATABASE synapse"

echo "+++ Run synapse_port_db against empty database"
coverage run scripts/synapse_port_db --sqlite-database .buildkite/test_db.db --postgres-config .buildkite/postgres-config.yaml
