#!/usr/bin/env bash
#
# Test script for 'synapse_port_db'.
#   - configures synapse and a postgres server.
#   - runs the port script on a prepopulated test sqlite db
#   - also runs it against an new sqlite db
#
# Expects Synapse to have been already installed with `poetry install --extras postgres`.
# Expects `poetry` to be available on the `PATH`.

set -xe
cd "$(dirname "$0")/../.."

echo "--- Generate the signing key"

# Generate the server's signing key.
poetry run synapse_homeserver --generate-keys -c .ci/sqlite-config.yaml

echo "--- Prepare test database"

# Make sure the SQLite3 database is using the latest schema and has no pending background update.
poetry run update_synapse_database --database-config .ci/sqlite-config.yaml --run-background-updates

# Create the PostgreSQL database.
poetry run .ci/scripts/postgres_exec.py "CREATE DATABASE synapse"

echo "+++ Run synapse_port_db against test database"
# TODO: this invocation of synapse_port_db (and others below) used to be prepended with `coverage run`,
# but coverage seems unable to find the entrypoints installed by `pip install -e .`.
poetry run synapse_port_db --sqlite-database .ci/test_db.db --postgres-config .ci/postgres-config.yaml

# We should be able to run twice against the same database.
echo "+++ Run synapse_port_db a second time"
poetry run synapse_port_db --sqlite-database .ci/test_db.db --postgres-config .ci/postgres-config.yaml

#####

# Now do the same again, on an empty database.

echo "--- Prepare empty SQLite database"

# we do this by deleting the sqlite db, and then doing the same again.
rm .ci/test_db.db

poetry run update_synapse_database --database-config .ci/sqlite-config.yaml --run-background-updates

# re-create the PostgreSQL database.
poetry run .ci/scripts/postgres_exec.py \
  "DROP DATABASE synapse" \
  "CREATE DATABASE synapse"

echo "+++ Run synapse_port_db against empty database"
poetry run synapse_port_db --sqlite-database .ci/test_db.db --postgres-config .ci/postgres-config.yaml
