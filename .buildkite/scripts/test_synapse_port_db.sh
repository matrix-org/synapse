#!/bin/bash
#
# Test script for 'synapse_port_db', which creates a virtualenv, installs Synapse along
# with additional dependencies needed for the test (such as coverage or the PostgreSQL
# driver), update the schema of the test SQLite database and run background updates on it,
# create an empty test database in PostgreSQL, then run the 'synapse_port_db' script to
# test porting the SQLite database to the PostgreSQL database (with coverage).

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

echo "--- Prepare the databases"

# Make sure the SQLite3 database is using the latest schema and has no pending background update.
scripts-dev/update_database --database-config .buildkite/sqlite-config.yaml

# Create the PostgreSQL database.
./.buildkite/scripts/create_postgres_db.py

echo "+++ Run synapse_port_db"

# Run the script
coverage run scripts/synapse_port_db --sqlite-database .buildkite/test_db.db --postgres-config .buildkite/postgres-config.yaml
