#!/usr/bin/env bash

# Test for the export-data admin command against sqlite and postgres

set -xe
cd "$(dirname "$0")/../.."

echo "--- Install dependencies"

# Install dependencies for this test.
pip install psycopg2

# Install Synapse itself. This won't update any libraries.
pip install -e .

echo "--- Generate the signing key"

# Generate the server's signing key.
python -m synapse.app.homeserver --generate-keys -c .ci/sqlite-config.yaml

echo "--- Prepare test database"

# Make sure the SQLite3 database is using the latest schema and has no pending background update.
scripts/update_synapse_database --database-config .ci/sqlite-config.yaml --run-background-updates

# Run the export-data command on the sqlite test database
python -m synapse.app.admin_cmd -c .ci/sqlite-config.yaml  export-data @anon-20191002_181700-832:localhost:8800 \
--output-directory /tmp/export_data

# Test that the output directory exists and contains the rooms directory
dir="/tmp/export_data/rooms"
if [ -d "$dir" ]; then
  echo "Command successful, this test passes"
else
  echo "No output directories found, the command fails against a sqlite database."
  exit 1
fi

# Create the PostgreSQL database.
.ci/scripts/postgres_exec.py "CREATE DATABASE synapse"

# Port the SQLite databse to postgres so we can check command works against postgres
echo "+++ Port SQLite3 databse to postgres"
scripts/synapse_port_db --sqlite-database .ci/test_db.db --postgres-config .ci/postgres-config.yaml

# Run the export-data command on postgres database
python -m synapse.app.admin_cmd -c .ci/postgres-config.yaml  export-data @anon-20191002_181700-832:localhost:8800 \
--output-directory /tmp/export_data2

# Test that the output directory exists and contains the rooms directory
dir2="/tmp/export_data2/rooms"
if [ -d "$dir2" ]; then
  echo "Command successful, this test passes"
else
  echo "No output directories found, the command fails against a postgres database."
  exit 1
fi
