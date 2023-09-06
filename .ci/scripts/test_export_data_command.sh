#!/usr/bin/env bash

# Test for the export-data admin command against sqlite and postgres

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

# Run the export-data command on the sqlite test database
poetry run python -m synapse.app.admin_cmd -c .ci/sqlite-config.yaml  export-data @anon-20191002_181700-832:localhost:8800 \
--output-directory /tmp/export_data

# Test that the output directory exists and contains the rooms directory
dir_r="/tmp/export_data/rooms"
dir_u="/tmp/export_data/user_data"
if [ -d "$dir_r" ] && [ -d "$dir_u" ]; then
  echo "Command successful, this test passes"
else
  echo "No output directories found, the command fails against a sqlite database."
  exit 1
fi

# Create the PostgreSQL database.
psql -c "CREATE DATABASE synapse"

# Port the SQLite databse to postgres so we can check command works against postgres
echo "+++ Port SQLite3 databse to postgres"
poetry run synapse_port_db --sqlite-database .ci/test_db.db --postgres-config .ci/postgres-config.yaml

# Run the export-data command on postgres database
poetry run python -m synapse.app.admin_cmd -c .ci/postgres-config.yaml  export-data @anon-20191002_181700-832:localhost:8800 \
--output-directory /tmp/export_data2

# Test that the output directory exists and contains the rooms directory
dir_r2="/tmp/export_data2/rooms"
dir_u2="/tmp/export_data2/user_data"
if [ -d "$dir_r2" ] && [ -d "$dir_u2" ]; then
  echo "Command successful, this test passes"
else
  echo "No output directories found, the command fails against a postgres database."
  exit 1
fi
