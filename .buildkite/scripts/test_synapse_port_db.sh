#!/bin/bash -xe

find . -name '*.pyc' -delete

pip install psycopg2 coverage coverage-enable-subprocess

# Install Synapse itself. This won't update any libraries.
pip install -e .

# Make sure the SQLite3 database is using the latest schema and has no pending background update.
scripts-dev/update_database --database-config .buildkite/sqlite-config.yaml

# Create the PostgreSQL database.
PGPASSWORD=postgres createdb -h postgres -u postgres synapse

# Run the script
coverage run scripts/synapse_port_db --sqlite-database .buildkite/test_db.db --postgres-config .buildkite/postgres-config.yaml
