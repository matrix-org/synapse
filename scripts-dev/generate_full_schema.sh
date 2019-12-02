#!/bin/bash
#
# This script generates SQL files for creating a brand new Synapse DB with the latest
# schema, on both SQLite3 and Postgres.
#
# It does so by having Synapse generate an up-to-date SQLite DB, then running
# synapse_port_db to convert it to Postgres. It then dumps the contents of both.

POSTGRES_HOST="localhost"
POSTGRES_DB_NAME="synapse_full_schema.$$"
SQLITE_DB_FILE_NAME="full_schema_sqlite.db"

SQLITE_FULL_SCHEMA_OUTPUT_FILE="full.sql.sqlite"
POSTGRES_FULL_SCHEMA_OUTPUT_FILE="full.sql.postgres"
OUTPUT_DIR=$(pwd)

usage() {
  echo "Usage: $0 -p <postgres_username> [-c] [-v] [-o] [-h]"
  echo
  echo "-p <postgres_username>"
  echo "  Username to connect to local postgres instance. The password will be requested"
  echo "  during script execution."
  echo "-c"
  echo "  Enable coverage tracking. Useful for CI runs."
  echo "-v"
  echo "  Suppress warning about requiring the use of a virtualenv."
  echo "-o"
  echo "  Directory to output full schema files to. Defaults to the current directory."
  echo "-h"
  echo "  Display this help text."
}

while getopts "p:cvo:h" opt; do
  case $opt in
    p)
      POSTGRES_USERNAME=$OPTARG
      ;;
    c)
      COVERAGE=1
      ;;
    v)
      NO_VIRTUALENV=1
      ;;
    o)
      command -v realpath > /dev/null || (echo "The -o flag requires the 'realpath' binary to be installed" && exit 1)
      OUTPUT_DIR="$(realpath "$OPTARG")"
      ;;
    h)
      usage
      exit
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      exit
      ;;
  esac
done

# Check that the script is running with a virtualenv enabled
if [ -z ${NO_VIRTUALENV+x} ] && [ -z ${VIRTUAL_ENV+x} ]; then
  echo "It is highly recommended to run this script with a virtualenv activated. Exiting now."
  echo "If you wish to suppress this warning, please run with the -v option."
  exit 1
fi

if [ -z ${POSTGRES_USERNAME+x} ]; then
  echo "No postgres username supplied"
  usage
  exit 1
fi

read -rsp "Postgres password for '$POSTGRES_USERNAME':" POSTGRES_PASSWORD
echo ""

set -xe

# cd to root of the synapse directory
cd "$(dirname "$0")/.."

# Install required dependencies
echo "Installing dependencies..."
if [ -z ${COVERAGE+x} ]; then
  # No coverage needed
  pip install psycopg2
else
  # Coverage desired
  pip install psycopg2 coverage coverage-enable-subprocess
fi

# Install Synapse itself. This won't update any libraries.
pip install -e .

# Create temporary SQLite and Postgres homeserver db configs and key file
KEY_FILE=$(mktemp)
SQLITE_CONFIG=$(mktemp)
POSTGRES_CONFIG=$(mktemp)
cat > "$SQLITE_CONFIG" <<EOF
server_name: "test"

signing_key_path: "$KEY_FILE"
macaroon_secret_key: "abcde"

report_stats: false

database:
  name: "sqlite3"
  args:
    database: "$SQLITE_DB_FILE_NAME"

# Suppress the key server warning.
trusted_key_servers:
  - server_name: "matrix.org"
suppress_key_server_warning: true
EOF

cat > "$POSTGRES_CONFIG" <<EOF
server_name: "test"

signing_key_path: "$KEY_FILE"
macaroon_secret_key: "abcde"

report_stats: false

database:
  name: "psycopg2"
  args:
    user: "$POSTGRES_USERNAME"
    host: "$POSTGRES_HOST"
    password: "$POSTGRES_PASSWORD"
    database: "$POSTGRES_DB_NAME"

# Suppress the key server warning.
trusted_key_servers:
  - server_name: "matrix.org"
suppress_key_server_warning: true
EOF

# Generate the server's signing key.
echo "Generating SQLite3 db schema..."
python -m synapse.app.homeserver --generate-keys -c "$SQLITE_CONFIG"

# Make sure the SQLite3 database is using the latest schema and has no pending background update.
echo "Running db background jobs..."
scripts-dev/update_database --database-config "$SQLITE_CONFIG"

# Create the PostgreSQL database.
echo "Creating postgres database..."
createdb synapse_full_schema

echo "Copying data from SQLite3 to Postgres with synapse_port_db..."
if [ -z ${COVERAGE+x} ]; then
  # No coverage needed
  scripts/synapse_port_db --sqlite-database "$SQLITE_DB_FILE_NAME" --postgres-config "$POSTGRES_CONFIG"
else
  # Coverage desired
  coverage run scripts/synapse_port_db --sqlite-database "$SQLITE_DB_FILE_NAME" --postgres-config "$POSTGRES_CONFIG"
fi

# Delete schema_version, applied_schema_deltas and applied_module_schemas tables
# This needs to be done after synapse_port_db is run
echo "Dropping unwanted db tables..."
sqlite3 $SQLITE_DB_FILE_NAME "DROP TABLE schema_version"
sqlite3 $SQLITE_DB_FILE_NAME "DROP TABLE applied_schema_deltas"
sqlite3 $SQLITE_DB_FILE_NAME "DROP TABLE applied_module_schemas"
psql $POSTGRES_DB_NAME -U "$POSTGRES_USERNAME" -w -c 'DROP TABLE schema_version'
psql $POSTGRES_DB_NAME -U "$POSTGRES_USERNAME" -w -c 'DROP TABLE applied_schema_deltas'
psql $POSTGRES_DB_NAME -U "$POSTGRES_USERNAME" -w -c 'DROP TABLE applied_module_schemas'

echo "Dumping SQLite3 schema to '$SQLITE_FULL_SCHEMA_OUTPUT_FILE'..."
sqlite3 "$SQLITE_DB_FILE_NAME" ".dump" > "$OUTPUT_DIR/$SQLITE_FULL_SCHEMA_OUTPUT_FILE"

echo "Dumping Postgres schema to '$POSTGRES_FULL_SCHEMA_OUTPUT_FILE'..."
pg_dump --format=plain --no-tablespaces --no-acl --no-owner $POSTGRES_DB_NAME | sed -e '/^--/d' -e 's/public\.//g' -e '/^SET /d' -e '/^SELECT /d' > "$OUTPUT_DIR/$POSTGRES_FULL_SCHEMA_OUTPUT_FILE"

echo "Cleaning up temporary files and databases..."
rm "$SQLITE_DB_FILE_NAME"
rm "$POSTGRES_CONFIG"
rm "$SQLITE_CONFIG"
rm "$KEY_FILE"
dropdb $POSTGRES_DB_NAME

# Remove last pesky instance of this table from the output
sed -i '/applied_module_schemas/d' "$OUTPUT_DIR/$POSTGRES_FULL_SCHEMA_OUTPUT_FILE"

echo "Done! Files dumped to: $OUTPUT_DIR"
