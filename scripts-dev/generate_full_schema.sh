#!/bin/bash
#
# This script generates SQL files for creating a brand new Synapse DB with the latest
# schema, on both SQLite3 and Postgres.
#
# It does so by having Synapse generate an up-to-date SQLite DB, then running
# synapse_port_db to convert it to Postgres. It then dumps the contents of both.

POSTGRES_HOST="localhost"
POSTGRES_DB_NAME="synapse_full_schema.$$"

SQLITE_FULL_SCHEMA_OUTPUT_FILE="full.sql.sqlite"
POSTGRES_FULL_SCHEMA_OUTPUT_FILE="full.sql.postgres"
OUTPUT_DIR=$(pwd)

REQUIRED_DEPS=("matrix-synapse" "psycopg2")

usage() {
  echo "Usage: $0 -p <postgres_username> -o <path> [-c] [-n] [-h]"
  echo
  echo "-p <postgres_username>"
  echo "  Username to connect to local postgres instance. The password will be requested"
  echo "  during script execution."
  echo "-c"
  echo "  CI mode. Enables coverage tracking and prints every command that the script runs."
  echo "-n"
  echo "  Suppress warning about requiring the use of a virtualenv."
  echo "-o <path>"
  echo "  Directory to output full schema files to."
  echo "-h"
  echo "  Display this help text."
}

while getopts "p:cno:h" opt; do
  case $opt in
    p)
      POSTGRES_USERNAME=$OPTARG
      ;;
    c)
      # Print all commands that are being executed
      set -x

      # Modify required dependencies for coverage
      REQUIRED_DEPS+=("coverage" "coverage-enable-subprocess")

      COVERAGE=1
      ;;
    n)
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

# Check that required dependencies are installed
unsatisfied_requirements=()
for dep in "${REQUIRED_DEPS[@]}"; do
  pip show "$dep" --quiet || unsatisfied_requirements+=("$dep")
done
if [ ! ${#unsatisfied_requirements} -eq 0 ]; then
  echo "Please install the following python packages: ${unsatisfied_requirements[*]}"
  exit 1
fi

# Check that the script is running with a virtualenv enabled
if [ -z "$NO_VIRTUALENV" ] && [ -z "$VIRTUAL_ENV" ]; then
  echo "It is highly recommended to run this script with a virtualenv activated. Exiting now."
  echo "If you wish to suppress this warning, please run with the -n option."
  exit 1
fi

if [ -z "$POSTGRES_USERNAME" ]; then
  echo "No postgres username supplied"
  usage
  exit 1
fi

if [ -z "$OUTPUT_DIR" ]; then
  echo "No output directory supplied"
  usage
  exit 1
fi

read -rsp "Postgres password for '$POSTGRES_USERNAME':" POSTGRES_PASSWORD
echo ""

# Exit immediately if a command fails
set -e

# cd to root of the synapse directory
cd "$(dirname "$0")/.."

# Create temporary SQLite and Postgres homeserver db configs and key file
TMPDIR=$(mktemp -d)
KEY_FILE=$TMPDIR/test.signing.key # default Synapse signing key path
SQLITE_CONFIG=$TMPDIR/sqlite.conf
SQLITE_DB=$TMPDIR/homeserver.db
POSTGRES_CONFIG=$TMPDIR/postgres.conf

# Ensure these files are delete on script exit
trap 'rm -rf $TMPDIR' EXIT

cat > "$SQLITE_CONFIG" <<EOF
server_name: "test"

signing_key_path: "$KEY_FILE"
macaroon_secret_key: "abcde"

report_stats: false

database:
  name: "sqlite3"
  args:
    database: "$SQLITE_DB"

# Suppress the key server warning.
trusted_key_servers: []
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
trusted_key_servers: []
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
createdb $POSTGRES_DB_NAME

echo "Copying data from SQLite3 to Postgres with synapse_port_db..."
if [ -z "$COVERAGE" ]; then
  # No coverage needed
  scripts/synapse_port_db --sqlite-database "$SQLITE_DB" --postgres-config "$POSTGRES_CONFIG"
else
  # Coverage desired
  coverage run scripts/synapse_port_db --sqlite-database "$SQLITE_DB" --postgres-config "$POSTGRES_CONFIG"
fi

# Delete schema_version, applied_schema_deltas and applied_module_schemas tables
# This needs to be done after synapse_port_db is run
echo "Dropping unwanted db tables..."
SQL="
DROP TABLE schema_version;
DROP TABLE applied_schema_deltas;
DROP TABLE applied_module_schemas;
"
sqlite3 "$SQLITE_DB" <<< "$SQL"
psql $POSTGRES_DB_NAME -U "$POSTGRES_USERNAME" -w <<< "$SQL"

echo "Dumping SQLite3 schema to '$SQLITE_FULL_SCHEMA_OUTPUT_FILE'..."
sqlite3 "$SQLITE_DB_FILE_NAME" ".dump" > "$OUTPUT_DIR/$SQLITE_FULL_SCHEMA_OUTPUT_FILE"

echo "Dumping Postgres schema to '$POSTGRES_FULL_SCHEMA_OUTPUT_FILE'..."
pg_dump --format=plain --no-tablespaces --no-acl --no-owner $POSTGRES_DB_NAME | sed -e '/^--/d' -e 's/public\.//g' -e '/^SET /d' -e '/^SELECT /d' > "$OUTPUT_DIR/$POSTGRES_FULL_SCHEMA_OUTPUT_FILE"

echo "Cleaning up temporary Postgres database..."
dropdb $POSTGRES_DB_NAME

# Remove last pesky instance of this table from the output
sed -i '/applied_module_schemas/d' "$OUTPUT_DIR/$POSTGRES_FULL_SCHEMA_OUTPUT_FILE"

echo "Done! Files dumped to: $OUTPUT_DIR"
