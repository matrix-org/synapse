#!/usr/bin/env bash
#
# This script generates SQL files for creating a brand new Synapse DB with the latest
# schema, on both SQLite3 and Postgres.
#
# It does so by having Synapse generate an up-to-date SQLite DB, then running
# synapse_port_db to convert it to Postgres. It then dumps the contents of both.

export PGHOST="localhost"
POSTGRES_DB_NAME="synapse_full_schema.$$"

SQLITE_SCHEMA_FILE="schema.sql.sqlite"
SQLITE_ROWS_FILE="rows.sql.sqlite"
POSTGRES_SCHEMA_FILE="full.sql.postgres"
POSTGRES_ROWS_FILE="rows.sql.postgres"

REQUIRED_DEPS=("matrix-synapse" "psycopg2")

usage() {
  echo
  echo "Usage: $0 -p <postgres_username> -o <path> [-c] [-n] [-h]"
  echo
  echo "-p <postgres_username>"
  echo "  Username to connect to local postgres instance. The password will be requested"
  echo "  during script execution."
  echo "-c"
  echo "  CI mode. Prints every command that the script runs."
  echo "-o <path>"
  echo "  Directory to output full schema files to."
  echo "-h"
  echo "  Display this help text."
}

while getopts "p:co:h" opt; do
  case $opt in
    p)
      export PGUSER=$OPTARG
      ;;
    c)
      # Print all commands that are being executed
      set -x
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
      echo "ERROR: Invalid option: -$OPTARG" >&2
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
if [ ${#unsatisfied_requirements} -ne 0 ]; then
  echo "Please install the following python packages: ${unsatisfied_requirements[*]}"
  exit 1
fi

if [ -z "$PGUSER" ]; then
  echo "No postgres username supplied"
  usage
  exit 1
fi

if [ -z "$OUTPUT_DIR" ]; then
  echo "No output directory supplied"
  usage
  exit 1
fi

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

read -rsp "Postgres password for '$PGUSER': " PGPASSWORD
echo ""
export PGPASSWORD

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
# TODO: the trap should also drop the temp postgres DB
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
EOF

cat > "$POSTGRES_CONFIG" <<EOF
server_name: "test"

signing_key_path: "$KEY_FILE"
macaroon_secret_key: "abcde"

report_stats: false

database:
  name: "psycopg2"
  args:
    user: "$PGUSER"
    host: "$PGHOST"
    password: "$PGPASSWORD"
    database: "$POSTGRES_DB_NAME"

# Suppress the key server warning.
trusted_key_servers: []
EOF

# Generate the server's signing key.
echo "Generating SQLite3 db schema..."
python -m synapse.app.homeserver --generate-keys -c "$SQLITE_CONFIG"

# Make sure the SQLite3 database is using the latest schema and has no pending background update.
echo "Running db background jobs..."
synapse/_scripts/update_synapse_database.py --database-config "$SQLITE_CONFIG" --run-background-updates

# Create the PostgreSQL database.
echo "Creating postgres database..."
createdb --lc-collate=C --lc-ctype=C --template=template0 "$POSTGRES_DB_NAME"

echo "Running db background jobs..."
synapse/_scripts/update_synapse_database.py --database-config "$POSTGRES_CONFIG" --run-background-updates


# Delete schema_version, applied_schema_deltas and applied_module_schemas tables
# Also delete any shadow tables from fts4
echo "Dropping unwanted db tables..."
SQL="
DROP TABLE schema_version;
DROP TABLE applied_schema_deltas;
DROP TABLE applied_module_schemas;
"
sqlite3 "$SQLITE_DB" <<< "$SQL"
psql "$POSTGRES_DB_NAME" -w <<< "$SQL"

echo "Dumping SQLite3 schema to '$OUTPUT_DIR/$SQLITE_SCHEMA_FILE' and '$OUTPUT_DIR/$SQLITE_ROWS_FILE'..."
sqlite3 "$SQLITE_DB" ".schema --indent" > "$OUTPUT_DIR/$SQLITE_SCHEMA_FILE"
sqlite3 "$SQLITE_DB" ".dump --data-only --nosys" > "$OUTPUT_DIR/$SQLITE_ROWS_FILE"

echo "Dumping Postgres schema to '$OUTPUT_DIR/$POSTGRES_SCHEMA_FILE' and '$OUTPUT_DIR/$POSTGRES_ROWS_FILE'..."
pg_dump --format=plain --schema-only         --no-tablespaces --no-acl --no-owner "$POSTGRES_DB_NAME" | sed -e '/^$/d' -e '/^--/d' -e 's/public\.//g' -e '/^SET /d' -e '/^SELECT /d' > "$OUTPUT_DIR/$POSTGRES_SCHEMA_FILE"
pg_dump --format=plain --data-only --inserts --no-tablespaces --no-acl --no-owner "$POSTGRES_DB_NAME" | sed -e '/^$/d' -e '/^--/d' -e 's/public\.//g' -e '/^SET /d' -e '/^SELECT /d' > "$OUTPUT_DIR/$POSTGRES_ROWS_FILE"

echo "Cleaning up temporary Postgres database..."
dropdb $POSTGRES_DB_NAME

echo "Done! Files dumped to: $OUTPUT_DIR"
