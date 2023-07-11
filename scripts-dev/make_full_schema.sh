#!/usr/bin/env bash
#
# This script generates SQL files for creating a brand new Synapse DB with the latest
# schema, on both SQLite3 and Postgres.

export PGHOST="localhost"
POSTGRES_MAIN_DB_NAME="synapse_full_schema_main.$$"
POSTGRES_COMMON_DB_NAME="synapse_full_schema_common.$$"
POSTGRES_STATE_DB_NAME="synapse_full_schema_state.$$"
REQUIRED_DEPS=("matrix-synapse" "psycopg2")

usage() {
  echo
  echo "Usage: $0 -p <postgres_username> -o <path> [-c] [-n <schema number>] [-h]"
  echo
  echo "-p <postgres_username>"
  echo "  Username to connect to local postgres instance. The password will be requested"
  echo "  during script execution."
  echo "-c"
  echo "  CI mode. Prints every command that the script runs."
  echo "-o <path>"
  echo "  Directory to output full schema files to. You probably want to use"
  echo "  '-o synapse/storage/schema'"
  echo "-n <schema number>"
  echo "  Schema number for the new snapshot. Used to set the location of files within "
  echo "  the output directory, mimicking that of synapse/storage/schemas."
  echo "  Defaults to 9999."
  echo "-h"
  echo "  Display this help text."
  echo ""
  echo ""
  echo "You probably want to invoke this with something like"
  echo "  docker run --rm -e POSTGRES_PASSWORD=postgres -e POSTGRES_USER=postgres -e POSTGRES_DB=synapse -p 5432:5432 postgres:11-alpine"
  echo "  echo postgres | scripts-dev/make_full_schema.sh -p postgres -n MY_SCHEMA_NUMBER -o synapse/storage/schema"
  echo ""
  echo "  NB: make sure to run this against the *oldest* supported version of postgres,"
  echo "  or else pg_dump might output non-backwards-compatible syntax."
}

SCHEMA_NUMBER="9999"
while getopts "p:co:hn:" opt; do
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
    n)
      SCHEMA_NUMBER="$OPTARG"
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
SQLITE_MAIN_DB=$TMPDIR/main.db
SQLITE_STATE_DB=$TMPDIR/state.db
SQLITE_COMMON_DB=$TMPDIR/common.db
POSTGRES_CONFIG=$TMPDIR/postgres.conf

# Ensure these files are delete on script exit
cleanup() {
  echo "Cleaning up temporary sqlite database and config files..."
  rm -r "$TMPDIR"
  echo "Cleaning up temporary Postgres database..."
  dropdb --if-exists "$POSTGRES_COMMON_DB_NAME"
  dropdb --if-exists "$POSTGRES_MAIN_DB_NAME"
  dropdb --if-exists "$POSTGRES_STATE_DB_NAME"
}
trap 'cleanup' EXIT

cat > "$SQLITE_CONFIG" <<EOF
server_name: "test"

signing_key_path: "$KEY_FILE"
macaroon_secret_key: "abcde"

report_stats: false

databases:
  common:
    name: "sqlite3"
    data_stores: []
    args:
      database: "$SQLITE_COMMON_DB"
  main:
    name: "sqlite3"
    data_stores: ["main"]
    args:
      database: "$SQLITE_MAIN_DB"
  state:
    name: "sqlite3"
    data_stores: ["state"]
    args:
      database: "$SQLITE_STATE_DB"

# Suppress the key server warning.
trusted_key_servers: []
EOF

cat > "$POSTGRES_CONFIG" <<EOF
server_name: "test"

signing_key_path: "$KEY_FILE"
macaroon_secret_key: "abcde"

report_stats: false

databases:
  common:
    name: "psycopg2"
    data_stores: []
    args:
      user: "$PGUSER"
      host: "$PGHOST"
      password: "$PGPASSWORD"
      database: "$POSTGRES_COMMON_DB_NAME"
  main:
    name: "psycopg2"
    data_stores: ["main"]
    args:
      user: "$PGUSER"
      host: "$PGHOST"
      password: "$PGPASSWORD"
      database: "$POSTGRES_MAIN_DB_NAME"
  state:
    name: "psycopg2"
    data_stores: ["state"]
    args:
      user: "$PGUSER"
      host: "$PGHOST"
      password: "$PGPASSWORD"
      database: "$POSTGRES_STATE_DB_NAME"


# Suppress the key server warning.
trusted_key_servers: []
EOF

# Generate the server's signing key.
echo "Generating SQLite3 db schema..."
python -m synapse.app.homeserver --generate-keys -c "$SQLITE_CONFIG"

# Make sure the SQLite3 database is using the latest schema and has no pending background update.
echo "Running db background jobs..."
poetry run python synapse/_scripts/update_synapse_database.py --database-config "$SQLITE_CONFIG" --run-background-updates

# Create the PostgreSQL database.
echo "Creating postgres databases..."
createdb --lc-collate=C --lc-ctype=C --template=template0 "$POSTGRES_COMMON_DB_NAME"
createdb --lc-collate=C --lc-ctype=C --template=template0 "$POSTGRES_MAIN_DB_NAME"
createdb --lc-collate=C --lc-ctype=C --template=template0 "$POSTGRES_STATE_DB_NAME"

echo "Running db background jobs..."
poetry run python synapse/_scripts/update_synapse_database.py --database-config "$POSTGRES_CONFIG" --run-background-updates


echo "Dropping unwanted db tables..."

# Some common tables are created and updated by Synapse itself and do not belong in the
# schema.
DROP_APP_MANAGED_TABLES="
DROP TABLE schema_version;
DROP TABLE schema_compat_version;
DROP TABLE applied_schema_deltas;
DROP TABLE applied_module_schemas;
"
# Other common tables are not created by Synapse and do belong in the schema.
# TODO: we could derive DROP_COMMON_TABLES from the dump of the common-only DB. But
#       since there's only one table there, I haven't bothered to do so.
DROP_COMMON_TABLES="$DROP_APP_MANAGED_TABLES
DROP TABLE background_updates;
"

sqlite3 "$SQLITE_COMMON_DB" <<< "$DROP_APP_MANAGED_TABLES"
sqlite3 "$SQLITE_MAIN_DB" <<< "$DROP_COMMON_TABLES"
sqlite3 "$SQLITE_STATE_DB" <<< "$DROP_COMMON_TABLES"
psql "$POSTGRES_COMMON_DB_NAME" -w <<< "$DROP_APP_MANAGED_TABLES"
psql "$POSTGRES_MAIN_DB_NAME" -w <<< "$DROP_COMMON_TABLES"
psql "$POSTGRES_STATE_DB_NAME" -w <<< "$DROP_COMMON_TABLES"

# For Reasons(TM), SQLite's `.schema` also dumps out "shadow tables", the implementation
# details behind full text search tables. Omit these from the dumps.

sqlite3 "$SQLITE_MAIN_DB" <<< "
DROP TABLE event_search_content;
DROP TABLE event_search_segments;
DROP TABLE event_search_segdir;
DROP TABLE event_search_docsize;
DROP TABLE event_search_stat;
DROP TABLE user_directory_search_content;
DROP TABLE user_directory_search_segments;
DROP TABLE user_directory_search_segdir;
DROP TABLE user_directory_search_docsize;
DROP TABLE user_directory_search_stat;
"

echo "Dumping SQLite3 schema..."

mkdir -p "$OUTPUT_DIR/"{common,main,state}"/full_schemas/$SCHEMA_NUMBER"
sqlite3 "$SQLITE_COMMON_DB" ".schema"                    > "$OUTPUT_DIR/common/full_schemas/$SCHEMA_NUMBER/full.sql.sqlite"
sqlite3 "$SQLITE_COMMON_DB" ".dump --data-only --nosys" >> "$OUTPUT_DIR/common/full_schemas/$SCHEMA_NUMBER/full.sql.sqlite"
sqlite3 "$SQLITE_MAIN_DB"   ".schema"                    > "$OUTPUT_DIR/main/full_schemas/$SCHEMA_NUMBER/full.sql.sqlite"
sqlite3 "$SQLITE_MAIN_DB"   ".dump --data-only --nosys" >> "$OUTPUT_DIR/main/full_schemas/$SCHEMA_NUMBER/full.sql.sqlite"
sqlite3 "$SQLITE_STATE_DB"  ".schema"                    > "$OUTPUT_DIR/state/full_schemas/$SCHEMA_NUMBER/full.sql.sqlite"
sqlite3 "$SQLITE_STATE_DB"  ".dump --data-only --nosys" >> "$OUTPUT_DIR/state/full_schemas/$SCHEMA_NUMBER/full.sql.sqlite"

cleanup_pg_schema() {
  # Cleanup as follows:
  # - Remove empty lines. pg_dump likes to output a lot of these.
  # - Remove comment-only lines. pg_dump also likes to output a lot of these to visually
  #   separate tables etc.
  # - Remove "public." prefix --- the schema name.
  # - Remove "SET" commands. Last time I ran this, the output commands were
  #     SET statement_timeout = 0;
  #     SET lock_timeout = 0;
  #     SET idle_in_transaction_session_timeout = 0;
  #     SET client_encoding = 'UTF8';
  #     SET standard_conforming_strings = on;
  #     SET check_function_bodies = false;
  #     SET xmloption = content;
  #     SET client_min_messages = warning;
  #     SET row_security = off;
  #     SET default_table_access_method = heap;
  # - Very carefully remove specific SELECT statements. We CANNOT blanket remove all
  #   SELECT statements because some of those have side-effects which we do want in the
  #   schema. Last time I ran this, the only SELECTS were
  #     SELECT pg_catalog.set_config('search_path', '', false);
  #   and
  #     SELECT pg_catalog.setval(text, bigint, bool);
  #   We do want to remove the former, but the latter is important. If the last argument
  #   is `true` or omitted, this marks the given integer as having been consumed and
  #   will NOT appear as the nextval.
   sed -e '/^$/d' \
   -e '/^--/d' \
   -e 's/public\.//g' \
   -e '/^SET /d' \
   -e '/^SELECT pg_catalog.set_config/d'
}

echo "Dumping Postgres schema..."

pg_dump --format=plain --schema-only         --no-tablespaces --no-acl --no-owner "$POSTGRES_COMMON_DB_NAME" | cleanup_pg_schema  > "$OUTPUT_DIR/common/full_schemas/$SCHEMA_NUMBER/full.sql.postgres"
pg_dump --format=plain --data-only --inserts --no-tablespaces --no-acl --no-owner "$POSTGRES_COMMON_DB_NAME" | cleanup_pg_schema >> "$OUTPUT_DIR/common/full_schemas/$SCHEMA_NUMBER/full.sql.postgres"
pg_dump --format=plain --schema-only         --no-tablespaces --no-acl --no-owner "$POSTGRES_MAIN_DB_NAME"   | cleanup_pg_schema  > "$OUTPUT_DIR/main/full_schemas/$SCHEMA_NUMBER/full.sql.postgres"
pg_dump --format=plain --data-only --inserts --no-tablespaces --no-acl --no-owner "$POSTGRES_MAIN_DB_NAME"   | cleanup_pg_schema >> "$OUTPUT_DIR/main/full_schemas/$SCHEMA_NUMBER/full.sql.postgres"
pg_dump --format=plain --schema-only         --no-tablespaces --no-acl --no-owner "$POSTGRES_STATE_DB_NAME"  | cleanup_pg_schema  > "$OUTPUT_DIR/state/full_schemas/$SCHEMA_NUMBER/full.sql.postgres"
pg_dump --format=plain --data-only --inserts --no-tablespaces --no-acl --no-owner "$POSTGRES_STATE_DB_NAME"  | cleanup_pg_schema >> "$OUTPUT_DIR/state/full_schemas/$SCHEMA_NUMBER/full.sql.postgres"

if [[ "$OUTPUT_DIR" == *synapse/storage/schema ]]; then
  echo "Updating contrib/datagrip symlinks..."
  ln -sf "../../synapse/storage/schema/common/full_schemas/$SCHEMA_NUMBER/full.sql.postgres" "contrib/datagrip/common.sql"
  ln -sf "../../synapse/storage/schema/main/full_schemas/$SCHEMA_NUMBER/full.sql.postgres"   "contrib/datagrip/main.sql"
  ln -sf "../../synapse/storage/schema/state/full_schemas/$SCHEMA_NUMBER/full.sql.postgres"  "contrib/datagrip/state.sql"
else
  echo "Not updating contrib/datagrip symlinks (unknown output directory)"
fi
echo "Done! Files dumped to: $OUTPUT_DIR"
