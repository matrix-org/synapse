#!/bin/sh

# This script will write a dump file of local user state if you want to splat
# your entire server database and start again but preserve the identity of
# local users and their access tokens.
#
# To restore it, use
#
#   $ sqlite3 homeserver.db < table-save.sql

sqlite3 "$1" <<'EOF' >table-save.sql
.dump users
.dump access_tokens
.dump presence
.dump profiles
EOF
