#!/bin/bash

# This is will prepare a synapse database for running with v0.0.1 of synapse. 
# It will store all the user information, but will *delete* all messages and
# room data.

set -e

cp "$1" "$1.bak"

DUMP=$(sqlite3 "$1" << 'EOF'
.dump users
.dump access_tokens
.dump presence
.dump profiles
EOF
)

rm "$1"

sqlite3 "$1" <<< "$DUMP" 
