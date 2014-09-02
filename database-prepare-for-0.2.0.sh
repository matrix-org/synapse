#!/bin/bash

# This is will prepare a synapse database for running with v0.2.0 of synapse. 

set -e

cp "$1" "$1.bak"

sqlite3 "$1" < "synapse/storage/schema/im.sql" 
sqlite3 "$1" <<< "PRAGMA user_version = 2;"
