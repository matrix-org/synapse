#!/bin/bash

set -e

DIR="$( cd "$( dirname "$0" )" && pwd )"

PID_FILE="$DIR/servers.pid"

if [ -f $PID_FILE ]; then
    echo "servers.pid exists!"
    exit 1
fi

find "$DIR" -name "*.log" -delete
find "$DIR" -name "*.db" -delete

rm -rf $DIR/etc
