#!/usr/bin/env bash

DIR="$( cd "$( dirname "$0" )" && pwd )"

FILES=$(find "$DIR" -name "*.pid" -type f);

for pid_file in $FILES; do
    pid=$(cat "$pid_file")
    if [[ $pid ]]; then
        echo "Killing $pid_file with $pid"
        kill "$pid"
    fi
done

