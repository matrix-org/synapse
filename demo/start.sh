#!/bin/bash

DIR="$( cd "$( dirname "$0" )" && pwd )"

CWD=$(pwd)

cd "$DIR/.."

for port in "8080" "8081" "8082"; do
    echo "Starting server on port $port... "

    python -m synapse.app.homeserver \
        -p "$port" \
        -H "localhost:$port" \
        -f "$DIR/$port.log" \
        -d "$DIR/$port.db" \
        -vv \
        -D --pid-file "$DIR/$port.pid"
done

echo "Starting webclient on port 8000..."
python "demo/webserver.py" -p 8000 -P "$DIR/webserver.pid" "webclient"

cd "$CWD"
