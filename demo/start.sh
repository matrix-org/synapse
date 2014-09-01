#!/bin/bash

DIR="$( cd "$( dirname "$0" )" && pwd )"

CWD=$(pwd)

cd "$DIR/.."

mkdir -p demo/etc

for port in 8080 8081 8082; do
    echo "Starting server on port $port... "

    python -m synapse.app.homeserver \
        --generate-config \
        --config-path "demo/etc/$port.config" \
        -H "localhost:$port" \
        -p "$port" \
        -H "localhost:$port" \
        -f "$DIR/$port.log" \
        -d "$DIR/$port.db" \
        -D --pid-file "$DIR/$port.pid" \
        --manhole $((port + 1000)) \
        --tls-dh-params-path "demo/demo.tls.dh"

    python -m synapse.app.homeserver \
        --config-path "demo/etc/$port.config" \
        -vv \

done

echo "Starting webclient on port 8000..."
python "demo/webserver.py" -p 8000 -P "$DIR/webserver.pid" "webclient"

cd "$CWD"
