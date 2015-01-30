#!/bin/bash

DIR="$( cd "$( dirname "$0" )" && pwd )"

CWD=$(pwd)

cd "$DIR/.."

mkdir -p demo/etc

# Check the --no-rate-limit param
PARAMS=""
if [ $# -eq 1 ]; then
    if [ $1 = "--no-rate-limit" ]; then
	    PARAMS="--rc-messages-per-second 1000 --rc-message-burst-count 1000"
    fi
fi

for port in 8080 8081 8082; do
    echo "Starting server on port $port... "

    https_port=$((port + 400))

    python -m synapse.app.homeserver \
        --generate-config \
        --config-path "demo/etc/$port.config" \
        -p "$https_port" \
        --unsecure-port "$port" \
        -H "localhost:$https_port" \
        -f "$DIR/$port.log" \
        -d "$DIR/$port.db" \
        -D --pid-file "$DIR/$port.pid" \
        --manhole $((port + 1000)) \
        --tls-dh-params-path "demo/demo.tls.dh" \
        --media-store-path "demo/media_store.$port" \
		$PARAMS $SYNAPSE_PARAMS \

    python -m synapse.app.homeserver \
        --config-path "demo/etc/$port.config" \
        -vv \

done

cd "$CWD"
