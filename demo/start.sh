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

export PYTHONPATH=$(readlink -f $(pwd))


echo $PYTHONPATH

for port in 8080 8081 8082; do
    echo "Starting server on port $port... "

    https_port=$((port + 400))
    mkdir -p demo/$port
    pushd demo/$port

    #rm $DIR/etc/$port.config
    python -m synapse.app.homeserver \
        --generate-config \
        --enable_registration \
        -H "localhost:$https_port" \
        --config-path "$DIR/etc/$port.config" \

    python -m synapse.app.homeserver \
        --config-path "$DIR/etc/$port.config" \
        -D \
        -vv \

    popd
done

cd "$CWD"
