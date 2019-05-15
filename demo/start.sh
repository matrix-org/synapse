#!/bin/bash

DIR="$( cd "$( dirname "$0" )" && pwd )"

CWD=$(pwd)

cd "$DIR/.."

mkdir -p demo/etc

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
        -H "localhost:$https_port" \
        --config-path "$DIR/etc/$port.config" \
        --report-stats no

    printf '\n\n# Customisation made by demo/start.sh\n' >> $DIR/etc/$port.config
    echo 'enable_registration: true' >> $DIR/etc/$port.config

    # Check script parameters
    if [ $# -eq 1 ]; then
        if [ $1 = "--no-rate-limit" ]; then
            # messages rate limit
            echo 'rc_messages_per_second: 1000' >> $DIR/etc/$port.config
            echo 'rc_message_burst_count: 1000' >> $DIR/etc/$port.config

            # registration rate limit
            printf 'rc_registration:\n  per_second: 1000\n  burst_count: 1000\n' >> $DIR/etc/$port.config

            # login rate limit
            echo 'rc_login:' >> $DIR/etc/$port.config
            printf '  address:\n    per_second: 1000\n    burst_count: 1000\n' >> $DIR/etc/$port.config
            printf '  account:\n    per_second: 1000\n    burst_count: 1000\n' >> $DIR/etc/$port.config
            printf '  failed_attempts:\n    per_second: 1000\n    burst_count: 1000\n' >> $DIR/etc/$port.config
        fi
    fi

    if ! grep -F "full_twisted_stacktraces" -q  $DIR/etc/$port.config; then
        echo "full_twisted_stacktraces: true" >> $DIR/etc/$port.config
    fi
    if ! grep -F "report_stats" -q  $DIR/etc/$port.config ; then
        echo "report_stats: false" >> $DIR/etc/$port.config
    fi

    python -m synapse.app.homeserver \
        --config-path "$DIR/etc/$port.config" \
        -D \
        -vv \

    popd
done

cd "$CWD"
