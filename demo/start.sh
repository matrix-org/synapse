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
    python3 -m synapse.app.homeserver \
        --generate-config \
        -H "localhost:$https_port" \
        --config-path "$DIR/etc/$port.config" \
        --report-stats no

    if ! grep -F "Customisation made by demo/start.sh" -q  $DIR/etc/$port.config; then
        printf '\n\n# Customisation made by demo/start.sh\n' >> $DIR/etc/$port.config

        echo 'enable_registration: true' >> $DIR/etc/$port.config

        # Warning, this heredoc depends on the interaction of tabs and spaces. Please don't
        # accidentaly bork me with your fancy settings.
		listeners=$(cat <<-PORTLISTENERS
		# Configure server to listen on both $https_port and $port
		# This overides some of the default settings above
		listeners:
		  - port: $https_port
		    type: http
		    tls: true
		    resources:
		      - names: [client, federation]

		  - port: $port
		    tls: false
		    bind_addresses: ['::1', '127.0.0.1']
		    type: http
		    x_forwarded: true
		    resources:
		      - names: [client, federation]
		        compress: false
		PORTLISTENERS
		)
        echo "${listeners}" >> $DIR/etc/$port.config

        # Disable tls for the servers
        printf '\n\n# Disable tls on the servers.' >> $DIR/etc/$port.config
        echo '# DO NOT USE IN PRODUCTION' >> $DIR/etc/$port.config
        echo 'use_insecure_ssl_client_just_for_testing_do_not_use: true' >> $DIR/etc/$port.config
        echo 'federation_verify_certificates: false' >> $DIR/etc/$port.config

        # Set tls paths
        echo "tls_certificate_path: \"$DIR/etc/localhost:$https_port.tls.crt\"" >> $DIR/etc/$port.config
        echo "tls_private_key_path: \"$DIR/etc/localhost:$https_port.tls.key\"" >> $DIR/etc/$port.config

        # Generate tls keys
        openssl req -x509 -newkey rsa:4096 -keyout $DIR/etc/localhost\:$https_port.tls.key -out $DIR/etc/localhost\:$https_port.tls.crt -days 365 -nodes -subj "/O=matrix"

        # Ignore keys from the trusted keys server
        echo '# Ignore keys from the trusted keys server' >> $DIR/etc/$port.config
        echo 'trusted_key_servers:' >> $DIR/etc/$port.config
        echo '  - server_name: "matrix.org"' >> $DIR/etc/$port.config
        echo '    accept_keys_insecurely: true' >> $DIR/etc/$port.config

        # Reduce the blacklist
        blacklist=$(cat <<-BLACK
		# Set the blacklist so that it doesn't include 127.0.0.1, ::1
		federation_ip_range_blacklist:
		  - '10.0.0.0/8'
		  - '172.16.0.0/12'
		  - '192.168.0.0/16'
		  - '100.64.0.0/10'
		  - '169.254.0.0/16'
		  - 'fe80::/64'
		  - 'fc00::/7'
		BLACK
		)
        echo "${blacklist}" >> $DIR/etc/$port.config
    fi

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

    python3 -m synapse.app.homeserver \
        --config-path "$DIR/etc/$port.config" \
        -D \

    popd
done

cd "$CWD"
