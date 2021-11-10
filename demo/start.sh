#!/usr/bin/env bash

DIR="$( cd "$( dirname "$0" )" && pwd )"

CWD=$(pwd)

cd "$DIR/.." || exit

mkdir -p demo/etc

PYTHONPATH=$(readlink -f "$(pwd)")
export PYTHONPATH


echo "$PYTHONPATH"

for port in 8080 8081 8082; do
    echo "Starting server on port $port... "

    https_port=$((port + 400))
    mkdir -p demo/$port
    pushd demo/$port || exit

    #rm $DIR/etc/$port.config
    python3 -m synapse.app.homeserver \
        --generate-config \
        -H "localhost:$https_port" \
        --config-path "$DIR/etc/$port.config" \
        --report-stats no

    if ! grep -F "Customisation made by demo/start.sh" -q "$DIR/etc/$port.config"; then
        # Generate tls keys
        openssl req -x509 -newkey rsa:4096 -keyout "$DIR/etc/localhost:$https_port.tls.key" -out "$DIR/etc/localhost:$https_port.tls.crt" -days 365 -nodes -subj "/O=matrix"

        # Regenerate configuration
        {
            printf '\n\n# Customisation made by demo/start.sh\n'
            echo "public_baseurl: http://localhost:$port/"
            echo 'enable_registration: true'

			# Warning, this heredoc depends on the interaction of tabs and spaces.
			# Please don't accidentaly bork me with your fancy settings.
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

            echo "${listeners}"

            # Disable tls for the servers
            printf '\n\n# Disable tls on the servers.'
            echo '# DO NOT USE IN PRODUCTION'
            echo 'use_insecure_ssl_client_just_for_testing_do_not_use: true'
            echo 'federation_verify_certificates: false'

            # Set tls paths
            echo "tls_certificate_path: \"$DIR/etc/localhost:$https_port.tls.crt\""
            echo "tls_private_key_path: \"$DIR/etc/localhost:$https_port.tls.key\""

            # Ignore keys from the trusted keys server
            echo '# Ignore keys from the trusted keys server'
            echo 'trusted_key_servers:'
            echo '  - server_name: "matrix.org"'
            echo '    accept_keys_insecurely: true'

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

            echo "${blacklist}"
        } >> "$DIR/etc/$port.config"
    fi

    # Check script parameters
    if [ $# -eq 1 ]; then
        if [ "$1" = "--no-rate-limit" ]; then

            # Disable any rate limiting
            ratelimiting=$(cat <<-RC
			rc_message:
			  per_second: 1000
			  burst_count: 1000
			rc_registration:
			  per_second: 1000
			  burst_count: 1000
			rc_login:
			  address:
			    per_second: 1000
			    burst_count: 1000
			  account:
			    per_second: 1000
			    burst_count: 1000
			  failed_attempts:
			    per_second: 1000
			    burst_count: 1000
			rc_admin_redaction:
			  per_second: 1000
			  burst_count: 1000
			rc_joins:
			  local:
			    per_second: 1000
			    burst_count: 1000
			  remote:
			    per_second: 1000
			    burst_count: 1000
			rc_3pid_validation:
			  per_second: 1000
			  burst_count: 1000
			rc_invites:
			  per_room:
			    per_second: 1000
			    burst_count: 1000
			  per_user:
			    per_second: 1000
			    burst_count: 1000
			RC
			)
            echo "${ratelimiting}" >> "$DIR/etc/$port.config"
        fi
    fi

    if ! grep -F "full_twisted_stacktraces" -q  "$DIR/etc/$port.config"; then
        echo "full_twisted_stacktraces: true" >> "$DIR/etc/$port.config"
    fi
    if ! grep -F "report_stats" -q  "$DIR/etc/$port.config" ; then
        echo "report_stats: false" >> "$DIR/etc/$port.config"
    fi

    python3 -m synapse.app.homeserver \
        --config-path "$DIR/etc/$port.config" \
        -D \

    popd || exit
done

cd "$CWD" || exit
