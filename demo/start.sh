#!/usr/bin/env bash

DIR="$( cd "$( dirname "$0" )" && pwd )"

CWD=$(pwd)

cd "$DIR/.." || exit

# Do not override PYTHONPATH if we are in a virtual env
if [ "$VIRTUAL_ENV" = "" ]; then
    PYTHONPATH=$(readlink -f "$(pwd)")
    export PYTHONPATH
	echo "$PYTHONPATH"
fi

# Create servers which listen on HTTP at 808x and HTTPS at 848x.
for port in 8080 8081 8082; do
    echo "Starting server on port $port... "

    https_port=$((port + 400))
    mkdir -p demo/$port
    pushd demo/$port || exit

    # Generate the configuration for the homeserver at localhost:848x, note that
    # the homeserver name needs to match the HTTPS listening port for federation
    # to properly work..
    python3 -m synapse.app.homeserver \
        --generate-config \
        --server-name "localhost:$https_port" \
        --config-path "$port.config" \
        --report-stats no

    if ! grep -F "Customisation made by demo/start.sh" -q "$port.config"; then
        # Generate TLS keys.
        openssl req -x509 -newkey rsa:4096 \
          -keyout "localhost:$port.tls.key" \
          -out "localhost:$port.tls.crt" \
          -days 365 -nodes -subj "/O=matrix"

        # Add customisations to the configuration.
        {
            printf '\n\n# Customisation made by demo/start.sh\n\n'
            echo "public_baseurl: http://localhost:$port/"
            echo 'enable_registration: true'
            echo 'enable_registration_without_verification: true'
            echo ''

			# Warning, this heredoc depends on the interaction of tabs and spaces.
			# Please don't accidentally bork me with your fancy settings.
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

            # Disable TLS for the servers
            printf '\n\n# Disable TLS for the servers.'
            echo '# DO NOT USE IN PRODUCTION'
            echo 'use_insecure_ssl_client_just_for_testing_do_not_use: true'
            echo 'federation_verify_certificates: false'

            # Set paths for the TLS certificates.
            echo "tls_certificate_path: \"$DIR/$port/localhost:$port.tls.crt\""
            echo "tls_private_key_path: \"$DIR/$port/localhost:$port.tls.key\""

            # Request keys directly from servers contacted over federation
            echo 'trusted_key_servers: []'

			# Allow the servers to communicate over localhost.
			allow_list=$(cat <<-ALLOW_LIST
			# Allow the servers to communicate over localhost.
			ip_range_whitelist:
			  - '127.0.0.1/8'
			  - '::1/128'
			ALLOW_LIST
			)

            echo "${allow_list}"
        } >> "$port.config"
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
            echo "${ratelimiting}" >> "$port.config"
        fi
    fi

    # Always disable reporting of stats if the option is not there.
    if ! grep -F "report_stats" -q  "$port.config" ; then
        echo "report_stats: false" >> "$port.config"
    fi

    # Run the homeserver in the background.
    python3 -m synapse.app.homeserver \
        --config-path "$port.config" \
        -D \

    popd || exit
done

cd "$CWD" || exit
