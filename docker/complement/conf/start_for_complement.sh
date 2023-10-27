#!/bin/bash
#
# Default ENTRYPOINT for the docker image used for testing synapse with workers under complement

set -e

echo "Complement Synapse launcher"
echo "  Args: $@"
echo "  Env: SYNAPSE_COMPLEMENT_DATABASE=$SYNAPSE_COMPLEMENT_DATABASE SYNAPSE_COMPLEMENT_USE_WORKERS=$SYNAPSE_COMPLEMENT_USE_WORKERS SYNAPSE_COMPLEMENT_USE_ASYNCIO_REACTOR=$SYNAPSE_COMPLEMENT_USE_ASYNCIO_REACTOR"

function log {
    d=$(date +"%Y-%m-%d %H:%M:%S,%3N")
    echo "$d $@"
}

# Set the server name of the homeserver
export SYNAPSE_SERVER_NAME=${SERVER_NAME}

# No need to report stats here
export SYNAPSE_REPORT_STATS=no


case "$SYNAPSE_COMPLEMENT_DATABASE" in
  postgres)
    # Set postgres authentication details which will be placed in the homeserver config file
    export POSTGRES_PASSWORD=somesecret
    export POSTGRES_USER=postgres
    export POSTGRES_HOST=localhost

    # configure supervisord to start postgres
    export START_POSTGRES=true
    ;;

  sqlite|"")
    # Configure supervisord not to start Postgres, as we don't need it
    export START_POSTGRES=false
    ;;

  *)
    echo "Unknown Synapse database: SYNAPSE_COMPLEMENT_DATABASE=$SYNAPSE_COMPLEMENT_DATABASE" >&2
    exit 1
    ;;
esac


if [[ -n "$SYNAPSE_COMPLEMENT_USE_WORKERS" ]]; then
  # Specify the workers to test with
  # Allow overriding by explicitly setting SYNAPSE_WORKER_TYPES outside, while still
  # utilizing WORKERS=1 for backwards compatibility.
  # -n True if the length of string is non-zero.
  # -z True if the length of string is zero.
  if [[ -z "$SYNAPSE_WORKER_TYPES" ]]; then
    export SYNAPSE_WORKER_TYPES="\
      event_persister:2, \
      background_worker, \
      frontend_proxy, \
      event_creator, \
      user_dir, \
      media_repository, \
      federation_inbound, \
      federation_reader, \
      federation_sender, \
      synchrotron, \
      client_reader, \
      appservice, \
      pusher, \
      stream_writers=account_data+presence+receipts+to_device+typing"

  fi
  log "Workers requested: $SYNAPSE_WORKER_TYPES"
  # adjust connection pool limits on worker mode as otherwise running lots of worker synapses
  # can make docker unhappy (in GHA)
  export POSTGRES_CP_MIN=1
  export POSTGRES_CP_MAX=3
  echo "using reduced connection pool limits for worker mode"
  # Improve startup times by using a launcher based on fork()
  export SYNAPSE_USE_EXPERIMENTAL_FORKING_LAUNCHER=1
else
  # Empty string here means 'main process only'
  export SYNAPSE_WORKER_TYPES=""
fi


if [[ -n "$SYNAPSE_COMPLEMENT_USE_ASYNCIO_REACTOR" ]]; then
  if [[ -n "$SYNAPSE_USE_EXPERIMENTAL_FORKING_LAUNCHER" ]]; then
    export SYNAPSE_COMPLEMENT_FORKING_LAUNCHER_ASYNC_IO_REACTOR="1"
  else
    export SYNAPSE_ASYNC_IO_REACTOR="1"
  fi
else
  export SYNAPSE_ASYNC_IO_REACTOR="0"
fi


# Add Complement's appservice registration directory, if there is one
# (It can be absent when there are no application services in this test!)
if [ -d /complement/appservice ]; then
    export SYNAPSE_AS_REGISTRATION_DIR=/complement/appservice
fi

# Generate a TLS key, then generate a certificate by having Complement's CA sign it
# Note that both the key and certificate are in PEM format (not DER).

# First generate a configuration file to set up a Subject Alternative Name.
cat > /conf/server.tls.conf <<EOF
.include /etc/ssl/openssl.cnf

[SAN]
subjectAltName=DNS:${SERVER_NAME}
EOF

# Generate an RSA key
openssl genrsa -out /conf/server.tls.key 2048

# Generate a certificate signing request
openssl req -new -config /conf/server.tls.conf -key /conf/server.tls.key -out /conf/server.tls.csr \
  -subj "/CN=${SERVER_NAME}" -reqexts SAN

# Make the Complement Certificate Authority sign and generate a certificate.
openssl x509 -req -in /conf/server.tls.csr \
  -CA /complement/ca/ca.crt -CAkey /complement/ca/ca.key -set_serial 1 \
  -out /conf/server.tls.crt -extfile /conf/server.tls.conf -extensions SAN

# Assert that we have a Subject Alternative Name in the certificate.
# (grep will exit with 1 here if there isn't a SAN in the certificate.)
openssl x509 -in /conf/server.tls.crt -noout -text | grep DNS:

export SYNAPSE_TLS_CERT=/conf/server.tls.crt
export SYNAPSE_TLS_KEY=/conf/server.tls.key

# Run the script that writes the necessary config files and starts supervisord, which in turn
# starts everything else
exec /configure_workers_and_start.py
