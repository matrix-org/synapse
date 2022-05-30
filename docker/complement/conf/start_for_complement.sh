#!/bin/bash
#
# Default ENTRYPOINT for the docker image used for testing synapse with workers under complement

set -e

echo "Complement Synapse launcher"
echo "  Args: $@"
echo "  Env: SYNAPSE_COMPLEMENT_DATABASE=$SYNAPSE_COMPLEMENT_DATABASE SYNAPSE_COMPLEMENT_USE_WORKERS=$SYNAPSE_COMPLEMENT_USE_WORKERS"

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
    export START_POSTGRES=true
    ;;

  sqlite)
    # Prevent Postgres from starting up as we don't need it to
    export START_POSTGRES=false
    ;;

  *)
    echo "Unknown Synapse database: SYNAPSE_COMPLEMENT_DATABASE=$SYNAPSE_COMPLEMENT_DATABASE"
    exit 1
    ;;
esac


if [[ -n "$SYNAPSE_COMPLEMENT_USE_WORKERS" ]]; then
  # Specify the workers to test with
  export SYNAPSE_WORKER_TYPES="\
      event_persister, \
      event_persister, \
      background_worker, \
      frontend_proxy, \
      event_creator, \
      user_dir, \
      media_repository, \
      federation_inbound, \
      federation_reader, \
      federation_sender, \
      synchrotron, \
      appservice, \
      pusher"

  export START_REDIS=true
else
  # Empty string here means 'main process only'
  export SYNAPSE_WORKER_TYPES=""
  # No sense starting Redis as we won't need it or use it
  export START_REDIS=false
fi


# Add Complement's appservice registration directory, if there is one
# (It can be absent when there are no application services in this test!)
if [ -d /complement/appservice ]; then
    export SYNAPSE_AS_REGISTRATION_DIR=/complement/appservice
fi

# Generate a TLS key, then generate a certificate by having Complement's CA sign it
# Note that both the key and certificate are in PEM format (not DER).
openssl genrsa -out /conf/server.tls.key 2048

openssl req -new -key /conf/server.tls.key -out /conf/server.tls.csr \
  -subj "/CN=${SERVER_NAME}"

openssl x509 -req -in /conf/server.tls.csr \
  -CA /complement/ca/ca.crt -CAkey /complement/ca/ca.key -set_serial 1 \
  -out /conf/server.tls.crt

export SYNAPSE_TLS_CERT=/conf/server.tls.crt
export SYNAPSE_TLS_KEY=/conf/server.tls.key

# Run the script that writes the necessary config files and starts supervisord, which in turn
# starts everything else
exec /configure_workers_and_start.py
