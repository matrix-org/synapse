#!/bin/bash
#
# Default ENTRYPOINT for the docker image used for testing synapse with workers under complement

set -e

function log {
    d=$(date +"%Y-%m-%d %H:%M:%S,%3N")
    echo "$d $@"
}

# Set the server name of the homeserver
export SYNAPSE_SERVER_NAME=${SERVER_NAME}

# No need to report stats here
export SYNAPSE_REPORT_STATS=no

# Set postgres authentication details which will be placed in the homeserver config file
export POSTGRES_PASSWORD=somesecret
export POSTGRES_USER=postgres
export POSTGRES_HOST=localhost

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
