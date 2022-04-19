#!/bin/bash
#
# Default ENTRYPOINT for the docker image used for testing synapse with workers under complement

set -e

function log {
    d=$(date +"%Y-%m-%d %H:%M:%S,%3N")
    echo "$d $@"
}

# Replace the server name in the caddy config
sed -i "s/{{ server_name }}/${SERVER_NAME}/g" /root/caddy.json

log "starting postgres"
pg_ctlcluster 13 main start

log "starting caddy"
/root/caddy start --config /root/caddy.json

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

# Run the script that writes the necessary config files and starts supervisord, which in turn
# starts everything else
exec /configure_workers_and_start.py
