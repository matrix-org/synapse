# This dockerfile builds on top of 'docker/Dockerfile-worker' in matrix-org/synapse
# by including a built-in postgres instance, as well as setting up the homeserver so
# that it is ready for testing via Complement.
#
# Instructions for building this image from those it depends on is detailed in this guide:
# https://github.com/matrix-org/synapse/blob/develop/docker/README-testing.md#testing-with-postgresql-and-single-or-multi-process-synapse
FROM matrixdotorg/synapse-workers

# Download a caddy server to stand in front of nginx and terminate TLS using Complement's
# custom CA.
# We include this near the top of the file in order to cache the result.
RUN curl -OL "https://github.com/caddyserver/caddy/releases/download/v2.3.0/caddy_2.3.0_linux_amd64.tar.gz" && \
  tar xzf caddy_2.3.0_linux_amd64.tar.gz && rm caddy_2.3.0_linux_amd64.tar.gz && mv caddy /root

# Install postgresql
RUN apt-get update
RUN apt-get install -y postgresql

# Configure a user and create a database for Synapse
RUN pg_ctlcluster 13 main start &&  su postgres -c "echo \
 \"ALTER USER postgres PASSWORD 'somesecret'; \
 CREATE DATABASE synapse \
  ENCODING 'UTF8' \
  LC_COLLATE='C' \
  LC_CTYPE='C' \
  template=template0;\" | psql" && pg_ctlcluster 13 main stop

# Modify the shared homeserver config with postgres support, certificate setup
# and the disabling of rate-limiting
COPY conf-workers/workers-shared.yaml /conf/workers/shared.yaml

WORKDIR /data

# Copy the caddy config
COPY conf-workers/caddy.complement.json /root/caddy.json

# Expose caddy's listener ports
EXPOSE 8008 8448

ENTRYPOINT \
  # Replace the server name in the caddy config
  sed -i "s/{{ server_name }}/${SERVER_NAME}/g" /root/caddy.json && \
  # Start postgres
  pg_ctlcluster 13 main start 2>&1 && \
  # Start caddy
  /root/caddy start --config /root/caddy.json 2>&1 && \
  # Set the server name of the homeserver
  SYNAPSE_SERVER_NAME=${SERVER_NAME} \
  # No need to report stats here
  SYNAPSE_REPORT_STATS=no \
  # Set postgres authentication details which will be placed in the homeserver config file
  POSTGRES_PASSWORD=somesecret POSTGRES_USER=postgres POSTGRES_HOST=localhost \
  # Specify the workers to test with
  SYNAPSE_WORKER_TYPES="\
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
    pusher" \
  # Run the script that writes the necessary config files and starts supervisord, which in turn
  # starts everything else
  /configure_workers_and_start.py

HEALTHCHECK --start-period=5s --interval=1s --timeout=1s \
    CMD /bin/sh /healthcheck.sh
