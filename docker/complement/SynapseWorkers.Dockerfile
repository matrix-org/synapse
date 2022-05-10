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
RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y postgresql-13

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

# Copy the entrypoint
COPY conf-workers/start-complement-synapse-workers.sh /

# Expose caddy's listener ports
EXPOSE 8008 8448

ENTRYPOINT /start-complement-synapse-workers.sh

# Update the healthcheck to have a shorter check interval
HEALTHCHECK --start-period=5s --interval=1s --timeout=1s \
    CMD /bin/sh /healthcheck.sh
