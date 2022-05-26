# This dockerfile builds on top of 'docker/Dockerfile-worker' in matrix-org/synapse
# by including a built-in postgres instance, as well as setting up the homeserver so
# that it is ready for testing via Complement.
#
# Instructions for building this image from those it depends on is detailed in this guide:
# https://github.com/matrix-org/synapse/blob/develop/docker/README-testing.md#testing-with-postgresql-and-single-or-multi-process-synapse
FROM matrixdotorg/synapse-workers

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
COPY conf/workers-shared.yaml /conf/workers/shared.yaml

WORKDIR /data

COPY conf/postgres.supervisord.conf /etc/supervisor/conf.d/postgres.conf

# Copy the entrypoint
COPY conf/start-complement-synapse-workers.sh /

# Expose nginx's listener ports
EXPOSE 8008 8448

ENTRYPOINT ["/start-complement-synapse-workers.sh"]

# Update the healthcheck to have a shorter check interval
HEALTHCHECK --start-period=5s --interval=1s --timeout=1s \
    CMD /bin/sh /healthcheck.sh

# TODO Ideally we should be able to pass env vars straight in via Complement
# but for now we burn them in to the image.
# See https://github.com/matrix-org/complement/issues/6.
ARG use_workers=true
ENV SYNAPSE_COMPLEMENT_USE_WORKERS $use_workers
ARG database=postgres
ENV SYNAPSE_COMPLEMENT_DATABASE $database
