# This dockerfile builds on top of 'docker/Dockerfile-workers' in matrix-org/synapse
# by including a built-in postgres instance, as well as setting up the homeserver so
# that it is ready for testing via Complement.
#
# Instructions for building this image from those it depends on is detailed in this guide:
# https://github.com/matrix-org/synapse/blob/develop/docker/README-testing.md#testing-with-postgresql-and-single-or-multi-process-synapse
ARG SYNAPSE_VERSION=latest
FROM matrixdotorg/synapse-workers:$SYNAPSE_VERSION

# Install postgresql
RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -yqq postgresql-13

# Configure a user and create a database for Synapse
RUN pg_ctlcluster 13 main start &&  su postgres -c "echo \
 \"ALTER USER postgres PASSWORD 'somesecret'; \
 CREATE DATABASE synapse \
  ENCODING 'UTF8' \
  LC_COLLATE='C' \
  LC_CTYPE='C' \
  template=template0;\" | psql" && pg_ctlcluster 13 main stop

# Extend the shared homeserver config to disable rate-limiting,
# set Complement's static shared secret, enable registration, amongst other
# tweaks to get Synapse ready for testing.
# To do this, we copy the old template out of the way and then include it
# with Jinja2.
RUN mv /conf/shared.yaml.j2 /conf/shared-orig.yaml.j2
COPY conf/workers-shared-extra.yaml.j2 /conf/shared.yaml.j2

WORKDIR /data

COPY conf/postgres.supervisord.conf /etc/supervisor/conf.d/postgres.conf

# Copy the entrypoint
COPY conf/start_for_complement.sh /

# Expose nginx's listener ports
EXPOSE 8008 8448

ENTRYPOINT ["/start_for_complement.sh"]

# Update the healthcheck to have a shorter check interval
HEALTHCHECK --start-period=5s --interval=1s --timeout=1s \
    CMD /bin/sh /healthcheck.sh
