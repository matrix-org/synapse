# This dockerfile builds on top of Dockerfile-worker and includes a built-in postgres instance.
# It is intended to be used for Complement testing

FROM matrixdotorg/synapse:workers

# Install postgres
RUN apt-get update
RUN apt-get install -y postgres

# Create required databases in postgres

# Create a user without a password
RUN sudo -u postgres createuser -w synapse_user

# Then set their password
RUN sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'somesecret';"

# Create the synapse database
RUN sudo -u postgres psql -c "CREATE DATABASE synapse \
 ENCODING 'UTF8' \
 LC_COLLATE='C' \
 LC_CTYPE='C' \
 template=template0 \
 OWNER synapse_user;"

# Modify Synapse's database config to point to the local postgres
COPY ./docker/synapse_use_local_postgres.py /synapse_use_local_postgres.py
RUN /synapse_use_local_postgres.py

VOLUME ["/data"]

EXPOSE 8008/tcp 8009/tcp 8448/tcp

# Start supervisord
CMD ["/usr/bin/supervisord"]