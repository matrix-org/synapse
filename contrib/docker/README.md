# Synapse Docker

This Docker image will run Synapse as a single process. It does not provide any
database server or TURN server that you should run separately.

If you run a Postgres server, you should simply have it in the same Compose
project or set the proper environment variables and the image will automatically
use that server.

## Build

Build the docker image with the `docker build` command from the root of the synapse repository.

```
docker build -t matrixdotorg/synapse:v0.22.1 .
```

The `-t` option sets the image tag. Official images are tagged `matrixdotorg/synapse:<version>` where `<version>` is the same as the release tag in the synapse git repository.

You may have a local Python wheel cache available, in which case copy the relevant packages in the ``cache/`` directory at the root of the project.

## Run

It is recommended that you use Docker Compose to run your containers, including
this image and a Postgres server. A sample ``docker-compose.yml`` is provided,
with example labels for a reverse proxy and other artifacts.

Then, to run the server:

```
docker-compose up -d
```

In the case you specified a custom path for you configuration file and wish to
generate a fresh ``homeserver.yaml``, simply run:

```
docker-compose run synapse generate
```

If you do not wish to use Compose, you may still run this image using plain
Docker commands:

Note that the following is just a guideline and you may need to add parameters to the docker run command to account for the network situation with your postgres database.

```
docker run \
    -d \
    --name synapse \
    -v ${DATA_PATH}:/data \
    -e SYNAPSE_SERVER_NAME=my.matrix.host \
    matrixdotorg/synapse:v0.22.1
```


## Volumes

The image expects a single volue, located at ``/data``, that will hold:

* temporary files during uploads;
* uploaded media and thumbnais;
* the SQLite database if you do not configure postgres.

## Environment

If you do not specify a custom path for the configuration file, a very generic
file will be generated, based on the following environment settings.
These are a good starting point for setting up your own deployment.

Synapse specific settings:

* ``SYNAPSE_SERVER_NAME`` (mandatory), the current server public hostname.
* ``SYNAPSE_CONFIG_PATH``, path to a custom config file (will ignore all
  other options then).
* ``SYNAPSE_NO_TLS``, set this variable to disable TLS in Synapse (use this if
  you run your own TLS-capable reverse proxy).
* ``SYNAPSE_WEB_CLIENT``, set this variable to enable the embedded Web client.
* ``SYNAPSE_ENABLE_REGISTRATION``, set this variable to enable registration on
  the Synapse instance.
* ``SYNAPSE_ALLOW_GUEST``, set this variable to allow guest joining this server.
* ``SYNAPSE_EVENT_CACHE_SIZE``, the event cache size [default `10K`].
* ``SYNAPSE_REPORT_STATS``, set this variable to `yes` to enable anonymous
  statistics reporting back to the Matrix project which helps us to get funding.

Shared secrets, these will be initialized to random values if not set:

* ``SYNAPSE_REGISTRATION_SHARED_SECRET``, secret for registrering users if
  registration is disable.
* ``SYNAPSE_MACAROON_SECRET_KEY``, secret for Macaroon.

Database specific values (will use SQLite if not set):

* `POSTGRES_DATABASE` - The database name for the synapse postgres database. [default: `matrix`]
* `POSTGRES_HOST` - The host of the postgres database if you wish to use postgresql instead of sqlite3. [default: `db` which is useful when using a container on the same docker network in a compose file where the postgres service is called `db`]
* `POSTGRES_PASSWORD` - The password for the synapse postgres database. **If this is set then postgres will be used instead of sqlite3.** [default: none] **NOTE**: You are highly encouraged to use postgresql! Please use the compose file to make it easier to deploy.
* `POSTGRES_USER` - The user for the synapse postgres database. [default: `matrix`]
