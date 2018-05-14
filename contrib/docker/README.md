# Synapse Docker

This Docker image will run Synapse as a single process. It does not provide any
database server or TURN server that you should run separately.

If you run a Postgres server, you should simply have it in the same Compose
project or set the proper environment variables and the image will automatically
use that server.

## Build

Build the docker image with the `docker build` command from the root of the synapse repository.

```
docker build -t docker.io/matrixdotorg/synapse .
```

The `-t` option sets the image tag. Official images are tagged `matrixdotorg/synapse:<version>` where `<version>` is the same as the release tag in the synapse git repository.

You may have a local Python wheel cache available, in which case copy the relevant packages in the ``cache/`` directory at the root of the project.

## Run

This image is designed to run either with an automatically generated configuration
file or with a custom configuration that requires manual edition.

### Automated configuration

It is recommended that you use Docker Compose to run your containers, including
this image and a Postgres server. A sample ``docker-compose.yml`` is provided,
including example labels for reverse proxying and other artifacts.

Read the section about environment variables and set at least mandatory variables,
then run the server:

```
docker-compose up -d
```

### Manual configuration

A sample ``docker-compose.yml`` is provided, including example labels for
reverse proxying and other artifacts.

Specify a ``SYNAPSE_CONFIG_PATH``, preferably to a persistent path,
to use manual configuration. To generate a fresh ``homeserver.yaml``, simply run:

```
docker-compose run --rm -e SYNAPSE_SERVER_NAME=my.matrix.host synapse generate
```

Then, customize your configuration and run the server:

```
docker-compose up -d
```

### Without Compose

If you do not wish to use Compose, you may still run this image using plain
Docker commands. Note that the following is just a guideline and you may need
to add parameters to the docker run command to account for the network situation
with your postgres database.

```
docker run \
    -d \
    --name synapse \
    -v ${DATA_PATH}:/data \
    -e SYNAPSE_SERVER_NAME=my.matrix.host \
    -e SYNAPSE_REPORT_STATS=yes \
    docker.io/matrixdotorg/synapse:latest
```

## Volumes

The image expects a single volume, located at ``/data``, that will hold:

* temporary files during uploads;
* uploaded media and thumbnails;
* the SQLite database if you do not configure postgres;
* the appservices configuration.

You are free to use separate volumes depending on storage endpoints at your
disposal. For instance, ``/data/media`` coud be stored on a large but low
performance hdd storage while other files could be stored on high performance
endpoints.

In order to setup an application service, simply create an ``appservices``
directory in the data volume and write the application service Yaml
configuration file there. Multiple application services are supported.

## Environment

Unless you specify a custom path for the configuration file, a very generic
file will be generated, based on the following environment settings.
These are a good starting point for setting up your own deployment.

Global settings:

* ``UID``, the user id Synapse will run as [default 991]
* ``GID``, the group id Synapse will run as [default 991]
* ``SYNAPSE_CONFIG_PATH``, path to a custom config file

If ``SYNAPSE_CONFIG_PATH`` is set, you should generate a configuration file
then customize it manually. No other environment variable is required.

Otherwise, a dynamic configuration file will be used. The following environment
variables are available for configuration:

* ``SYNAPSE_SERVER_NAME`` (mandatory), the current server public hostname.
* ``SYNAPSE_REPORT_STATS``, (mandatory, ``yes`` or ``no``), enable anonymous
  statistics reporting back to the Matrix project which helps us to get funding.
* ``SYNAPSE_MACAROON_SECRET_KEY`` (mandatory) secret for signing access tokens
  to the server, set this to a proper random key.
* ``SYNAPSE_NO_TLS``, set this variable to disable TLS in Synapse (use this if
  you run your own TLS-capable reverse proxy).
* ``SYNAPSE_ENABLE_REGISTRATION``, set this variable to enable registration on
  the Synapse instance.
* ``SYNAPSE_ALLOW_GUEST``, set this variable to allow guest joining this server.
* ``SYNAPSE_EVENT_CACHE_SIZE``, the event cache size [default `10K`].
* ``SYNAPSE_CACHE_FACTOR``, the cache factor [default `0.5`].
* ``SYNAPSE_RECAPTCHA_PUBLIC_KEY``, set this variable to the recaptcha public
  key in order to enable recaptcha upon registration.
* ``SYNAPSE_RECAPTCHA_PRIVATE_KEY``, set this variable to the recaptcha private
  key in order to enable recaptcha upon registration.
* ``SYNAPSE_TURN_URIS``, set this variable to the coma-separated list of TURN
  uris to enable TURN for this homeserver.
* ``SYNAPSE_TURN_SECRET``, set this to the TURN shared secret if required.

Shared secrets, that will be initialized to random values if not set:

* ``SYNAPSE_REGISTRATION_SHARED_SECRET``, secret for registrering users if
  registration is disable.

Database specific values (will use SQLite if not set):

* `POSTGRES_DB` - The database name for the synapse postgres database. [default: `synapse`]
* `POSTGRES_HOST` - The host of the postgres database if you wish to use postgresql instead of sqlite3. [default: `db` which is useful when using a container on the same docker network in a compose file where the postgres service is called `db`]
* `POSTGRES_PASSWORD` - The password for the synapse postgres database. **If this is set then postgres will be used instead of sqlite3.** [default: none] **NOTE**: You are highly encouraged to use postgresql! Please use the compose file to make it easier to deploy.
* `POSTGRES_USER` - The user for the synapse postgres database. [default: `matrix`]

Mail server specific values (will not send emails if not set):

* ``SYNAPSE_SMTP_HOST``, hostname to the mail server.
* ``SYNAPSE_SMTP_PORT``, TCP port for accessing the mail server [default ``25``].
* ``SYNAPSE_SMTP_USER``, username for authenticating against the mail server if any.
* ``SYNAPSE_SMTP_PASSWORD``, password for authenticating against the mail server if any.
