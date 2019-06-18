# Synapse Docker

This Docker image will run Synapse as a single process. By default it uses a
sqlite database; for production use you should connect it to a separate
postgres database.

The image also does *not* provide a TURN server.

## Run

### Using docker-compose (easier)

This image is designed to run either with an automatically generated
configuration file or with a custom configuration that requires manual editing.

An easy way to make use of this image is via docker-compose. See the
[contrib/docker](https://github.com/matrix-org/synapse/tree/master/contrib/docker) section of the synapse project for
examples.

### Without Compose (harder)

If you do not wish to use Compose, you may still run this image using plain
Docker commands. Note that the following is just a guideline and you may need
to add parameters to the docker run command to account for the network situation
with your postgres database.

```
docker run \
    -d \
    --name synapse \
    --mount type=volume,src=synapse-data,dst=/data \
    -e SYNAPSE_SERVER_NAME=my.matrix.host \
    -e SYNAPSE_REPORT_STATS=yes \
    -p 8448:8448 \
    matrixdotorg/synapse:latest
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

## TLS certificates

Synapse requires a valid TLS certificate. You can do one of the following:

 * Provide your own certificate and key (as
   `${DATA_PATH}/${SYNAPSE_SERVER_NAME}.tls.crt` and
   `${DATA_PATH}/${SYNAPSE_SERVER_NAME}.tls.key`, or elsewhere by providing an
   entire config as `${SYNAPSE_CONFIG_PATH}`). In this case, you should forward
   traffic to port 8448 in the container, for example with `-p 443:8448`.

 * Use a reverse proxy to terminate incoming TLS, and forward the plain http
   traffic to port 8008 in the container. In this case you should set `-e
   SYNAPSE_NO_TLS=1`.

 * Use the ACME (Let's Encrypt) support built into Synapse. This requires
   `${SYNAPSE_SERVER_NAME}` port 80 to be forwarded to port 8009 in the
   container, for example with `-p 80:8009`. To enable it in the docker
   container, set `-e SYNAPSE_ACME=1`.

If you don't do any of these, Synapse will fail to start with an error similar to:

    synapse.config._base.ConfigError: Error accessing file '/data/<server_name>.tls.crt' (config for tls_certificate): No such file or directory

## Environment

Unless you specify a custom path for the configuration file, a very generic
file will be generated, based on the following environment settings.
These are a good starting point for setting up your own deployment.

Global settings:

* ``UID``, the user id Synapse will run as [default 991]
* ``GID``, the group id Synapse will run as [default 991]
* ``SYNAPSE_CONFIG_PATH``, path to a custom config file

If ``SYNAPSE_CONFIG_PATH`` is set, you should generate a configuration file
then customize it manually: see [Generating a config
file](#generating-a-config-file).

Otherwise, a dynamic configuration file will be used.

### Environment variables used to build a dynamic configuration file

The following environment variables are used to build the configuration file
when ``SYNAPSE_CONFIG_PATH`` is not set.

* ``SYNAPSE_SERVER_NAME`` (mandatory), the server public hostname.
* ``SYNAPSE_REPORT_STATS``, (mandatory, ``yes`` or ``no``), enable anonymous
  statistics reporting back to the Matrix project which helps us to get funding.
* `SYNAPSE_NO_TLS`, (accepts `true`, `false`, `on`, `off`, `1`, `0`, `yes`, `no`]): disable
  TLS in Synapse (use this if you run your own TLS-capable reverse proxy). Defaults
  to `false` (ie, TLS is enabled by default).
* ``SYNAPSE_ENABLE_REGISTRATION``, set this variable to enable registration on
  the Synapse instance.
* ``SYNAPSE_ALLOW_GUEST``, set this variable to allow guest joining this server.
* ``SYNAPSE_EVENT_CACHE_SIZE``, the event cache size [default `10K`].
* ``SYNAPSE_RECAPTCHA_PUBLIC_KEY``, set this variable to the recaptcha public
  key in order to enable recaptcha upon registration.
* ``SYNAPSE_RECAPTCHA_PRIVATE_KEY``, set this variable to the recaptcha private
  key in order to enable recaptcha upon registration.
* ``SYNAPSE_TURN_URIS``, set this variable to the coma-separated list of TURN
  uris to enable TURN for this homeserver.
* ``SYNAPSE_TURN_SECRET``, set this to the TURN shared secret if required.
* ``SYNAPSE_MAX_UPLOAD_SIZE``, set this variable to change the max upload size
  [default `10M`].
* ``SYNAPSE_ACME``: set this to enable the ACME certificate renewal support.

Shared secrets, that will be initialized to random values if not set:

* ``SYNAPSE_REGISTRATION_SHARED_SECRET``, secret for registrering users if
  registration is disable.
* ``SYNAPSE_MACAROON_SECRET_KEY`` secret for signing access tokens
  to the server.

Database specific values (will use SQLite if not set):

* `POSTGRES_DB` - The database name for the synapse postgres
  database. [default: `synapse`]
* `POSTGRES_HOST` - The host of the postgres database if you wish to use
  postgresql instead of sqlite3. [default: `db` which is useful when using a
  container on the same docker network in a compose file where the postgres
  service is called `db`]
* `POSTGRES_PASSWORD` - The password for the synapse postgres database. **If
  this is set then postgres will be used instead of sqlite3.** [default: none]
  **NOTE**: You are highly encouraged to use postgresql! Please use the compose
  file to make it easier to deploy.
* `POSTGRES_USER` - The user for the synapse postgres database. [default:
  `synapse`]

Mail server specific values (will not send emails if not set):

* ``SYNAPSE_SMTP_HOST``, hostname to the mail server.
* ``SYNAPSE_SMTP_PORT``, TCP port for accessing the mail server [default
  ``25``].
* ``SYNAPSE_SMTP_USER``, username for authenticating against the mail server if
  any.
* ``SYNAPSE_SMTP_PASSWORD``, password for authenticating against the mail
  server if any.

### Generating a config file

It is possible to generate a basic configuration file for use with
`SYNAPSE_CONFIG_PATH` using the `generate` commandline option. You will need to
specify values for `SYNAPSE_CONFIG_PATH`, `SYNAPSE_SERVER_NAME` and
`SYNAPSE_REPORT_STATS`, and mount a docker volume to store the data on. For
example:

```
docker run -it --rm \
    --mount type=volume,src=synapse-data,dst=/data \
    -e SYNAPSE_CONFIG_PATH=/data/homeserver.yaml \
    -e SYNAPSE_SERVER_NAME=my.matrix.host \
    -e SYNAPSE_REPORT_STATS=yes \
    matrixdotorg/synapse:latest generate
```

This will generate a `homeserver.yaml` in (typically)
`/var/lib/docker/volumes/synapse-data/_data`, which you can then customise and
use with:

```
docker run -d --name synapse \
    --mount type=volume,src=synapse-data,dst=/data \
    -e SYNAPSE_CONFIG_PATH=/data/homeserver.yaml \
    matrixdotorg/synapse:latest
```
