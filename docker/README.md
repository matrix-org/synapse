# Synapse Docker

This Docker image will run Synapse as a single process. By default it uses a
sqlite database; for production use you should connect it to a separate
postgres database. The image also does *not* provide a TURN server.

This image should work on all platforms that are supported by Docker upstream.
Note that Docker's WS1-backend Linux Containers on Windows
platform is [experimental](https://github.com/docker/for-win/issues/6470) and
is not supported by this image.

## Volumes

By default, the image expects a single volume, located at `/data`, that will hold:

* configuration files;
* uploaded media and thumbnails;
* the SQLite database if you do not configure postgres;
* the appservices configuration.

You are free to use separate volumes depending on storage endpoints at your
disposal. For instance, `/data/media` could be stored on a large but low
performance hdd storage while other files could be stored on high performance
endpoints.

In order to setup an application service, simply create an `appservices`
directory in the data volume and write the application service Yaml
configuration file there. Multiple application services are supported.

## Generating a configuration file

The first step is to generate a valid config file. To do this, you can run the
image with the `generate` command line option.

You will need to specify values for the `SYNAPSE_SERVER_NAME` and
`SYNAPSE_REPORT_STATS` environment variable, and mount a docker volume to store
the configuration on. For example:

```
docker run -it --rm \
    --mount type=volume,src=synapse-data,dst=/data \
    -e SYNAPSE_SERVER_NAME=my.matrix.host \
    -e SYNAPSE_REPORT_STATS=yes \
    matrixdotorg/synapse:latest generate
```

For information on picking a suitable server name, see
https://github.com/matrix-org/synapse/blob/master/INSTALL.md.

The above command will generate a `homeserver.yaml` in (typically)
`/var/lib/docker/volumes/synapse-data/_data`. You should check this file, and
customise it to your needs.

The following environment variables are supported in `generate` mode:

* `SYNAPSE_SERVER_NAME` (mandatory): the server public hostname.
* `SYNAPSE_REPORT_STATS` (mandatory, `yes` or `no`): whether to enable
  anonymous statistics reporting.
* `SYNAPSE_HTTP_PORT`: the port Synapse should listen on for http traffic.
      Defaults to `8008`.
* `SYNAPSE_CONFIG_DIR`: where additional config files (such as the log config
  and event signing key) will be stored. Defaults to `/data`.
* `SYNAPSE_CONFIG_PATH`: path to the file to be generated. Defaults to
  `<SYNAPSE_CONFIG_DIR>/homeserver.yaml`.
* `SYNAPSE_DATA_DIR`: where the generated config will put persistent data
  such as the database and media store. Defaults to `/data`.
* `UID`, `GID`: the user id and group id to use for creating the data
  directories. Defaults to `991`, `991`.

## Running synapse

Once you have a valid configuration file, you can start synapse as follows:

```
docker run -d --name synapse \
    --mount type=volume,src=synapse-data,dst=/data \
    -p 8008:8008 \
    matrixdotorg/synapse:latest
```

(assuming 8008 is the port Synapse is configured to listen on for http traffic.)

You can then check that it has started correctly with:

```
docker logs synapse
```

If all is well, you should now be able to connect to http://localhost:8008 and
see a confirmation message.

The following environment variables are supported in `run` mode:

* `SYNAPSE_CONFIG_DIR`: where additional config files are stored. Defaults to
  `/data`.
* `SYNAPSE_CONFIG_PATH`: path to the config file. Defaults to
  `<SYNAPSE_CONFIG_DIR>/homeserver.yaml`.
* `SYNAPSE_WORKER`: module to execute, used when running synapse with workers.
   Defaults to `synapse.app.homeserver`, which is suitable for non-worker mode.
* `UID`, `GID`: the user and group id to run Synapse as. Defaults to `991`, `991`.
* `TZ`: the [timezone](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones) the container will run with. Defaults to `UTC`.

For more complex setups (e.g. for workers) you can also pass your args directly to synapse using `run` mode. For example like this:

```
docker run -d --name synapse \
    --mount type=volume,src=synapse-data,dst=/data \
    -p 8008:8008 \
    matrixdotorg/synapse:latest run \
    -m synapse.app.generic_worker \
    --config-path=/data/homeserver.yaml \
    --config-path=/data/generic_worker.yaml
```

If you do not provide `-m`, the value of the `SYNAPSE_WORKER` environment variable is used. If you do not provide at least one `--config-path` or `-c`, the value of the `SYNAPSE_CONFIG_PATH` environment variable is used instead.

## Generating an (admin) user

After synapse is running, you may wish to create a user via `register_new_matrix_user`.

This requires a `registration_shared_secret` to be set in your config file. Synapse
must be restarted to pick up this change.

You can then call the script:

```
docker exec -it synapse register_new_matrix_user http://localhost:8008 -c /data/homeserver.yaml --help
```

Remember to remove the `registration_shared_secret` and restart if you no-longer need it.

## TLS support

The default configuration exposes a single HTTP port: http://localhost:8008. It
is suitable for local testing, but for any practical use, you will either need
to use a reverse proxy, or configure Synapse to expose an HTTPS port.

For documentation on using a reverse proxy, see
https://github.com/matrix-org/synapse/blob/master/docs/reverse_proxy.md.

For more information on enabling TLS support in synapse itself, see
https://github.com/matrix-org/synapse/blob/master/INSTALL.md#tls-certificates. Of
course, you will need to expose the TLS port from the container with a `-p`
argument to `docker run`.

## Legacy dynamic configuration file support

The docker image used to support creating a dynamic configuration file based
on environment variables. This is no longer supported, and an error will be
raised if you try to run synapse without a config file.

It is, however, possible to generate a static configuration file based on
the environment variables that were previously used. To do this, run the docker
container once with the environment variables set, and `migrate_config`
command line option. For example:

```
docker run -it --rm \
    --mount type=volume,src=synapse-data,dst=/data \
    -e SYNAPSE_SERVER_NAME=my.matrix.host \
    -e SYNAPSE_REPORT_STATS=yes \
    matrixdotorg/synapse:latest migrate_config
```

This will generate the same configuration file as the legacy mode used, and
will store it in `/data/homeserver.yaml`. You can then use it as shown above at
[Running synapse](#running-synapse).

Note that the defaults used in this configuration file may be different to
those when generating a new config file with `generate`: for example, TLS is
enabled by default in this mode. You are encouraged to inspect the generated
configuration file and edit it to ensure it meets your needs.

## Building the image

If you need to build the image from a Synapse checkout, use the following `docker
 build` command from the repo's root:

```
docker build -t matrixdotorg/synapse -f docker/Dockerfile .
```

You can choose to build a different docker image by changing the value of the `-f` flag to
point to another Dockerfile.

## Disabling the healthcheck

If you are using a non-standard port or tls inside docker you can disable the healthcheck
whilst running the above `docker run` commands. 

```
   --no-healthcheck
```

## Disabling the healthcheck in docker-compose file

If you wish to disable the healthcheck via docker-compose, append the following to your service configuration.

```
  healthcheck:
    disable: true
```

## Setting custom healthcheck on docker run

If you wish to point the healthcheck at a different port with docker command, add the following

```
  --health-cmd 'curl -fSs http://localhost:1234/health'
```

## Setting the healthcheck in docker-compose file

You can add the following to set a custom healthcheck in a docker compose file.
You will need docker-compose version >2.1 for this to work. 

```
healthcheck:
  test: ["CMD", "curl", "-fSs", "http://localhost:8008/health"]
  interval: 15s
  timeout: 5s
  retries: 3
  start_period: 5s
```

## Using jemalloc

Jemalloc is embedded in the image and will be used instead of the default allocator.
You can read about jemalloc by reading the Synapse [README](../README.md).
