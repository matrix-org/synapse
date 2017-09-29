# Synapse Docker

## Build

Build the docker image with the `docker build` command from the root of the synapse repository.

```
docker build -t matrixdotorg/synapse:v0.22.1 .
```

The `-t` option sets the image tag. Official images are tagged `matrixdotorg/synapse:<version>` where `<version>` is the same as the release tag in the synapse git repository.

## Configure

Synapse provides a command for generating homeserver configuration files. These are a good starting point for setting up your own deployment.

The documentation below will refer to a `CONFIG_PATH` shell variable. This is a path to a directory where synapse configuration will be stored. It needs to be mapped into the container as a volume at `/synapse/config/` as can be seen in the example `docker run` command.

Docker container environment variables:
* `GENERATE_CONFIG` - Set this to any non-empty string, such as `yes`, to trigger generation of configuration files. Existing files in the `CONFIG_PATH` will **not** be overwritten.
* `POSTGRES_DATABASE` - The database name for the synapse postgres database. [default: `synapse`]
* `POSTGRES_HOST` - The host of the postgres database if you wish to use postgresql instead of sqlite3. [default: `postgres` which is useful when using a container on the same docker network in a compose file where the postgres service is called `postgres`] **NOTE**: `localhost` and `127.0.0.1` refer to the container itself unless running the container with `host` networking.
* `POSTGRES_PASSWORD` - The password for the synapse postgres database. **If this is set then postgres will be used instead of sqlite3.** [default: none] **NOTE**: You are highly encouraged to use postgresql! Please use the compose file to make it easier to deploy.
* `POSTGRES_USER` - The user for the synapse postgres database. [default: `postgres`]
* `REPORT_STATS` - Whether to send anonymous usage statistics back to the Matrix project which helps us to get funding! Must be `yes` or `no`. [default: `yes`]
* `SERVER_NAME` - The domain used for the Matrix homeserver. If you intend to run this synapse instance on a public domain, use that domain. [default: `localhost`]

```
CONFIG_PATH=/my/magical/config/path/
mkdir -p ${CONFIG_PATH}
docker run \
    --rm \
    -e GENERATE_CONFIG=yes \
    -e POSTGRES_PASSWORD=MyVerySecretPassword \
    -e REPORT_STATS=yes \
    -e SERVER_NAME=example.com \
    -v ${CONFIG_PATH}:/synapse/config/ \
    matrixdotorg/synapse:v0.22.1
```

This will create a temporary container from the image and use the synapse code for generating configuration files and TLS keys and certificates for the specified `SERVER_NAME` domain. The files are written to `CONFIG_PATH`.

## Run

**NOTE**: If you are not using postgresql and are using sqlite3 as your database, you will need to make a directory to store the sqlite3 database file in and then mount this volume into the container at `/synapse/data/`. As it is so easy to use postgresql, when using Docker containers, this is not documented to somewhat discourage it. Choose a `POSTGRES_PASSWORD` instead.

### Docker Compose

A `docker-compose.yaml` file is included to ease deployment of the basic synapse and postgres setup. Remember to set a `POSTGRES_PASSWORD` when generating your configuration above. You will need it for running the containers in the composition.

From the `docker/` subdirectory of the synapse repository:
```
CONFIG_PATH=/my/magical/config/path/
POSTGRES_PASSWORD=MyVerySecretPassword \
docker-compose \
    -p synapse \
    up -d
```

### Docker

Note that the following is just a guideline and you may need to add parameters to the docker run command to account for the network situation with your postgres database.

```
docker run \
    -d \
    --name synapse \
    -v ${CONFIG_PATH}:/synapse/config/ \
    matrixdotorg/synapse:v0.22.1
```
