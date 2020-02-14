# Synapse Docker

FIXME: this is out-of-date as of
https://github.com/matrix-org/synapse/issues/5518. Contributions to bring it up
to date would be welcome.

### Automated configuration

It is recommended that you use Docker Compose to run your containers, including
this image and a Postgres server. A sample ``docker-compose.yml`` is provided,
including example labels for reverse proxying and other artifacts.

Read the section about environment variables and set at least mandatory variables,
then run the server:

```
docker-compose up -d
```

If secrets are not specified in the environment variables, they will be generated
as part of the startup. Please ensure these secrets are kept between launches of the
Docker container, as their loss may require users to log in again.

### Manual configuration

A sample ``docker-compose.yml`` is provided, including example labels for
reverse proxying and other artifacts. The docker-compose file is an example,
please comment/uncomment sections that are not suitable for your usecase.

Specify a ``SYNAPSE_CONFIG_PATH``, preferably to a persistent path,
to use manual configuration. To generate a fresh ``homeserver.yaml``, simply run:

```
docker-compose run --rm -e SYNAPSE_SERVER_NAME=my.matrix.host synapse generate
```

Then, customize your configuration and run the server:

```
docker-compose up -d
```

### More information

For more information on required environment variables and mounts, see the main docker documentation at [/docker/README.md](../../docker/README.md)
