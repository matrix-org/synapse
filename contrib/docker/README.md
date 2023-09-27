
# Synapse Docker

There are two `docker-compose.yaml` files to support `sqlite` and `postgres` databases.

1. The `postgres` database is recommended for production use, you could use `docker-compose.postgres.yaml`.

2. The `sqlite` database is recommended for development and testing, you could use `docker-compose.sqlite.yaml`.

Please comment/uncomment sections that are not suitable for your usecase.
Go to the directory `contrib/docker` to run the below command.

### Configuration

The container `synapse-init` is to generate a fresh `homeserver.yaml`, you can use the `generate` command.
(See the [documentation](../../docker/README.md#generating-a-configuration-file)
for more information.) You will need to specify appropriate values for at least the
`SYNAPSE_SERVER_NAME` and `SYNAPSE_REPORT_STATS` environment variables. For example:

Specify a ``SYNAPSE_CONFIG_PATH``, preferably to a persistent path,
to use manual configuration.

You just choose one of the following options.

#### sqlite

1. change the `SYNAPSE_SERVER_NAME` of `synapse-init` at the `docker-compose.sqlite.yaml`
2. change the local device path of `volumes` at the `docker-compose.sqlite.yaml`
3. run the command `docker-compose -f docker-compose.sqlite.yml up -d`

#### postgres

1. change the `SYNAPSE_SERVER_NAME` of `synapse-init` at the `docker-compose.postgres.yaml`
2. change the local device path of `volumes` for `synapse_data` and `pg_data` at the `docker-compose.postgres.yaml`
3. create the direcotry of `pg_data`, such as `mkdir -p pg_data`
3. change the postgres password by `POSTGRES_PASSWORD`
3. run the command `docker-compose -f docker-compose.postgres.yml up -d`

### Validate

Open `http://localhost:8008` in your browser, and it's successful if you see the welcome page.

### More information

For more information on required environment variables and mounts, see the main docker documentation at [/docker/README.md](../../docker/README.md)
