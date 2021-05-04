
# Synapse Docker

### Configuration

A sample ``docker-compose.yml`` is provided, including example labels for
reverse proxying and other artifacts. The docker-compose file is an example,
please comment/uncomment sections that are not suitable for your usecase.

Specify a ``SYNAPSE_CONFIG_PATH``, preferably to a persistent path,
to use manual configuration.

To generate a fresh `homeserver.yaml`, you can use the `generate` command.
(See the [documentation](../../docker/README.md#generating-a-configuration-file)
for more information.) You will need to specify appropriate values for at least the
`SYNAPSE_SERVER_NAME` and `SYNAPSE_REPORT_STATS` environment variables. For example:

```
docker-compose run --rm -e SYNAPSE_SERVER_NAME=my.matrix.host -e SYNAPSE_REPORT_STATS=yes synapse generate
```

(This will also generate necessary signing keys.)

Then, customize your configuration and run the server:

```
docker-compose up -d
```

### More information

For more information on required environment variables and mounts, see the main docker documentation at [/docker/README.md](../../docker/README.md)
