# Synapse Docker

FIXME: this is out-of-date as of
https://github.com/matrix-org/synapse/issues/5518. Contributions to bring it up
to date would be welcome.

### Configuration

A sample ``docker-compose.yml`` is provided, including example labels for
reverse proxying and other artifacts. The docker-compose file is an example,
please comment/uncomment sections that are not suitable for your usecase.

Specify a ``SYNAPSE_CONFIG_PATH``, preferably to a persistent path,
to use manual configuration. To generate a fresh ``homeserver.yaml``, simply run:

```
docker-compose run --rm -e SYNAPSE_SERVER_NAME=my.matrix.host -e SYNAPSE_REPORT_STATS=yes synapse generate
```

Above command contains variable SYNAPSE_REPORT_STATS which is opt-in only. You are free to say 'no' here. 
This will also generate necessary signing keys.
Then, customize your configuration and run the server:

```
docker-compose up -d
```

### More information

For more information on required environment variables and mounts, see the main docker documentation at [/docker/README.md](../../docker/README.md)
