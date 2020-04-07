# Setting up Synapse with Workers and Systemd

This is a setup for managing synapse with systemd including support for
managing workers. It provides a `matrix-synapse` service for the master, as
well as a `matrix-synapse-worker@` service template for any workers you
require. Additionally, to group the required services it sets up a
`matrix-synapse.target`.

See the folder [system](system) for the systemd unit files.

The folder [workers](workers) contains an example configuration for the
`federation_reader` worker. Pay special attention to the name of the
configuration file. In order to work with the `matrix-synapse-worker@.service`
service, it needs to have the exact same name as the worker app.

This setup expects neither the homeserver nor any workers to fork. Forking is
handled by systemd.

## Set up

1. Adjust your matrix configs. You can find an example worker config in the
[workers](workers) folder. See below for relevant settings in the
`homeserver.yaml`.
1. Copy the `*.service` and `*.target` files in [system](system) to
`/etc/systemd/system`.
1. Run `systemctl deamon-reload` to tell systemd to load the new unit files.
1. Run `systemctl enable matrix-synapse.service`. This will configure the
synapse master process to be started as part of the `matrix-synapse.target`
target.
1. For each worker process to be enabled, run `systemctl enable
matrix-synapse-worker@<worker_name>.service`. For each `<worker_name>`, there
should be a corresponding configuration file
`/etc/matrix-synapse/workers/<worker_name>.yaml`.
1. Start all the synapse processes with `systemctl start matrix-synapse.target`.
1. Tell systemd to start synapse on boot with `systemctl enable matrix-synapse.target`

## Usage

After you have setup you can use the following commands to manage your synapse
installation:

```sh
# Restart Synapse master and all workers
systemctl restart matrix-synapse.target

# Stop Synapse and all workers
systemctl stop matrix-synapse.target

# Restart a specific worker (eg. federation_reader); the master is
# unaffected by this.
systemctl restart matrix-synapse-worker@federation_reader.service

# Add a new worker (assuming all configs are set up already)
systemctl enable matrix-synapse-worker@federation_writer.service
systemctl restart matrix-synapse.target
```

## The Configs

None of the workers should fork, as forking is handled by systemd, so ensure
that none of the configuration files set either `daemonize` or
`worker_daemonize`.

The config files of all workers are expected to be located in
`/etc/matrix-synapse/workers`. If you want to use a different location, edit
the provided `*.service` files accordingly.

There is no need for a separate configuration file for the master process.
