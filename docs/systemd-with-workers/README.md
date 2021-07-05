# Setting up Synapse with Workers and Systemd

This is a setup for managing synapse with systemd, including support for
managing workers. It provides a `matrix-synapse` service for the master, as
well as a `matrix-synapse-worker@` service template for any workers you
require. Additionally, to group the required services, it sets up a
`matrix-synapse.target`.

See the folder [system](https://github.com/matrix-org/synapse/tree/develop/docs/systemd-with-workers/system/)
for the systemd unit files.

The folder [workers](https://github.com/matrix-org/synapse/tree/develop/docs/systemd-with-workers/workers/)
contains an example configuration for the `federation_reader` worker.

## Synapse configuration files

See [workers.md](../workers.md) for information on how to set up the
configuration files and reverse-proxy correctly. You can find an example worker
config in the [workers](https://github.com/matrix-org/synapse/tree/develop/docs/systemd-with-workers/workers/)
folder.

Systemd manages daemonization itself, so ensure that none of the configuration
files set either `daemonize` or `worker_daemonize`.

The config files of all workers are expected to be located in
`/etc/matrix-synapse/workers`. If you want to use a different location, edit
the provided `*.service` files accordingly.

There is no need for a separate configuration file for the master process.

## Set up

1. Adjust synapse configuration files as above.
1. Copy the `*.service` and `*.target` files in [system](https://github.com/matrix-org/synapse/tree/develop/docs/systemd-with-workers/system/)
to `/etc/systemd/system`.
1. Run `systemctl daemon-reload` to tell systemd to load the new unit files.
1. Run `systemctl enable matrix-synapse.service`. This will configure the
synapse master process to be started as part of the `matrix-synapse.target`
target.
1. For each worker process to be enabled, run `systemctl enable
matrix-synapse-worker@<worker_name>.service`. For each `<worker_name>`, there
should be a corresponding configuration file.
`/etc/matrix-synapse/workers/<worker_name>.yaml`.
1. Start all the synapse processes with `systemctl start matrix-synapse.target`.
1. Tell systemd to start synapse on boot with `systemctl enable matrix-synapse.target`.

## Usage

Once the services are correctly set up, you can use the following commands
to manage your synapse installation:

```sh
# Restart Synapse master and all workers
systemctl restart matrix-synapse.target

# Stop Synapse and all workers
systemctl stop matrix-synapse.target

# Restart the master alone
systemctl start matrix-synapse.service

# Restart a specific worker (eg. federation_reader); the master is
# unaffected by this.
systemctl restart matrix-synapse-worker@federation_reader.service

# Add a new worker (assuming all configs are set up already)
systemctl enable matrix-synapse-worker@federation_writer.service
systemctl restart matrix-synapse.target
```

## Hardening

**Optional:** If further hardening is desired, the file
`override-hardened.conf` may be copied from
`contrib/systemd/override-hardened.conf` in this repository to the location
`/etc/systemd/system/matrix-synapse.service.d/override-hardened.conf` (the
directory may have to be created). It enables certain sandboxing features in
systemd to further secure the synapse service. You may read the comments to
understand what the override file is doing. The same file will need to be copied
to
`/etc/systemd/system/matrix-synapse-worker@.service.d/override-hardened-worker.conf`
(this directory may also have to be created) in order to apply the same
hardening options to any worker processes.

Once these files have been copied to their appropriate locations, simply reload
systemd's manager config files and restart all Synapse services to apply the hardening options. They will automatically
be applied at every restart as long as the override files are present at the
specified locations.

```sh
systemctl daemon-reload

# Restart services
systemctl restart matrix-synapse.target
```

In order to see their effect, you may run `systemd-analyze security
matrix-synapse.service` before and after applying the hardening options to see
the changes being applied at a glance.
