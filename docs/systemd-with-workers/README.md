# Setting up Synapse with Workers and Systemd

The necessary service files are included in the Debian packaging, see
[debian](https://github.com/matrix-org/synapse/tree/develop/debian/) for the
systemd unit files.

The folder [workers](https://github.com/matrix-org/synapse/tree/develop/docs/systemd-with-workers/workers/)
contains an example configuration for the `generic_worker` worker.

## Synapse configuration files

See [the worker documentation](../workers.md) for information on how to set up the
configuration files and reverse-proxy correctly.
Below is a sample `generic_worker` worker configuration file.
```yaml
{{#include workers/generic_worker.yaml}}
```

Systemd manages daemonization itself, so ensure that none of the configuration
files set either `daemonize` or `worker_daemonize`.

The config files of all workers are expected to be located in
`/etc/matrix-synapse/workers`. If you want to use a different location, edit
the provided `*.service` files accordingly.

There is no need for a separate configuration file for the master process.

## Set up

1. Adjust synapse configuration files as above.
1. For each worker process to be enabled, run `systemctl enable
matrix-synapse-worker@<worker_name>.service`. For each `<worker_name>`, there
should be a corresponding configuration file.
`/etc/matrix-synapse/workers/<worker_name>.yaml`.
1. Start all the synapse processes with `systemctl start matrix-synapse.target`.

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

# Restart a specific worker (eg. generic_worker); the master is
# unaffected by this.
systemctl restart matrix-synapse-worker@generic_worker.service

# Add a new worker (assuming all configs are set up already)
systemctl enable matrix-synapse-worker@federation_writer.service
systemctl restart matrix-synapse.target
```
