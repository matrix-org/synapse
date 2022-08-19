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

## Hardening

**Optional:** If further hardening is desired, the file
`override-hardened.conf` may be copied from
[contrib/systemd/override-hardened.conf](https://github.com/matrix-org/synapse/tree/develop/contrib/systemd/)
in this repository to the location
`/etc/systemd/system/matrix-synapse.service.d/override-hardened.conf` (the
directory may have to be created). It enables certain sandboxing features in
systemd to further secure the synapse service. You may read the comments to
understand what the override file is doing. The same file will need to be copied to
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
