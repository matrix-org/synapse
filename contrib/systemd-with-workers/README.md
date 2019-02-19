# Setup Synapse with Workers and Systemd

This is a setup for using managing synapse with systemd including support for managing workers. It provides a `matrix-synapse-homeserver`, as well as a `matrix-synapse-worker@` service for any workers you require. Additionally to group the required services it sets up a `matrix.target`. You can of course add any bot- or bridge-services to this target as well by setting the respective `WantedBy` value in the `[Install]` section of their unit files to `matrix.target`.

See the folder [system](system) for any service and target files.

The folder [workers](workers) contains an example configuration for the `federation_reader` worker. Pay special attention to the name of the configuration file. In order to work with the `matrix-synapse-worker@.service` service, it needs to have the exact same name as the worker app.

This setup expects neither the homeserver nor any workers to fork. Forking is handled by systemd.

## Setup

1. Adjust your matrix configs. Make sure that the worker config files have the exact same name as the worker app. Compare `matrix-synapse-worker@.service` for why. You can find an example worker config in the [workers](workers) folder. See below for relevant settings in the `homeserver.yaml`.
2. Copy the `*.service` and `*.target` files in [system](system) to `/etc/systemd/system`.
3. `systemctl enable matrix-synapse-homeserver.service` this adds the homeserver app to the `matrix.target`
4. *Optional.* `systemctl enable matrix-synapse-worker@federation_reader.service` this adds the federation_reader app to the `matrix.target`
5. *Optional.* Repeat step 4 for any additional workers you require.
6. *Optional.* Add any bots or bridges by enabling them.
7. Start all matrix related services via `systemctl start matrix.target`
8. *Optional.* Enable autostart of all matrix related services on system boot via `systemctl enable matrix.target`

## The Configs

Make sure the `worker_app` is set in the `homeserver.yaml` and it does not fork.

```
worker_app: synapse.app.homeserver
daemonize: false
```

None of the workers should fork, as forking is handled by systemd. Hence make sure this is present in all worker config files.

```
worker_daemonize: false
```

The config files of all workers are expected to be located in `/etc/matrix-synapse/workers`. If you want to use a different location you have to edit the provided `*.service` files accordingly.
