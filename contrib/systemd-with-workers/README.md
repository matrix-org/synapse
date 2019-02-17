# Setup Synapse with Workers and Systemd

This is a setup for using managing synapse with systemd including support for managing workers. It provides a `matrix-synapse-homeserver`, as well as a `matrix-synapse-worker@` service for any workers you require. Additionally to group the required services it sets up a `matrix.target`. You can of course add any bot- or bridge-services to this target as well by setting the respective `WantedBy` value in the `[Install]` section of their unit files to `matrix.target`.

See the folder [system](system) for any service and target files.

The folder [workers](workers) contains an example configuration for the `federation_reader` worker. Pay special attention to the path of the pid file and the name of the configuration file. In order to work with the `matrix-synapse-worker@.service` service those have to have the exact same name as the worker app.

## Setup

1. Adjust your matrix configs. Make sure that the pid files and config files have the exact same name as the worker app. Compare `matrix-synapse-worker@.service` for why. You can find an example worker config in the [workers](workers) folder. See below for relevant settings in the `homeserver.yaml`.
2. Make sure the location for the PID files exists and is writable by the `matrix-synapse` user.
3. `systemctl enable matrix-synapse-homeserver.service` this adds the homeserver app to the `matrix.target`
4. *Optional.* `systemctl enable matrix-synapse-worker@federation_reader.service` this adds the federation_reader app to the `matrix.target`
5. *Optional.* Repeat step 4 for any additional workers you require.
6. *Optional.* Add any bots or bridges by enabling them.
7. Start all matrix related services via `systemctl start matrix.target`
8. *Optional.* Enable autostart of all matrix related services on system boot via `systemctl enable matrix.target`

## The homeserver.yaml

The `homeserver.yaml` needs to be setup for a forking homeserver, that will write a PID file to the location in which the systemd service will expect it. If this setup is supposed to work without workers, the homeserver still needs to fork.

```
# Only when using workers.
worker_app: synapse.app.homeserver
worker_pid_file: /etc/matrix-synapse/pid/homeserver.pid

# No matter if you want to use workers or not.
daemonize: true
pid_file: /etc/matrix-synapse/pid/homeserver.pid
```

## Notes

It would probably be preferable to setup the PID files in the `/var/run` folder however I don't know of the top of my head how to allow non-root users to write PID files in this folder. So here's a TODO for any contributors.
