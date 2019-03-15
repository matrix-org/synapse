# Setup Synapse with Workers and Systemd

This is a setup for managing synapse with systemd including support for
managing workers. It provides a `matrix-synapse`, as well as a
`matrix-synapse-worker@` service for any workers you require. Additionally to
group the required services it sets up a `matrix.target`. You can use this to
automatically start any bot- or bridge-services. More on this in
[Bots and Bridges](#bots-and-bridges).

See the folder [system](system) for any service and target files.

The folder [workers](workers) contains an example configuration for the
`federation_reader` worker. Pay special attention to the name of the
configuration file. In order to work with the `matrix-synapse-worker@.service`
service, it needs to have the exact same name as the worker app.

This setup expects neither the homeserver nor any workers to fork. Forking is
handled by systemd.

## Setup

1. Adjust your matrix configs. Make sure that the worker config files have the
exact same name as the worker app. Compare `matrix-synapse-worker@.service` for
why. You can find an example worker config in the [workers](workers) folder. See
below for relevant settings in the `homeserver.yaml`.
2. Copy the `*.service` and `*.target` files in [system](system) to
`/etc/systemd/system`.
3. `systemctl enable matrix-synapse.service` this adds the homeserver
app to the `matrix.target`
4. *Optional.* `systemctl enable
matrix-synapse-worker@federation_reader.service` this adds the federation_reader
app to the `matrix-synapse.service`
5. *Optional.* Repeat step 4 for any additional workers you require.
6. *Optional.* Add any bots or bridges by enabling them.
7. Start all matrix related services via `systemctl start matrix.target`
8. *Optional.* Enable autostart of all matrix related services on system boot
via `systemctl enable matrix.target`

## Usage

After you have setup you can use the following commands to manage your synapse
installation:

```
# Start matrix-synapse, all workers and any enabled bots or bridges.
systemctl start matrix.target

# Restart matrix-synapse and all workers (not necessarily restarting bots
# or bridges, see "Bots and Bridges")
systemctl restart matrix-synapse.service

# Stop matrix-synapse and all workers (not necessarily restarting bots
# or bridges, see "Bots and Bridges")
systemctl stop matrix-synapse.service

# Restart a specific worker (i. e. federation_reader), the homeserver is
# unaffected by this.
systemctl restart matrix-synapse-worker@federation_reader.service

# Add a new worker (assuming all configs are setup already)
systemctl enable matrix-synapse-worker@federation_writer.service
systemctl restart matrix-synapse.service
```

## The Configs

Make sure the `worker_app` is set in the `homeserver.yaml` and it does not fork.

```
worker_app: synapse.app.homeserver 
daemonize: false
```

None of the workers should fork, as forking is handled by systemd. Hence make
sure this is present in all worker config files.

```
worker_daemonize: false
```

The config files of all workers are expected to be located in
`/etc/matrix-synapse/workers`. If you want to use a different location you have
to edit the provided `*.service` files accordingly.  

## Bots and Bridges

Most bots and bridges do not care if the homeserver goes down or is restarted.
Depending on the implementation this may crash them though. So look up the docs
or ask the community of the specific bridge or bot you want to run to make sure
you choose the correct setup.

Whichever configuration you choose, after the setup the following will enable
automatically starting (and potentially restarting) your bot/bridge with the
`matrix.target`.

```
systemctl enable <yourBotOrBridgeName>.service
```

**Note** that from an inactive synapse the bots/bridges will only be started with
synapse if you start the `matrix.target`, not if you start the
`matrix-synapse.service`. This is on purpose. Think of `matrix-synapse.service`
as *just* synapse, but `matrix.target` being anything matrix related, including
synapse and any and all enabled bots and bridges.

### Start with synapse but ignore synapse going down

If the bridge can handle shutdowns of the homeserver you'll want to install the
service in the `matrix.target` and optionally add a
`After=matrix-synapse.service` dependency to have the bot/bridge start after
synapse on starting everything.

In this case the service file should look like this.

```
[Unit]
# ...
# Optional, this will only ensure that if you start everything, synapse will
# be started before the bot/bridge will be started.
After=matrix-synapse.service

[Service]
# ...

[Install]
WantedBy=matrix.target
```

### Stop/restart when synapse stops/restarts

If the bridge can't handle shutdowns of the homeserver you'll still want to
install the service in the `matrix.target` but also have to specify the
`After=matrix-synapse.service` *and* `BindsTo=matrix-synapse.service`
dependencies to have the bot/bridge stop/restart with synapse.

In this case the service file should look like this.

```
[Unit]
# ...
# Mandatory
After=matrix-synapse.service
BindsTo=matrix-synapse.service

[Service]
# ...

[Install]
WantedBy=matrix.target
```
