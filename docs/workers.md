# Scaling synapse via workers

For small instances it recommended to run Synapse in monolith mode (the
default). For larger instances where performance is a concern it can be helpful
to split out functionality into multiple separate python processes. These
processes are called 'workers', and are (eventually) intended to scale
horizontally independently.

Synapse's worker support is under active development and subject to change as
we attempt to rapidly scale ever larger Synapse instances. However we are
documenting it here to help admins needing a highly scalable Synapse instance
similar to the one running `matrix.org`.

All processes continue to share the same database instance, and as such,
workers only work with PostgreSQL-based Synapse deployments. SQLite should only
be used for demo purposes and any admin considering workers should already be
running PostgreSQL.

## Master/worker communication

The processes communicate with each other via a Synapse-specific protocol called
'replication' (analogous to MySQL- or Postgres-style database replication) which
feeds streams of newly written data between processes so they can be kept in
sync with the database state.

Additionally, processes may make HTTP requests to each other. Typically this is
used for operations which need to wait for a reply - such as sending an event.

As of Synapse v1.13.0, it is possible to configure Synapse to send replication
via a [Redis pub/sub channel](https://redis.io/topics/pubsub), and is now the
recommended way of configuring replication. This is an alternative to the old
direct TCP connections to the master: rather than all the workers connecting to
the master, all the workers and the master connect to Redis, which relays
replication commands between processes. This can give a significant cpu saving
on the master and will be a prerequisite for upcoming performance improvements.


## Configuration

To make effective use of the workers, you will need to configure an HTTP
reverse-proxy such as nginx or haproxy, which will direct incoming requests to
the correct worker, or to the main synapse instance. Note that this includes
requests made to the federation port. See [reverse_proxy.md](reverse_proxy.md)
for information on setting up a reverse proxy.

To enable workers, you need to add both a HTTP replication listener and redis
config to the main Synapse configuration file (`homeserver.yaml`). For example:

```yaml
listeners:
  # The HTTP replication port
  - port: 9093
    bind_address: '127.0.0.1'
    type: http
    resources:
     - names: [replication]

redis:
    enabled: true
```

See the sample config for the full documentation of each option.

Under **no circumstances** should the replication API listener be exposed to the
public internet; it has no authentication and is unencrypted.

You should then create a set of configs for the various worker processes.  Each
worker configuration file inherits the configuration of the main homeserver
configuration file.  You can then override configuration specific to that
worker, e.g. the HTTP listener that it provides (if any); logging
configuration; etc.  You should minimise the number of overrides though to
maintain a usable config.

In the config file for each worker, you must specify the type of worker
application (`worker_app`), and you should specify a unqiue name for the worker
(`worker_name`). The currently available worker applications are listed below.
You must also specify the HTTP replication endpoint that it should talk to on
the main synapse process.  `worker_replication_host` should specify the host of
the main synapse and `worker_replication_http_port` should point to the HTTP
replication port.

For example:

```yaml
worker_app: synapse.app.generic_worker
worker_name: worker1

# The replication listener on the synapse to talk to.
worker_replication_host: 127.0.0.1
worker_replication_http_port: 9093

worker_listeners:
 - type: http
   port: 8083
   resources:
     - names:
       - client

worker_log_config: /home/matrix/synapse/config/worker1_log_config.yaml
```

...is a full configuration for a generic worker instance, which will expose a
plain HTTP endpoint on port 8083 separately serving various endpoints, e.g.
`/sync`, which are listed below.

Obviously you should configure your reverse-proxy to route the relevant
endpoints to the worker (`localhost:8083` in the above example).

Finally, you need to start your worker processes. This can be done with either
`synctl` or your distribution's preferred service manager such as `systemd`. We
recommend the use of `systemd` where available: for information on setting up
`systemd` to start synapse workers, see
[systemd-with-workers](systemd-with-workers). To use `synctl`, see below.


### Using synctl

If you want to use `synctl` to manage your synapse processes, you will need to
create an an additional configuration file for the master synapse process. That
configuration should look like this:

```yaml
worker_app: synapse.app.homeserver
```

Additionally, each worker app must be configured with the name of a "pid file",
to which it will write its process ID when it starts. For example, for a
synchrotron, you might write:

```yaml
worker_pid_file: /home/matrix/synapse/worker1.pid
```

Finally, to actually run your worker-based synapse, you must pass synctl the `-a`
commandline option to tell it to operate on all the worker configurations found
in the given directory, e.g.:

    synctl -a $CONFIG/workers start

Currently one should always restart all workers when restarting or upgrading
synapse, unless you explicitly know it's safe not to.  For instance, restarting
synapse without restarting all the synchrotrons may result in broken typing
notifications.

To manipulate a specific worker, you pass the -w option to synctl:

    synctl -w $CONFIG/workers/worker1.yaml restart

## Available worker applications

*Note:* Historically there used to be more apps, however they have been
amalgamated into a single `synapse.app.generic_worker` app. The remaining apps
are ones that do specific processing unrelated to requests, e.g. the `pusher`
that handles sending out push notifications for new events. The intention is for
all these to be folded into the `generic_worker` app and to use config to define
which processes handle the various proccessing such as push notifications.

### `synapse.app.generic_worker`

Handles the following API requests listed below matching the following regular
expressions:

    # Sync requests
    ^/_matrix/client/(v2_alpha|r0)/sync$
    ^/_matrix/client/(api/v1|v2_alpha|r0)/events$
    ^/_matrix/client/(api/v1|r0)/initialSync$
    ^/_matrix/client/(api/v1|r0)/rooms/[^/]+/initialSync$

    # Federation requests
    ^/_matrix/federation/v1/event/
    ^/_matrix/federation/v1/state/
    ^/_matrix/federation/v1/state_ids/
    ^/_matrix/federation/v1/backfill/
    ^/_matrix/federation/v1/get_missing_events/
    ^/_matrix/federation/v1/publicRooms
    ^/_matrix/federation/v1/query/
    ^/_matrix/federation/v1/make_join/
    ^/_matrix/federation/v1/make_leave/
    ^/_matrix/federation/v1/send_join/
    ^/_matrix/federation/v2/send_join/
    ^/_matrix/federation/v1/send_leave/
    ^/_matrix/federation/v2/send_leave/
    ^/_matrix/federation/v1/invite/
    ^/_matrix/federation/v2/invite/
    ^/_matrix/federation/v1/query_auth/
    ^/_matrix/federation/v1/event_auth/
    ^/_matrix/federation/v1/exchange_third_party_invite/
    ^/_matrix/federation/v1/user/devices/
    ^/_matrix/federation/v1/get_groups_publicised$
    ^/_matrix/key/v2/query

    # Inbound federation transaction request
    ^/_matrix/federation/v1/send/

    # Client API requests
    ^/_matrix/client/(api/v1|r0|unstable)/publicRooms$
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/joined_members$
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/context/.*$
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/members$
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/state$
    ^/_matrix/client/(api/v1|r0|unstable)/account/3pid$
    ^/_matrix/client/(api/v1|r0|unstable)/keys/query$
    ^/_matrix/client/(api/v1|r0|unstable)/keys/changes$
    ^/_matrix/client/versions$
    ^/_matrix/client/(api/v1|r0|unstable)/voip/turnServer$
    ^/_matrix/client/(api/v1|r0|unstable)/joined_groups$
    ^/_matrix/client/(api/v1|r0|unstable)/publicised_groups$
    ^/_matrix/client/(api/v1|r0|unstable)/publicised_groups/

    # Registration/login requests
    ^/_matrix/client/(api/v1|r0|unstable)/login$
    ^/_matrix/client/(r0|unstable)/register$
    ^/_matrix/client/(r0|unstable)/auth/.*/fallback/web$

    # Event sending requests
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/send
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/state/
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/(join|invite|leave|ban|unban|kick)$
    ^/_matrix/client/(api/v1|r0|unstable)/join/
    ^/_matrix/client/(api/v1|r0|unstable)/profile/


Additionally, the following REST endpoints can be handled for GET requests:

    ^/_matrix/federation/v1/groups/

Pagination requests can also be handled, but all requests with the same path
room must be routed to the same instance. Additionally, care must be taken to
ensure that the purge history admin API is not used while pagination requests
for the room are in flight:

    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/messages$

Note that the `client` and `federation` must be added to the listener resources
in the worker config.


#### Load balancing

Multiple instances of this app can be run and requests load balanced between
them. However, different endpoints have different characteristics and so admins
may wish to run multiple groups of workers handling different endpoints so that
load balancing can be done in different ways.

For `/sync` and `/initialSync` requests it will be more efficient if all
requests from a particular user are routed to a single instance. Extracting a
user ID from the access token or `Authorization` header is currently left as an
exercise for the reader. Admins may additionally wish to separate out `/sync`
requests that have a `since` query parameter from those that don't (and
`/initialSync`), as requests that don't are known as "initial sync" that happens
when a user logs in on a new device and can be *very* resource intensive, so
isolating these requests will stop them from interfering with other users ongoing
syncs.

Federation and client requests can be balanced via simple round robin.

The inbound federation transaction request `^/_matrix/federation/v1/send/`
should be balanced by source IP so that transactions from the same remote server
go to the same process.

Registration/login requests can be handled separately purely to help ensure that
unexpected load doesn't effect new logins and sign ups.

Finally, event sending requests can be  balanced by the embedded room ID (or
URI, or even just round robin). If there is a large bridge connected that is
sending or may send lots of events, then a dedicated set of workers can be
provisioned to ensure that bursts or increases of event sending is isolated from
effecting events sent by real users.

#### Stream writers

Additionally, there is *experimental* support for moving writing of specific
streams (such as events and typing) off of master to a particular worker. This
requires use of Redis.

To enable this then the worker must have a HTTP replication listener configured,
have a `worker_name` and be listed in the `instance_map` config. For example to
move event persistence off to a dedicated worker, the main shared config would
include:

```yaml
instance_map:
    event_persister1:
        host: localhost
        port: 8034

streams_writers:
    events: event_persister1
```


### `synapse.app.pusher`

Handles sending push notifications to sygnal and email. Doesn't handle any
REST endpoints itself, but you should set `start_pushers: False` in the
shared configuration file to stop the main synapse sending these notifications.

Note this worker cannot be load-balanced: only one instance should be active.

### `synapse.app.appservice`

Handles sending output traffic to Application Services. Doesn't handle any
REST endpoints itself, but you should set `notify_appservices: False` in the
shared configuration file to stop the main synapse sending these notifications.

Note this worker cannot be load-balanced: only one instance should be active.


### `synapse.app.federation_sender`

Handles sending federation traffic to other servers. Doesn't handle any
REST endpoints itself, but you should set `send_federation: False` in the
shared configuration file to stop the main synapse sending this traffic.

Note that if running multiple federation senders then you must list each
instance in the `federation_sender_instances` option by their `worker_name`. If
you add or remove instances they must all be stopped and started together. For example:

```yaml
federation_sender_instances:
    - federation_sender1
    - federation_sender2
```

### `synapse.app.media_repository`

Handles the media repository. It can handle all endpoints starting with:

    /_matrix/media/

... and the following regular expressions matching media-specific administration APIs:

    ^/_synapse/admin/v1/purge_media_cache$
    ^/_synapse/admin/v1/room/.*/media.*$
    ^/_synapse/admin/v1/user/.*/media.*$
    ^/_synapse/admin/v1/media/.*$
    ^/_synapse/admin/v1/quarantine_media/.*$

You should also set `enable_media_repo: False` in the shared configuration
file to stop the main synapse running background jobs related to managing the
media repository.

In the `media_repository` worker configuration file, configure the http listener to
expose the `media` resource. For example:

```yaml
    worker_listeners:
     - type: http
       port: 8085
       resources:
         - names:
           - media
```

Note that if running multiple media repositories they must be on the same server
and you must configure a single instance to run the background tasks, e.g.:

```yaml
    media_instance_running_background_jobs: "media-repository-1"
```

### `synapse.app.user_dir`

Handles searches in the user directory. It can handle REST endpoints matching
the following regular expressions:

    ^/_matrix/client/(api/v1|r0|unstable)/user_directory/search$

When using this worker you must also set `update_user_directory: False` in the
shared configuration file to stop the main synapse running background
jobs related to updating the user directory.

### `synapse.app.frontend_proxy`

Proxies some frequently-requested client endpoints to add caching and remove
load from the main synapse. It can handle REST endpoints matching the following
regular expressions:

    ^/_matrix/client/(api/v1|r0|unstable)/keys/upload

If `use_presence` is False in the homeserver config, it can also handle REST
endpoints matching the following regular expressions:

    ^/_matrix/client/(api/v1|r0|unstable)/presence/[^/]+/status

This "stub" presence handler will pass through `GET` request but make the
`PUT` effectively a no-op.

It will proxy any requests it cannot handle to the main synapse instance. It
must therefore be configured with the location of the main instance, via
the `worker_main_http_uri` setting in the `frontend_proxy` worker configuration
file. For example:

    worker_main_http_uri: http://127.0.0.1:8008
