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

The workers communicate with the master process via a Synapse-specific protocol
called 'replication' (analogous to MySQL- or Postgres-style database
replication) which feeds a stream of relevant data from the master to the
workers so they can be kept in sync with the master process and database state.

Additionally, workers may make HTTP requests to the master, to send information
in the other direction. Typically this is used for operations which need to
wait for a reply - such as sending an event.

## Configuration

To make effective use of the workers, you will need to configure an HTTP
reverse-proxy such as nginx or haproxy, which will direct incoming requests to
the correct worker, or to the main synapse instance. Note that this includes
requests made to the federation port. See [reverse_proxy.md](reverse_proxy.md)
for information on setting up a reverse proxy.

To enable workers, you need to add *two* replication listeners to the
main Synapse configuration file (`homeserver.yaml`). For example:

```yaml
listeners:
  # The TCP replication port
  - port: 9092
    bind_address: '127.0.0.1'
    type: replication

  # The HTTP replication port
  - port: 9093
    bind_address: '127.0.0.1'
    type: http
    resources:
     - names: [replication]
```

Under **no circumstances** should these replication API listeners be exposed to
the public internet; they have no authentication and are unencrypted.

You should then create a set of configs for the various worker processes.  Each
worker configuration file inherits the configuration of the main homeserver
configuration file.  You can then override configuration specific to that
worker, e.g. the HTTP listener that it provides (if any); logging
configuration; etc.  You should minimise the number of overrides though to
maintain a usable config.

In the config file for each worker, you must specify the type of worker
application (`worker_app`). The currently available worker applications are
listed below. You must also specify the replication endpoints that it should
talk to on the main synapse process.  `worker_replication_host` should specify
the host of the main synapse, `worker_replication_port` should point to the TCP
replication listener port and `worker_replication_http_port` should point to
the HTTP replication port.

For example:

```yaml
worker_app: synapse.app.synchrotron

# The replication listener on the synapse to talk to.
worker_replication_host: 127.0.0.1
worker_replication_port: 9092
worker_replication_http_port: 9093

worker_listeners:
 - type: http
   port: 8083
   resources:
     - names:
       - client

worker_log_config: /home/matrix/synapse/config/synchrotron_log_config.yaml
```

...is a full configuration for a synchrotron worker instance, which will expose a
plain HTTP `/sync` endpoint on port 8083 separately from the `/sync` endpoint provided
by the main synapse.

Obviously you should configure your reverse-proxy to route the relevant
endpoints to the worker (`localhost:8083` in the above example).

Finally, you need to start your worker processes. This can be done with either
`synctl` or your distribution's preferred service manager such as `systemd`. We
recommend the use of `systemd` where available: for information on setting up
`systemd` to start synapse workers, see
[systemd-with-workers](systemd-with-workers). To use `synctl`, see below.

### **Experimental** support for replication over redis

As of Synapse v1.13.0, it is possible to configure Synapse to send replication
via a [Redis pub/sub channel](https://redis.io/topics/pubsub). This is an
alternative to direct TCP connections to the master: rather than all the
workers connecting to the master, all the workers and the master connect to
Redis, which relays replication commands between processes. This can give a
significant cpu saving on the master and will be a prerequisite for upcoming
performance improvements.

Note that this support is currently experimental; you may experience lost
messages and similar problems! It is strongly recommended that admins setting
up workers for the first time use direct TCP replication as above.

To configure Synapse to use Redis:

1. Install Redis following the normal procedure for your distribution - for
   example, on Debian, `apt install redis-server`. (It is safe to use an
   existing Redis deployment if you have one: we use a pub/sub stream named
   according to the `server_name` of your synapse server.)
2. Check Redis is running and accessible: you should be able to `echo PING | nc -q1
   localhost 6379` and get a response of `+PONG`.
3. Install the python prerequisites. If you installed synapse into a
   virtualenv, this can be done with:
   ```sh
   pip install matrix-synapse[redis]
   ```
   The debian packages from matrix.org already include the required
   dependencies.
4. Add config to the shared configuration (`homeserver.yaml`):
    ```yaml
    redis:
      enabled: true
    ```
    Optional parameters which can go alongside `enabled` are `host`, `port`,
    `password`. Normally none of these are required.
5. Restart master and all workers.

Once redis replication is in use, `worker_replication_port` is redundant and
can be removed from the worker configuration files. Similarly, the
configuration for the `listener` for the TCP replication port can be removed
from the main configuration file. Note that the HTTP replication port is
still required.

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
worker_pid_file: /home/matrix/synapse/synchrotron.pid
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

    synctl -w $CONFIG/workers/synchrotron.yaml restart

## Available worker applications

### `synapse.app.pusher`

Handles sending push notifications to sygnal and email. Doesn't handle any
REST endpoints itself, but you should set `start_pushers: False` in the
shared configuration file to stop the main synapse sending these notifications.

Note this worker cannot be load-balanced: only one instance should be active.

### `synapse.app.synchrotron`

The synchrotron handles `sync` requests from clients. In particular, it can
handle REST endpoints matching the following regular expressions:

    ^/_matrix/client/(v2_alpha|r0)/sync$
    ^/_matrix/client/(api/v1|v2_alpha|r0)/events$
    ^/_matrix/client/(api/v1|r0)/initialSync$
    ^/_matrix/client/(api/v1|r0)/rooms/[^/]+/initialSync$

The above endpoints should all be routed to the synchrotron worker by the
reverse-proxy configuration.

It is possible to run multiple instances of the synchrotron to scale
horizontally. In this case the reverse-proxy should be configured to
load-balance across the instances, though it will be more efficient if all
requests from a particular user are routed to a single instance. Extracting
a userid from the access token is currently left as an exercise for the reader.

### `synapse.app.appservice`

Handles sending output traffic to Application Services. Doesn't handle any
REST endpoints itself, but you should set `notify_appservices: False` in the
shared configuration file to stop the main synapse sending these notifications.

Note this worker cannot be load-balanced: only one instance should be active.

### `synapse.app.federation_reader`

Handles a subset of federation endpoints. In particular, it can handle REST
endpoints matching the following regular expressions:

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
    ^/_matrix/federation/v1/send/
    ^/_matrix/federation/v1/get_groups_publicised$
    ^/_matrix/key/v2/query

Additionally, the following REST endpoints can be handled for GET requests:

    ^/_matrix/federation/v1/groups/

The above endpoints should all be routed to the federation_reader worker by the
reverse-proxy configuration.

The `^/_matrix/federation/v1/send/` endpoint must only be handled by a single
instance.

Note that `federation` must be added to the listener resources in the worker config:

```yaml
worker_app: synapse.app.federation_reader
...
worker_listeners:
 - type: http
   port: <port>
   resources:
     - names:
       - federation
```

### `synapse.app.federation_sender`

Handles sending federation traffic to other servers. Doesn't handle any
REST endpoints itself, but you should set `send_federation: False` in the
shared configuration file to stop the main synapse sending this traffic.

Note this worker cannot be load-balanced: only one instance should be active.

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

Note this worker cannot be load-balanced: only one instance should be active.

### `synapse.app.client_reader`

Handles client API endpoints. It can handle REST endpoints matching the
following regular expressions:

    ^/_matrix/client/(api/v1|r0|unstable)/publicRooms$
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/joined_members$
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/context/.*$
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/members$
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/state$
    ^/_matrix/client/(api/v1|r0|unstable)/login$
    ^/_matrix/client/(api/v1|r0|unstable)/account/3pid$
    ^/_matrix/client/(api/v1|r0|unstable)/keys/query$
    ^/_matrix/client/(api/v1|r0|unstable)/keys/changes$
    ^/_matrix/client/versions$
    ^/_matrix/client/(api/v1|r0|unstable)/voip/turnServer$
    ^/_matrix/client/(api/v1|r0|unstable)/joined_groups$
    ^/_matrix/client/(api/v1|r0|unstable)/publicised_groups$
    ^/_matrix/client/(api/v1|r0|unstable)/publicised_groups/

Additionally, the following REST endpoints can be handled for GET requests:

    ^/_matrix/client/(api/v1|r0|unstable)/pushrules/.*$
    ^/_matrix/client/(api/v1|r0|unstable)/groups/.*$
    ^/_matrix/client/(api/v1|r0|unstable)/user/[^/]*/account_data/
    ^/_matrix/client/(api/v1|r0|unstable)/user/[^/]*/rooms/[^/]*/account_data/

Additionally, the following REST endpoints can be handled, but all requests must
be routed to the same instance:

    ^/_matrix/client/(r0|unstable)/register$
    ^/_matrix/client/(r0|unstable)/auth/.*/fallback/web$

Pagination requests can also be handled, but all requests with the same path
room must be routed to the same instance. Additionally, care must be taken to
ensure that the purge history admin API is not used while pagination requests
for the room are in flight:

    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/messages$

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

### `synapse.app.event_creator`

Handles some event creation. It can handle REST endpoints matching:

    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/send
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/state/
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/(join|invite|leave|ban|unban|kick)$
    ^/_matrix/client/(api/v1|r0|unstable)/join/
    ^/_matrix/client/(api/v1|r0|unstable)/profile/

It will create events locally and then send them on to the main synapse
instance to be persisted and handled.
