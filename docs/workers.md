# Scaling synapse via workers

For small instances it recommended to run Synapse in the default monolith mode.
For larger instances where performance is a concern it can be helpful to split
out functionality into multiple separate python processes. These processes are
called 'workers', and are (eventually) intended to scale horizontally
independently.

Synapse's worker support is under active development and subject to change as
we attempt to rapidly scale ever larger Synapse instances. However we are
documenting it here to help admins needing a highly scalable Synapse instance
similar to the one running `matrix.org`.

All processes continue to share the same database instance, and as such,
workers only work with PostgreSQL-based Synapse deployments. SQLite should only
be used for demo purposes and any admin considering workers should already be
running PostgreSQL.

## Main process/worker communication

The processes communicate with each other via a Synapse-specific protocol called
'replication' (analogous to MySQL- or Postgres-style database replication) which
feeds streams of newly written data between processes so they can be kept in
sync with the database state.

When configured to do so, Synapse uses a
[Redis pub/sub channel](https://redis.io/topics/pubsub) to send the replication
stream between all configured Synapse processes. Additionally, processes may
make HTTP requests to each other, primarily for operations which need to wait
for a reply ─ such as sending an event.

Redis support was added in v1.13.0 with it becoming the recommended method in
v1.18.0. It replaced the old direct TCP connections (which is deprecated as of
v1.18.0) to the main process. With Redis, rather than all the workers connecting
to the main process, all the workers and the main process connect to Redis,
which relays replication commands between processes. This can give a significant
cpu saving on the main process and will be a prerequisite for upcoming
performance improvements.

See the [Architectural diagram](#architectural-diagram) section at the end for
a visualisation of what this looks like.


## Setting up workers

A Redis server is required to manage the communication between the processes.
The Redis server should be installed following the normal procedure for your
distribution (e.g. `apt install redis-server` on Debian). It is safe to use an
existing Redis deployment if you have one.

Once installed, check that Redis is running and accessible from the host running
Synapse, for example by executing `echo PING | nc -q1 localhost 6379` and seeing
a response of `+PONG`.

The appropriate dependencies must also be installed for Synapse. If using a
virtualenv, these can be installed with:

```sh
pip install matrix-synapse[redis]
```

Note that these dependencies are included when synapse is installed with `pip
install matrix-synapse[all]`. They are also included in the debian packages from
`matrix.org` and in the docker images at
https://hub.docker.com/r/matrixdotorg/synapse/.

To make effective use of the workers, you will need to configure an HTTP
reverse-proxy such as nginx or haproxy, which will direct incoming requests to
the correct worker, or to the main synapse instance. See
[reverse_proxy.md](reverse_proxy.md) for information on setting up a reverse
proxy.

When using workers, each worker process has its own configuration file which
contains settings specific to that worker, such as the HTTP listener that it
provides (if any), logging configuration, etc.

Normally, the worker processes are configured to read from a shared
configuration file as well as the worker-specific configuration files. This
makes it easier to keep common configuration settings synchronised across all
the processes.

The main process is somewhat special in this respect: it does not normally
need its own configuration file and can take all of its configuration from the
shared configuration file.


### Shared configuration

Normally, only a couple of changes are needed to make an existing configuration
file suitable for use with workers. First, you need to enable an "HTTP replication
listener" for the main process; and secondly, you need to enable redis-based
replication. For example:


```yaml
# extend the existing `listeners` section. This defines the ports that the
# main process will listen on.
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

Under **no circumstances** should the replication listener be exposed to the
public internet; it has no authentication and is unencrypted.


### Worker configuration

In the config file for each worker, you must specify the type of worker
application (`worker_app`), and you should specify a unique name for the worker
(`worker_name`). The currently available worker applications are listed below.
You must also specify the HTTP replication endpoint that it should talk to on
the main synapse process.  `worker_replication_host` should specify the host of
the main synapse and `worker_replication_http_port` should point to the HTTP
replication port. If the worker will handle HTTP requests then the
`worker_listeners` option should be set with a `http` listener, in the same way
as the `listeners` option in the shared config.

For example:

```yaml
worker_app: synapse.app.generic_worker
worker_name: worker1

# The replication listener on the main synapse process.
worker_replication_host: 127.0.0.1
worker_replication_http_port: 9093

worker_listeners:
 - type: http
   port: 8083
   resources:
     - names:
       - client
       - federation

worker_log_config: /home/matrix/synapse/config/worker1_log_config.yaml
```

...is a full configuration for a generic worker instance, which will expose a
plain HTTP endpoint on port 8083 separately serving various endpoints, e.g.
`/sync`, which are listed below.

Obviously you should configure your reverse-proxy to route the relevant
endpoints to the worker (`localhost:8083` in the above example).


### Running Synapse with workers

Finally, you need to start your worker processes. This can be done with either
`synctl` or your distribution's preferred service manager such as `systemd`. We
recommend the use of `systemd` where available: for information on setting up
`systemd` to start synapse workers, see
[systemd-with-workers](systemd-with-workers). To use `synctl`, see
[synctl_workers.md](synctl_workers.md).


## Available worker applications

### `synapse.app.generic_worker`

This worker can handle API requests matching the following regular
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
    ^/_synapse/client/password_reset/email/submit_token$

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

Pagination requests can also be handled, but all requests for a given
room must be routed to the same instance. Additionally, care must be taken to
ensure that the purge history admin API is not used while pagination requests
for the room are in flight:

    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/messages$

Additionally, the following endpoints should be included if Synapse is configured
to use SSO (you only need to include the ones for whichever SSO provider you're
using):

    # OpenID Connect requests.
    ^/_matrix/client/(api/v1|r0|unstable)/login/sso/redirect$
    ^/_synapse/oidc/callback$

    # SAML requests.
    ^/_matrix/client/(api/v1|r0|unstable)/login/sso/redirect$
    ^/_matrix/saml2/authn_response$

    # CAS requests.
    ^/_matrix/client/(api/v1|r0|unstable)/login/(cas|sso)/redirect$
    ^/_matrix/client/(api/v1|r0|unstable)/login/cas/ticket$

Note that a HTTP listener with `client` and `federation` resources must be
configured in the `worker_listeners` option in the worker config.

Ensure that all SSO logins go to a single process (usually the main process). 
For multiple workers not handling the SSO endpoints properly, see
[#7530](https://github.com/matrix-org/synapse/issues/7530).

#### Load balancing

It is possible to run multiple instances of this worker app, with incoming requests
being load-balanced between them by the reverse-proxy. However, different endpoints
have different characteristics and so admins
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
unexpected load doesn't affect new logins and sign ups.

Finally, event sending requests can be balanced by the room ID in the URI (or
the full URI, or even just round robin), the room ID is the path component after
`/rooms/`. If there is a large bridge connected that is sending or may send lots
of events, then a dedicated set of workers can be provisioned to limit the
effects of bursts of events from that bridge on events sent by normal users.

#### Stream writers

Additionally, there is *experimental* support for moving writing of specific
streams (such as events) off of the main process to a particular worker. (This
is only supported with Redis-based replication.)

Currently supported streams are `events` and `typing`.

To enable this, the worker must have a HTTP replication listener configured,
have a `worker_name` and be listed in the `instance_map` config. For example to
move event persistence off to a dedicated worker, the shared configuration would
include:

```yaml
instance_map:
    event_persister1:
        host: localhost
        port: 8034

stream_writers:
    events: event_persister1
```

The `events` stream also experimentally supports having multiple writers, where
work is sharded between them by room ID. Note that you *must* restart all worker
instances when adding or removing event persisters. An example `stream_writers`
configuration with multiple writers:

```yaml
stream_writers:
    events:
        - event_persister1
        - event_persister2
```

#### Background tasks

There is also *experimental* support for moving background tasks to a separate
worker. Background tasks are run periodically or started via replication. Exactly
which tasks are configured to run depends on your Synapse configuration (e.g. if
stats is enabled).

To enable this, the worker must have a `worker_name` and can be configured to run
background tasks. For example, to move background tasks to a dedicated worker,
the shared configuration would include:

```yaml
run_background_tasks_on: background_worker
```

You might also wish to investigate the `update_user_directory` and
`media_instance_running_background_jobs` settings.

### `synapse.app.pusher`

Handles sending push notifications to sygnal and email. Doesn't handle any
REST endpoints itself, but you should set `start_pushers: False` in the
shared configuration file to stop the main synapse sending push notifications.

Note this worker cannot be load-balanced: only one instance should be active.

### `synapse.app.appservice`

Handles sending output traffic to Application Services. Doesn't handle any
REST endpoints itself, but you should set `notify_appservices: False` in the
shared configuration file to stop the main synapse sending appservice notifications.

Note this worker cannot be load-balanced: only one instance should be active.


### `synapse.app.federation_sender`

Handles sending federation traffic to other servers. Doesn't handle any
REST endpoints itself, but you should set `send_federation: False` in the
shared configuration file to stop the main synapse sending this traffic.

If running multiple federation senders then you must list each
instance in the `federation_sender_instances` option by their `worker_name`.
All instances must be stopped and started when adding or removing instances.
For example:

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

Note that if a reverse proxy is used , then `/_matrix/media/` must be routed for both inbound client and federation requests (if they are handled separately).

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

### Historical apps

*Note:* Historically there used to be more apps, however they have been
amalgamated into a single `synapse.app.generic_worker` app. The remaining apps
are ones that do specific processing unrelated to requests, e.g. the `pusher`
that handles sending out push notifications for new events. The intention is for
all these to be folded into the `generic_worker` app and to use config to define
which processes handle the various proccessing such as push notifications.


## Migration from old config

There are two main independent changes that have been made: introducing Redis
support and merging apps into `synapse.app.generic_worker`. Both these changes
are backwards compatible and so no changes to the config are required, however
server admins are encouraged to plan to migrate to Redis as the old style direct
TCP replication config is deprecated.

To migrate to Redis add the `redis` config as above, and optionally remove the
TCP `replication` listener from master and `worker_replication_port` from worker
config.

To migrate apps to use `synapse.app.generic_worker` simply update the
`worker_app` option in the worker configs, and where worker are started (e.g.
in systemd service files, but not required for synctl).


## Architectural diagram

The following shows an example setup using Redis and a reverse proxy:

```
                     Clients & Federation
                              |
                              v
                        +-----------+
                        |           |
                        |  Reverse  |
                        |  Proxy    |
                        |           |
                        +-----------+
                            | | |
                            | | | HTTP requests
        +-------------------+ | +-----------+
        |                 +---+             |
        |                 |                 |
        v                 v                 v
+--------------+  +--------------+  +--------------+  +--------------+
|   Main       |  |   Generic    |  |   Generic    |  |  Event       |
|   Process    |  |   Worker 1   |  |   Worker 2   |  |  Persister   |
+--------------+  +--------------+  +--------------+  +--------------+
      ^    ^          |   ^   |         |   ^   |          ^    ^
      |    |          |   |   |         |   |   |          |    |
      |    |          |   |   |  HTTP   |   |   |          |    |
      |    +----------+<--|---|---------+   |   |          |    |
      |                   |   +-------------|-->+----------+    |
      |                   |                 |                   |
      |                   |                 |                   |
      v                   v                 v                   v
====================================================================
                                                         Redis pub/sub channel
```
