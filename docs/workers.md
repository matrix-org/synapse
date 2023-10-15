# Scaling synapse via workers

For small instances it is recommended to run Synapse in the default monolith mode.
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

See also [Matrix.org blog post](https://matrix.org/blog/2020/11/03/how-we-fixed-synapses-scalability)
for a higher level overview.

## Main process/worker communication

The processes communicate with each other via a Synapse-specific protocol called
'replication' (analogous to MySQL- or Postgres-style database replication) which
feeds streams of newly written data between processes so they can be kept in
sync with the database state.

When configured to do so, Synapse uses a
[Redis pub/sub channel](https://redis.io/docs/manual/pubsub/) to send the replication
stream between all configured Synapse processes. Additionally, processes may
make HTTP requests to each other, primarily for operations which need to wait
for a reply ─ such as sending an event.

All the workers and the main process connect to Redis, which relays replication
commands between processes.

If Redis support is enabled Synapse will use it as a shared cache, as well as a
pub/sub mechanism.

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
pip install "matrix-synapse[redis]"
```

Note that these dependencies are included when synapse is installed with `pip
install matrix-synapse[all]`. They are also included in the debian packages from
`matrix.org` and in the docker images at
https://hub.docker.com/r/matrixdotorg/synapse/.

To make effective use of the workers, you will need to configure an HTTP
reverse-proxy such as nginx or haproxy, which will direct incoming requests to
the correct worker, or to the main synapse instance. See
[the reverse proxy documentation](reverse_proxy.md) for information on setting up a reverse
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

Normally, only a few changes are needed to make an existing configuration
file suitable for use with workers:
* First, you need to enable an
["HTTP replication listener"](usage/configuration/config_documentation.md#listeners)
for the main process
* Secondly, you need to enable
[redis-based replication](usage/configuration/config_documentation.md#redis)
* You will need to add an [`instance_map`](usage/configuration/config_documentation.md#instance_map) 
with the `main` process defined, as well as the relevant connection information from
it's HTTP `replication` listener (defined in step 1 above).
  * Note that the `host` defined is the address the worker needs to look for the `main`
  process at, not necessarily the same address that is bound to.
  * If you are using Unix sockets for the `replication` resource, make sure to
  use a `path` to the socket file instead of a `port`.
* Optionally, a [shared secret](usage/configuration/config_documentation.md#worker_replication_secret)
can be used to authenticate HTTP traffic between workers. For example:

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

# Add a random shared secret to authenticate traffic.
worker_replication_secret: ""

redis:
    enabled: true

instance_map:
    main:
        host: 'localhost'
        port: 9093
```

See the [configuration manual](usage/configuration/config_documentation.md)
for the full documentation of each option.

Under **no circumstances** should the replication listener be exposed to the
public internet; replication traffic is:

* always unencrypted
* unauthenticated, unless [`worker_replication_secret`](usage/configuration/config_documentation.md#worker_replication_secret)
  is configured


### Worker configuration

In the config file for each worker, you must specify:
 * The type of worker ([`worker_app`](usage/configuration/config_documentation.md#worker_app)).
   The currently available worker applications are listed [below](#available-worker-applications).
 * A unique name for the worker ([`worker_name`](usage/configuration/config_documentation.md#worker_name)).
 * If handling HTTP requests, a [`worker_listeners`](usage/configuration/config_documentation.md#worker_listeners) option
   with an `http` listener.
 * **Synapse 1.72 and older:** if handling the `^/_matrix/client/v3/keys/upload` endpoint, the HTTP URI for
   the main process (`worker_main_http_uri`). This config option is no longer required and is ignored when running Synapse 1.73 and newer.

For example:

```yaml
{{#include systemd-with-workers/workers/generic_worker.yaml}}
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
[Systemd with Workers](systemd-with-workers/). To use `synctl`, see
[Using synctl with Workers](synctl_workers.md).

## Start Synapse with Poetry

The following applies to Synapse installations that have been installed from source using `poetry`.

You can start the main Synapse process with Poetry by running the following command:
```console
poetry run synapse_homeserver --config-file [your homeserver.yaml]
```
For worker setups, you can run the following command
```console
poetry run synapse_worker --config-file [your homeserver.yaml] --config-file [your worker.yaml]
```
## Available worker applications

### `synapse.app.generic_worker`

This worker can handle API requests matching the following regular expressions.
These endpoints can be routed to any worker. If a worker is set up to handle a
stream then, for maximum efficiency, additional endpoints should be routed to that
worker: refer to the [stream writers](#stream-writers) section below for further
information.

    # Sync requests
    ^/_matrix/client/(r0|v3)/sync$
    ^/_matrix/client/(api/v1|r0|v3)/events$
    ^/_matrix/client/(api/v1|r0|v3)/initialSync$
    ^/_matrix/client/(api/v1|r0|v3)/rooms/[^/]+/initialSync$

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
    ^/_matrix/federation/(v1|v2)/send_join/
    ^/_matrix/federation/(v1|v2)/send_leave/
    ^/_matrix/federation/(v1|v2)/invite/
    ^/_matrix/federation/v1/event_auth/
    ^/_matrix/federation/v1/timestamp_to_event/
    ^/_matrix/federation/v1/exchange_third_party_invite/
    ^/_matrix/federation/v1/user/devices/
    ^/_matrix/key/v2/query
    ^/_matrix/federation/v1/hierarchy/

    # Inbound federation transaction request
    ^/_matrix/federation/v1/send/

    # Client API requests
    ^/_matrix/client/(api/v1|r0|v3|unstable)/createRoom$
    ^/_matrix/client/(api/v1|r0|v3|unstable)/publicRooms$
    ^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/joined_members$
    ^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/context/.*$
    ^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/members$
    ^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/state$
    ^/_matrix/client/v1/rooms/.*/hierarchy$
    ^/_matrix/client/(v1|unstable)/rooms/.*/relations/
    ^/_matrix/client/v1/rooms/.*/threads$
    ^/_matrix/client/unstable/im.nheko.summary/rooms/.*/summary$
    ^/_matrix/client/(r0|v3|unstable)/account/3pid$
    ^/_matrix/client/(r0|v3|unstable)/account/whoami$
    ^/_matrix/client/(r0|v3|unstable)/devices$
    ^/_matrix/client/versions$
    ^/_matrix/client/(api/v1|r0|v3|unstable)/voip/turnServer$
    ^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/event/
    ^/_matrix/client/(api/v1|r0|v3|unstable)/joined_rooms$
    ^/_matrix/client/v1/rooms/.*/timestamp_to_event$
    ^/_matrix/client/(api/v1|r0|v3|unstable/.*)/rooms/.*/aliases
    ^/_matrix/client/(api/v1|r0|v3|unstable)/search$
    ^/_matrix/client/(r0|v3|unstable)/user/.*/filter(/|$)
    ^/_matrix/client/(api/v1|r0|v3|unstable)/directory/room/.*$
    ^/_matrix/client/(r0|v3|unstable)/capabilities$
    ^/_matrix/client/(r0|v3|unstable)/notifications$

    # Encryption requests
    ^/_matrix/client/(r0|v3|unstable)/keys/query$
    ^/_matrix/client/(r0|v3|unstable)/keys/changes$
    ^/_matrix/client/(r0|v3|unstable)/keys/claim$
    ^/_matrix/client/(r0|v3|unstable)/room_keys/
    ^/_matrix/client/(r0|v3|unstable)/keys/upload/

    # Registration/login requests
    ^/_matrix/client/(api/v1|r0|v3|unstable)/login$
    ^/_matrix/client/(r0|v3|unstable)/register$
    ^/_matrix/client/(r0|v3|unstable)/register/available$
    ^/_matrix/client/v1/register/m.login.registration_token/validity$
    ^/_matrix/client/(r0|v3|unstable)/password_policy$

    # Event sending requests
    ^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/redact
    ^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/send
    ^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/state/
    ^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/(join|invite|leave|ban|unban|kick)$
    ^/_matrix/client/(api/v1|r0|v3|unstable)/join/
    ^/_matrix/client/(api/v1|r0|v3|unstable)/knock/
    ^/_matrix/client/(api/v1|r0|v3|unstable)/profile/

    # Account data requests
    ^/_matrix/client/(r0|v3|unstable)/.*/tags
    ^/_matrix/client/(r0|v3|unstable)/.*/account_data

    # Receipts requests
    ^/_matrix/client/(r0|v3|unstable)/rooms/.*/receipt
    ^/_matrix/client/(r0|v3|unstable)/rooms/.*/read_markers

    # Presence requests
    ^/_matrix/client/(api/v1|r0|v3|unstable)/presence/

    # User directory search requests
    ^/_matrix/client/(r0|v3|unstable)/user_directory/search$

Additionally, the following REST endpoints can be handled for GET requests:

    ^/_matrix/client/(api/v1|r0|v3|unstable)/pushrules/

Pagination requests can also be handled, but all requests for a given
room must be routed to the same instance. Additionally, care must be taken to
ensure that the purge history admin API is not used while pagination requests
for the room are in flight:

    ^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/messages$

Additionally, the following endpoints should be included if Synapse is configured
to use SSO (you only need to include the ones for whichever SSO provider you're
using):

    # for all SSO providers
    ^/_matrix/client/(api/v1|r0|v3|unstable)/login/sso/redirect
    ^/_synapse/client/pick_idp$
    ^/_synapse/client/pick_username
    ^/_synapse/client/new_user_consent$
    ^/_synapse/client/sso_register$

    # OpenID Connect requests.
    ^/_synapse/client/oidc/callback$

    # SAML requests.
    ^/_synapse/client/saml2/authn_response$

    # CAS requests.
    ^/_matrix/client/(api/v1|r0|v3|unstable)/login/cas/ticket$

Ensure that all SSO logins go to a single process.
For multiple workers not handling the SSO endpoints properly, see
[#7530](https://github.com/matrix-org/synapse/issues/7530) and
[#9427](https://github.com/matrix-org/synapse/issues/9427).

Note that a [HTTP listener](usage/configuration/config_documentation.md#listeners)
with `client` and `federation` `resources` must be configured in the
[`worker_listeners`](usage/configuration/config_documentation.md#worker_listeners)
option in the worker config.

#### Load balancing

It is possible to run multiple instances of this worker app, with incoming requests
being load-balanced between them by the reverse-proxy. However, different endpoints
have different characteristics and so admins
may wish to run multiple groups of workers handling different endpoints so that
load balancing can be done in different ways.

For `/sync` and `/initialSync` requests it will be more efficient if all
requests from a particular user are routed to a single instance. This can
be done in reverse proxy by extracting username part from the users access token.

Admins may additionally wish to separate out `/sync`
requests that have a `since` query parameter from those that don't (and
`/initialSync`), as requests that don't are known as "initial sync" that happens
when a user logs in on a new device and can be *very* resource intensive, so
isolating these requests will stop them from interfering with other users ongoing
syncs.

Example `nginx` configuration snippet that handles the cases above. This is just an
example and probably requires some changes according to your particular setup:

```nginx
# Choose sync worker based on the existence of "since" query parameter
map $arg_since $sync {
    default synapse_sync;
    '' synapse_initial_sync;
}

# Extract username from access token passed as URL parameter
map $arg_access_token $accesstoken_from_urlparam {
    # Defaults to just passing back the whole accesstoken
    default   $arg_access_token;
    # Try to extract username part from accesstoken URL parameter
    "~syt_(?<username>.*?)_.*"           $username;
}

# Extract username from access token passed as authorization header
map $http_authorization $mxid_localpart {
    # Defaults to just passing back the whole accesstoken
    default                              $http_authorization;
    # Try to extract username part from accesstoken header
    "~Bearer syt_(?<username>.*?)_.*"    $username;
    # if no authorization-header exist, try mapper for URL parameter "access_token"
    ""                                   $accesstoken_from_urlparam;
}

upstream synapse_initial_sync {
    # Use the username mapper result for hash key
    hash $mxid_localpart consistent;
    server 127.0.0.1:8016;
    server 127.0.0.1:8036;
}

upstream synapse_sync {
    # Use the username mapper result for hash key
    hash $mxid_localpart consistent;
    server 127.0.0.1:8013;
    server 127.0.0.1:8037;
    server 127.0.0.1:8038;
    server 127.0.0.1:8039;
}

# Sync initial/normal
location ~ ^/_matrix/client/(r0|v3)/sync$ {
	proxy_pass http://$sync;
}

# Normal sync
location ~ ^/_matrix/client/(api/v1|r0|v3)/events$ {
	proxy_pass http://synapse_sync;
}

# Initial_sync
location ~ ^/_matrix/client/(api/v1|r0|v3)/initialSync$ {
	proxy_pass http://synapse_initial_sync;
}
location ~ ^/_matrix/client/(api/v1|r0|v3)/rooms/[^/]+/initialSync$ {
	proxy_pass http://synapse_initial_sync;
}
```

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

Additionally, the writing of specific streams (such as events) can be moved off
of the main process to a particular worker.

To enable this, the worker must have:
* An [HTTP `replication` listener](usage/configuration/config_documentation.md#listeners) configured,
* Have a [`worker_name`](usage/configuration/config_documentation.md#worker_name)
and be listed in the [`instance_map`](usage/configuration/config_documentation.md#instance_map)
config. 
* Have the main process declared on the [`instance_map`](usage/configuration/config_documentation.md#instance_map) as well.

Note: The same worker can handle multiple streams, but unless otherwise documented,
each stream can only have a single writer.

For example, to move event persistence off to a dedicated worker, the shared
configuration would include:

```yaml
instance_map:
    main:
        host: localhost
        port: 8030
    event_persister1:
        host: localhost
        port: 8034

stream_writers:
    events: event_persister1
```

An example for a stream writer instance:

```yaml
{{#include systemd-with-workers/workers/event_persister.yaml}}
```

Some of the streams have associated endpoints which, for maximum efficiency, should
be routed to the workers handling that stream. See below for the currently supported
streams and the endpoints associated with them:

##### The `events` stream

The `events` stream experimentally supports having multiple writer workers, where load
is sharded between them by room ID. Each writer is called an _event persister_. They are
responsible for
- receiving new events,
- linking them to those already in the room [DAG](development/room-dag-concepts.md),
- persisting them to the DB, and finally
- updating the events stream.

Because load is sharded in this way, you *must* restart all worker instances when
adding or removing event persisters.

An `event_persister` should not be mistaken for an `event_creator`.
An `event_creator` listens for requests from clients to create new events and does
so. It will then pass those events over HTTP replication to any configured event
persisters (or the main process if none are configured).

Note that `event_creator`s and `event_persister`s are implemented using the same
[`synapse.app.generic_worker`](#synapseappgeneric_worker).

An example [`stream_writers`](usage/configuration/config_documentation.md#stream_writers)
configuration with multiple writers:

```yaml
stream_writers:
    events:
        - event_persister1
        - event_persister2
```

##### The `typing` stream

The following endpoints should be routed directly to the worker configured as
the stream writer for the `typing` stream:

    ^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/typing

##### The `to_device` stream

The following endpoints should be routed directly to the worker configured as
the stream writer for the `to_device` stream:

    ^/_matrix/client/(r0|v3|unstable)/sendToDevice/

##### The `account_data` stream

The following endpoints should be routed directly to the worker configured as
the stream writer for the `account_data` stream:

    ^/_matrix/client/(r0|v3|unstable)/.*/tags
    ^/_matrix/client/(r0|v3|unstable)/.*/account_data

##### The `receipts` stream

The following endpoints should be routed directly to the worker configured as
the stream writer for the `receipts` stream:

    ^/_matrix/client/(r0|v3|unstable)/rooms/.*/receipt
    ^/_matrix/client/(r0|v3|unstable)/rooms/.*/read_markers

##### The `presence` stream

The following endpoints should be routed directly to the worker configured as
the stream writer for the `presence` stream:

    ^/_matrix/client/(api/v1|r0|v3|unstable)/presence/

#### Restrict outbound federation traffic to a specific set of workers

The
[`outbound_federation_restricted_to`](usage/configuration/config_documentation.md#outbound_federation_restricted_to)
configuration is useful to make sure outbound federation traffic only goes through a
specified subset of workers. This allows you to set more strict access controls (like a
firewall) for all workers and only allow the `federation_sender`'s to contact the
outside world.

```yaml
instance_map:
    main:
        host: localhost
        port: 8030
    federation_sender1:
        host: localhost
        port: 8034

outbound_federation_restricted_to:
  - federation_sender1

worker_replication_secret: "secret_secret"
```

#### Background tasks

There is also support for moving background tasks to a separate
worker. Background tasks are run periodically or started via replication. Exactly
which tasks are configured to run depends on your Synapse configuration (e.g. if
stats is enabled). This worker doesn't handle any REST endpoints itself.

To enable this, the worker must have a unique
[`worker_name`](usage/configuration/config_documentation.md#worker_name)
and can be configured to run background tasks. For example, to move background tasks
to a dedicated worker, the shared configuration would include:

```yaml
run_background_tasks_on: background_worker
```

You might also wish to investigate the
[`update_user_directory_from_worker`](#updating-the-user-directory) and
[`media_instance_running_background_jobs`](#synapseappmedia_repository) settings.

An example for a dedicated background worker instance:

```yaml
{{#include systemd-with-workers/workers/background_worker.yaml}}
```

#### Updating the User Directory

You can designate one generic worker to update the user directory.

Specify its name in the [shared configuration](usage/configuration/config_documentation.md#update_user_directory_from_worker)
as follows:

```yaml
update_user_directory_from_worker: worker_name
```

This work cannot be load-balanced; please ensure the main process is restarted
after setting this option in the shared configuration!

User directory updates allow REST endpoints matching the following regular
expressions to work:

    ^/_matrix/client/(r0|v3|unstable)/user_directory/search$

The above endpoints can be routed to any worker, though you may choose to route
it to the chosen user directory worker.

This style of configuration supersedes the legacy `synapse.app.user_dir`
worker application type.


#### Notifying Application Services

You can designate one generic worker to send output traffic to Application Services.
Doesn't handle any REST endpoints itself, but you should specify its name in the
[shared configuration](usage/configuration/config_documentation.md#notify_appservices_from_worker)
as follows:

```yaml
notify_appservices_from_worker: worker_name
```

This work cannot be load-balanced; please ensure the main process is restarted
after setting this option in the shared configuration!

This style of configuration supersedes the legacy `synapse.app.appservice`
worker application type.

#### Push Notifications

You can designate generic worker to sending push notifications to
a [push gateway](https://spec.matrix.org/v1.5/push-gateway-api/) such as
[sygnal](https://github.com/matrix-org/sygnal) and email.

This will stop the main process sending push notifications.

The workers responsible for sending push notifications can be defined using the
[`pusher_instances`](usage/configuration/config_documentation.md#pusher_instances)
option. For example:

```yaml
pusher_instances:
  - pusher_worker1
  - pusher_worker2
```

Multiple workers can be added to this map, in which case the work is balanced
across them. Ensure the main process and all pusher workers are restarted after changing
this option.

These workers don't need to accept incoming HTTP requests to send push notifications,
so no additional reverse proxy configuration is required for pusher workers.

This style of configuration supersedes the legacy `synapse.app.pusher`
worker application type.

### `synapse.app.pusher`

It is likely this option will be deprecated in the future and is not recommended for new
installations. Instead, [use `synapse.app.generic_worker` with the `pusher_instances`](#push-notifications).

Handles sending push notifications to sygnal and email. Doesn't handle any
REST endpoints itself, but you should set
[`start_pushers: false`](usage/configuration/config_documentation.md#start_pushers) in the
shared configuration file to stop the main synapse sending push notifications.

To run multiple instances at once the
[`pusher_instances`](usage/configuration/config_documentation.md#pusher_instances)
option should list all pusher instances by their
[`worker_name`](usage/configuration/config_documentation.md#worker_name), e.g.:

```yaml
start_pushers: false
pusher_instances:
    - pusher_worker1
    - pusher_worker2
```

An example for a pusher instance:

```yaml
{{#include systemd-with-workers/workers/pusher_worker.yaml}}
```


### `synapse.app.appservice`

**Deprecated as of Synapse v1.59.** [Use `synapse.app.generic_worker` with the
`notify_appservices_from_worker` option instead.](#notifying-application-services)

Handles sending output traffic to Application Services. Doesn't handle any
REST endpoints itself, but you should set `notify_appservices: False` in the
shared configuration file to stop the main synapse sending appservice notifications.

Note this worker cannot be load-balanced: only one instance should be active.


### `synapse.app.federation_sender`

It is likely this option will be deprecated in the future and not recommended for
new installations. Instead, [use `synapse.app.generic_worker` with the `federation_sender_instances`](usage/configuration/config_documentation.md#federation_sender_instances).

Handles sending federation traffic to other servers. Doesn't handle any
REST endpoints itself, but you should set
[`send_federation: false`](usage/configuration/config_documentation.md#send_federation)
in the shared configuration file to stop the main synapse sending this traffic.

If running multiple federation senders then you must list each
instance in the
[`federation_sender_instances`](usage/configuration/config_documentation.md#federation_sender_instances)
option by their
[`worker_name`](usage/configuration/config_documentation.md#worker_name).
All instances must be stopped and started when adding or removing instances.
For example:

```yaml
send_federation: false
federation_sender_instances:
    - federation_sender1
    - federation_sender2
```

An example for a federation sender instance:

```yaml
{{#include systemd-with-workers/workers/federation_sender.yaml}}
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
    ^/_synapse/admin/v1/users/.*/media$

You should also set
[`enable_media_repo: False`](usage/configuration/config_documentation.md#enable_media_repo)
in the shared configuration
file to stop the main synapse running background jobs related to managing the
media repository. Note that doing so will prevent the main process from being
able to handle the above endpoints.

In the `media_repository` worker configuration file, configure the
[HTTP listener](usage/configuration/config_documentation.md#listeners) to
expose the `media` resource. For example:

```yaml
{{#include systemd-with-workers/workers/media_worker.yaml}}
```

Note that if running multiple media repositories they must be on the same server
and you must specify a single instance to run the background tasks in the
[shared configuration](usage/configuration/config_documentation.md#media_instance_running_background_jobs),
e.g.:

```yaml
media_instance_running_background_jobs: "media-repository-1"
```

Note that if a reverse proxy is used , then `/_matrix/media/` must be routed for both inbound client and federation requests (if they are handled separately).

### `synapse.app.user_dir`

**Deprecated as of Synapse v1.59.** [Use `synapse.app.generic_worker` with the
`update_user_directory_from_worker` option instead.](#updating-the-user-directory)

Handles searches in the user directory. It can handle REST endpoints matching
the following regular expressions:

    ^/_matrix/client/(r0|v3|unstable)/user_directory/search$

When using this worker you must also set `update_user_directory: false` in the
shared configuration file to stop the main synapse running background
jobs related to updating the user directory.

Above endpoint is not *required* to be routed to this worker. By default,
`update_user_directory` is set to `true`, which means the main process
will handle updates. All workers configured with `client` can handle the above
endpoint as long as either this worker or the main process are configured to
handle it, and are online.

If `update_user_directory` is set to `false`, and this worker is not running,
the above endpoint may give outdated results.

### Historical apps

The following used to be separate worker application types, but are now
equivalent to `synapse.app.generic_worker`:

 * `synapse.app.client_reader`
 * `synapse.app.event_creator`
 * `synapse.app.federation_reader`
 * `synapse.app.federation_sender`
 * `synapse.app.frontend_proxy`
 * `synapse.app.pusher`
 * `synapse.app.synchrotron`


## Migration from old config

A main change that has occurred is the merging of worker apps into
`synapse.app.generic_worker`. This change is backwards compatible and so no
changes to the config are required.

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
      ^    ^          |   ^   |         |   ^   |         |   ^   ^
      |    |          |   |   |         |   |   |         |   |   |
      |    |          |   |   |  HTTP   |   |   |         |   |   |
      |    +----------+<--|---|---------+<--|---|---------+   |   |
      |                   |   +-------------|-->+-------------+   |
      |                   |                 |                     |
      |                   |                 |                     |
      v                   v                 v                     v
======================================================================
                                                         Redis pub/sub channel
```
