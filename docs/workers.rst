Scaling synapse via workers
===========================

Synapse has experimental support for splitting out functionality into
multiple separate python processes, helping greatly with scalability.  These
processes are called 'workers', and are (eventually) intended to scale
horizontally independently.

All of the below is highly experimental and subject to change as Synapse evolves,
but documenting it here to help folks needing highly scalable Synapses similar
to the one running matrix.org!

All processes continue to share the same database instance, and as such, workers
only work with postgres based synapse deployments (sharing a single sqlite
across multiple processes is a recipe for disaster, plus you should be using
postgres anyway if you care about scalability).

The workers communicate with the master synapse process via a synapse-specific
TCP protocol called 'replication' - analogous to MySQL or Postgres style
database replication; feeding a stream of relevant data to the workers so they
can be kept in sync with the main synapse process and database state.

Configuration
-------------

To make effective use of the workers, you will need to configure an HTTP
reverse-proxy such as nginx or haproxy, which will direct incoming requests to
the correct worker, or to the main synapse instance. Note that this includes
requests made to the federation port. See `<reverse_proxy.rst>`_ for
information on setting up a reverse proxy.

To enable workers, you need to add two replication listeners to the master
synapse, e.g.::

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

Under **no circumstances** should these replication API listeners be exposed to
the public internet; it currently implements no authentication whatsoever and is
unencrypted.

(Roughly, the TCP port is used for streaming data from the master to the
workers, and the HTTP port for the workers to send data to the main
synapse process.)

You then create a set of configs for the various worker processes.  These
should be worker configuration files, and should be stored in a dedicated
subdirectory, to allow synctl to manipulate them. An additional configuration
for the master synapse process will need to be created because the process will
not be started automatically. That configuration should look like this::

    worker_app: synapse.app.homeserver
    daemonize: true

Each worker configuration file inherits the configuration of the main homeserver
configuration file.  You can then override configuration specific to that worker,
e.g. the HTTP listener that it provides (if any); logging configuration; etc.
You should minimise the number of overrides though to maintain a usable config.

You must specify the type of worker application (``worker_app``). The currently
available worker applications are listed below. You must also specify the
replication endpoints that it's talking to on the main synapse process.
``worker_replication_host`` should specify the host of the main synapse,
``worker_replication_port`` should point to the TCP replication listener port and
``worker_replication_http_port`` should point to the HTTP replication port.

Currently, the ``event_creator`` and ``federation_reader`` workers require specifying
``worker_replication_http_port``.

For instance::

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

    worker_daemonize: True
    worker_pid_file: /home/matrix/synapse/synchrotron.pid
    worker_log_config: /home/matrix/synapse/config/synchrotron_log_config.yaml

...is a full configuration for a synchrotron worker instance, which will expose a
plain HTTP ``/sync`` endpoint on port 8083 separately from the ``/sync`` endpoint provided
by the main synapse.

Obviously you should configure your reverse-proxy to route the relevant
endpoints to the worker (``localhost:8083`` in the above example).

Finally, to actually run your worker-based synapse, you must pass synctl the -a
commandline option to tell it to operate on all the worker configurations found
in the given directory, e.g.::

    synctl -a $CONFIG/workers start

Currently one should always restart all workers when restarting or upgrading
synapse, unless you explicitly know it's safe not to.  For instance, restarting
synapse without restarting all the synchrotrons may result in broken typing
notifications.

To manipulate a specific worker, you pass the -w option to synctl::

    synctl -w $CONFIG/workers/synchrotron.yaml restart


Available worker applications
-----------------------------

``synapse.app.pusher``
~~~~~~~~~~~~~~~~~~~~~~

Handles sending push notifications to sygnal and email. Doesn't handle any
REST endpoints itself, but you should set ``start_pushers: False`` in the
shared configuration file to stop the main synapse sending these notifications.

Note this worker cannot be load-balanced: only one instance should be active.

``synapse.app.synchrotron``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The synchrotron handles ``sync`` requests from clients. In particular, it can
handle REST endpoints matching the following regular expressions::

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

``synapse.app.appservice``
~~~~~~~~~~~~~~~~~~~~~~~~~~

Handles sending output traffic to Application Services. Doesn't handle any
REST endpoints itself, but you should set ``notify_appservices: False`` in the
shared configuration file to stop the main synapse sending these notifications.

Note this worker cannot be load-balanced: only one instance should be active.

``synapse.app.federation_reader``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Handles a subset of federation endpoints. In particular, it can handle REST
endpoints matching the following regular expressions::

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
    ^/_matrix/federation/v1/send_leave/
    ^/_matrix/federation/v1/invite/
    ^/_matrix/federation/v1/query_auth/
    ^/_matrix/federation/v1/event_auth/
    ^/_matrix/federation/v1/exchange_third_party_invite/
    ^/_matrix/federation/v1/send/
    ^/_matrix/key/v2/query

The above endpoints should all be routed to the federation_reader worker by the
reverse-proxy configuration.

The `^/_matrix/federation/v1/send/` endpoint must only be handled by a single
instance.

``synapse.app.federation_sender``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Handles sending federation traffic to other servers. Doesn't handle any
REST endpoints itself, but you should set ``send_federation: False`` in the
shared configuration file to stop the main synapse sending this traffic.

Note this worker cannot be load-balanced: only one instance should be active.

``synapse.app.media_repository``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Handles the media repository. It can handle all endpoints starting with::

    /_matrix/media/

You should also set ``enable_media_repo: False`` in the shared configuration
file to stop the main synapse running background jobs related to managing the
media repository.

Note this worker cannot be load-balanced: only one instance should be active.

``synapse.app.client_reader``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Handles client API endpoints. It can handle REST endpoints matching the
following regular expressions::

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

Additionally, the following REST endpoints can be handled for GET requests::

    ^/_matrix/client/(api/v1|r0|unstable)/pushrules/.*$

Additionally, the following REST endpoints can be handled, but all requests must
be routed to the same instance::

    ^/_matrix/client/(r0|unstable)/register$

Pagination requests can also be handled, but all requests with the same path
room must be routed to the same instance. Additionally, care must be taken to
ensure that the purge history admin API is not used while pagination requests
for the room are in flight::

    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/messages$


``synapse.app.user_dir``
~~~~~~~~~~~~~~~~~~~~~~~~

Handles searches in the user directory. It can handle REST endpoints matching
the following regular expressions::

    ^/_matrix/client/(api/v1|r0|unstable)/user_directory/search$

``synapse.app.frontend_proxy``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Proxies some frequently-requested client endpoints to add caching and remove
load from the main synapse. It can handle REST endpoints matching the following
regular expressions::

    ^/_matrix/client/(api/v1|r0|unstable)/keys/upload

If ``use_presence`` is False in the homeserver config, it can also handle REST
endpoints matching the following regular expressions::

    ^/_matrix/client/(api/v1|r0|unstable)/presence/[^/]+/status

This "stub" presence handler will pass through ``GET`` request but make the
``PUT`` effectively a no-op.

It will proxy any requests it cannot handle to the main synapse instance. It
must therefore be configured with the location of the main instance, via
the ``worker_main_http_uri`` setting in the frontend_proxy worker configuration
file. For example::

    worker_main_http_uri: http://127.0.0.1:8008


``synapse.app.event_creator``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Handles some event creation. It can handle REST endpoints matching::

    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/send
    ^/_matrix/client/(api/v1|r0|unstable)/rooms/.*/(join|invite|leave|ban|unban|kick)$
    ^/_matrix/client/(api/v1|r0|unstable)/join/
    ^/_matrix/client/(api/v1|r0|unstable)/profile/

It will create events locally and then send them on to the main synapse
instance to be persisted and handled.
