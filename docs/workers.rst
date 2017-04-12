Scaling synapse via workers
---------------------------

Synapse has experimental support for splitting out functionality into
multiple separate python processes, helping greatly with scalability.  These
processes are called 'workers', and are (eventually) intended to scale
horizontally independently.

All processes continue to share the same database instance, and as such, workers
only work with postgres based synapse deployments (sharing a single sqlite
across multiple processes is a recipe for disaster, plus you should be using
postgres anyway if you care about scalability).

The workers communicate with the master synapse process via a synapse-specific
TCP protocol called 'replication' - analogous to MySQL or Postgres style
database replication; feeding a stream of relevant data to the workers so they
can be kept in sync with the main synapse process and database state.

To enable workers, you need to add a replication listener to the master synapse, e.g.::

    listeners:
      - port: 9092
        bind_address: '127.0.0.1'
        type: replication

Under **no circumstances** should this replication API listener be exposed to the
public internet; it currently implements no authentication whatsoever and is
unencrypted.

You then create a set of configs for the various worker processes.  These should be
worker configuration files should be stored in a dedicated subdirectory, to allow
synctl to manipulate them.

The current available worker applications are:
 * synapse.app.pusher - handles sending push notifications to sygnal and email
 * synapse.app.synchrotron - handles /sync endpoints.  can scales horizontally through multiple instances.
 * synapse.app.appservice - handles output traffic to Application Services
 * synapse.app.federation_reader - handles receiving federation traffic (including public_rooms API)
 * synapse.app.media_repository - handles the media repository.
 * synapse.app.client_reader - handles client API endpoints like /publicRooms

Each worker configuration file inherits the configuration of the main homeserver
configuration file.  You can then override configuration specific to that worker,
e.g. the HTTP listener that it provides (if any); logging configuration; etc.
You should minimise the number of overrides though to maintain a usable config.

You must specify the type of worker application (worker_app) and the replication
endpoint that it's talking to on the main synapse process (worker_replication_host
and worker_replication_port).

For instance::

    worker_app: synapse.app.synchrotron

    # The replication listener on the synapse to talk to.
    worker_replication_host: 127.0.0.1
    worker_replication_port: 9092

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
plain HTTP /sync endpoint on port 8083 separately from the /sync endpoint provided
by the main synapse.

Obviously you should configure your loadbalancer to route the /sync endpoint to
the synchrotron instance(s) in this instance.

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

All of the above is highly experimental and subject to change as Synapse evolves,
but documenting it here to help folks needing highly scalable Synapses similar
to the one running matrix.org!
