How to monitor Synapse metrics using Prometheus
===============================================

1: Install prometheus:
  Follow instructions at http://prometheus.io/docs/introduction/install/

2: Enable synapse metrics:
  Simply setting a (local) port number will enable it. Pick a port.
  prometheus itself defaults to 9090, so starting just above that for
  locally monitored services seems reasonable. E.g. 9092:

  Add to homeserver.yaml

    metrics_port: 9092

  Restart synapse

3: Check out synapse-prometheus-config
  https://github.com/matrix-org/synapse-prometheus-config

4: Add ``synapse.html`` and ``synapse.rules``
  The ``.html`` file needs to appear in prometheus's ``consoles`` directory,
  and the ``.rules`` file needs to be invoked somewhere in the main config
  file. A symlink to each from the git checkout into the prometheus directory
  might be easiest to ensure ``git pull`` keeps it updated.

5: Add a prometheus target for synapse
  This is easiest if prometheus runs on the same machine as synapse, as it can
  then just use localhost::

    global: {
      rule_file: "synapse.rules"
    }

    job: {
      name: "synapse"

      target_group: {
        target: "http://localhost:9092/"
      }
    }

6: Start prometheus::

   ./prometheus -config.file=prometheus.conf

7: Wait a few seconds for it to start and perform the first scrape,
   then visit the console:

    http://server-where-prometheus-runs:9090/consoles/synapse.html
