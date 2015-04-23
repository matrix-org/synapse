How to monitor Synapse metrics using Prometheus
===============================================

1: install prometheus:
  Follow instructions at http://prometheus.io/docs/introduction/install/

2: enable synapse metrics:
  Simply setting a (local) port number will enable it. Pick a port.
  prometheus itself defaults to 9090, so starting just above that for
  locally monitored services seems reasonable. E.g. 9092:

  Add to homeserver.yaml

    metrics_port: 9092

  Restart synapse

3: check out synapse-prometheus-config
  https://github.com/matrix-org/synapse-prometheus-config

4: arrange for synapse.html to appear in prometheus's "consoles"
   directory - symlink might be easiest to ensure `git pull` keeps it
   updated.

5: arrange for synapse.rules to be invoked from the main
   prometheus.conf and add a synapse target. This is easiest if
   prometheus runs on the same machine as synapse, as it can then just
   use localhost::

    global: {
      rule_file: "synapse.rules"
    }

    job: {
      name: "synapse"

      target_group: {
        target: "http://localhost:9092/"
      }
    }

6: start prometheus::

   ./prometheus -config.file=prometheus.conf

7: wait a few seconds for it to start and perform the first scrape,
   then visit the console:

    http://server-where-prometheus-runs:9090/consoles/synapse.html
