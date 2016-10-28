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

3: Add a prometheus target for synapse. It needs to set the ``metrics_path``
   to a non-default value::

    - job_name: "synapse"
      metrics_path: "/_synapse/metrics"
      static_configs:
        - targets:
            "my.server.here:9092"
