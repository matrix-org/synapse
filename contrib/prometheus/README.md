This directory contains some sample monitoring config for using the
'Prometheus' monitoring server against synapse.

To use it, first install prometheus by following the instructions at

  http://prometheus.io/

### for Prometheus v1

Add a new job to the main prometheus.conf file:

```yaml
  job: {
    name: "synapse"

    target_group: {
      target: "http://SERVER.LOCATION.HERE:PORT/_synapse/metrics"
    }
  }
```

### for Prometheus v2

Add a new job to the main prometheus.yml file:

```yaml
  - job_name: "synapse"
    metrics_path: "/_synapse/metrics"
    # when endpoint uses https:
    scheme: "https"

    static_configs:
    - targets: ["my.server.here:port"]
```

An example of a Prometheus configuration with workers can be found in
[metrics-howto.md](https://github.com/matrix-org/synapse/blob/master/docs/metrics-howto.md).

To use `synapse.rules` add

```yaml
  rule_files:
    - "/PATH/TO/synapse-v2.rules"
```

Metrics are disabled by default when running synapse; they must be enabled
with the 'enable-metrics' option, either in the synapse config file or as a
command-line option.
