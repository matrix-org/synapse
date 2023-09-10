# Structured Logging

A structured logging system can be useful when your logs are destined for a
machine to parse and process. By maintaining its machine-readable characteristics,
it enables more efficient searching and aggregations when consumed by software
such as the [ELK stack](https://opensource.com/article/18/9/open-source-log-aggregation-tools).

Synapse's structured logging system is configured via the file that Synapse's
`log_config` config option points to. The file should include a formatter which
uses the `synapse.logging.TerseJsonFormatter` class included with Synapse and a
handler which uses the above formatter.

There is also a `synapse.logging.JsonFormatter` option which does not include
a timestamp in the resulting JSON. This is useful if the log ingester adds its
own timestamp.

A structured logging configuration looks similar to the following:

```yaml
version: 1

formatters:
    structured:
        class: synapse.logging.TerseJsonFormatter

handlers:
    file:
        class: logging.handlers.TimedRotatingFileHandler
        formatter: structured
        filename: /path/to/my/logs/homeserver.log
        when: midnight
        backupCount: 3  # Does not include the current log file.
        encoding: utf8

loggers:
    synapse:
        level: INFO
        handlers: [remote]
    synapse.storage.SQL:
        level: WARNING
```

The above logging config will set Synapse as 'INFO' logging level by default,
with the SQL layer at 'WARNING', and will log to a file, stored as JSON.

It is also possible to configure Synapse to log to a remote endpoint by using the
`synapse.logging.RemoteHandler` class included with Synapse. It takes the
following arguments:

- `host`: Hostname or IP address of the log aggregator.
- `port`: Numerical port to contact on the host.
- `maximum_buffer`: (Optional, defaults to 1000) The maximum buffer size to allow.

A remote structured logging configuration looks similar to the following:

```yaml
version: 1

formatters:
    structured:
        class: synapse.logging.TerseJsonFormatter

handlers:
    remote:
        class: synapse.logging.RemoteHandler
        formatter: structured
        host: 10.1.2.3
        port: 9999

loggers:
    synapse:
        level: INFO
        handlers: [remote]
    synapse.storage.SQL:
        level: WARNING
```

The above logging config will set Synapse as 'INFO' logging level by default,
with the SQL layer at 'WARNING', and will log JSON formatted messages to a
remote endpoint at 10.1.2.3:9999.
