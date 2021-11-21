# Structured Logging

A structured logging system can be useful when your logs are destined for a
machine to parse and process. By maintaining its machine-readable characteristics,
it enables more efficient searching and aggregations when consumed by software
such as the "ELK stack".

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

It is also possible to figure Synapse to log to a remote endpoint by using the
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

## Upgrading from legacy structured logging configuration

Versions of Synapse prior to v1.23.0 included a custom structured logging
configuration which is deprecated. It used a `structured: true` flag and
configured `drains` instead of ``handlers`` and `formatters`.

Synapse currently automatically converts the old configuration to the new
configuration, but this will be removed in a future version of Synapse. The
following reference can be used to update your configuration. Based on the drain
`type`, we can pick a new handler:

1. For a type of `console`, `console_json`, or `console_json_terse`: a handler
   with a class of `logging.StreamHandler` and a `stream` of `ext://sys.stdout`
   or `ext://sys.stderr` should be used.
2. For a type of `file` or `file_json`: a handler of `logging.FileHandler` with
   a location of the file path should be used.
3. For a type of `network_json_terse`: a handler of `synapse.logging.RemoteHandler`
   with the host and port should be used.

Then based on the drain `type` we can pick a new formatter:

1. For a type of `console` or `file` no formatter is necessary.
2. For a type of `console_json` or `file_json`: a formatter of
   `synapse.logging.JsonFormatter` should be used.
3. For a type of `console_json_terse` or `network_json_terse`: a formatter of
   `synapse.logging.TerseJsonFormatter` should be used.

For each new handler and formatter they should be added to the logging configuration
and then assigned to either a logger or the root logger.

An example legacy configuration:

```yaml
structured: true

loggers:
    synapse:
        level: INFO
    synapse.storage.SQL:
        level: WARNING

drains:
    console:
        type: console
        location: stdout
    file:
        type: file_json
        location: homeserver.log
```

Would be converted into a new configuration:

```yaml
version: 1

formatters:
    json:
        class: synapse.logging.JsonFormatter

handlers:
    console:
        class: logging.StreamHandler
        location: ext://sys.stdout
    file:
        class: logging.FileHandler
        formatter: json
        filename: homeserver.log

loggers:
    synapse:
        level: INFO
        handlers: [console, file]
    synapse.storage.SQL:
        level: WARNING
```

The new logging configuration is a bit more verbose, but significantly more
flexible. It allows for configuration that were not previously possible, such as
sending plain logs over the network, or using different handlers for different
modules.
