# Structured Logging

A structured logging system can be useful when your logs are destined for a machine to parse and process. By maintaining its machine-readable characteristics, it enables more efficient searching and aggregations when consumed by software such as the "ELK stack".

Synapse's structured logging system is configured via the file that Synapse's `log_config` config option points to. The file must be YAML and contain `structured: true`. It must contain a list of "drains" (places where logs go to).

A structured logging configuration looks similar to the following:

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

The above logging config will set Synapse as 'INFO' logging level by default, with the SQL layer at 'WARNING', and will have two logging drains (to the console and to a file, stored as JSON).

## Drain Types

Drain types can be specified by the `type` key.

### `console`

Outputs human-readable logs to the console.

Arguments:

- `location`: Either `stdout` or `stderr`.

### `console_json`

Outputs machine-readable JSON logs to the console.

Arguments:

- `location`: Either `stdout` or `stderr`.

### `console_json_terse`

Outputs machine-readable JSON logs to the console, separated by newlines. This
format is not designed to be read and re-formatted into human-readable text, but
is optimal for a logging aggregation system.

Arguments:

- `location`: Either `stdout` or `stderr`.

### `file`

Outputs human-readable logs to a file.

Arguments:

- `location`: An absolute path to the file to log to.

### `file_json`

Outputs machine-readable logs to a file.

Arguments:

- `location`: An absolute path to the file to log to.

### `network_json_terse`

Delivers machine-readable JSON logs to a log aggregator over TCP. This is
compatible with LogStash's TCP input with the codec set to `json_lines`.

Arguments:

- `host`: Hostname or IP address of the log aggregator.
- `port`: Numerical port to contact on the host.