# Background Updates API

This API allows a server administrator to manage the background updates being
run against the database.

## Status

This API gets the current status of the background updates.


The API is:

```
GET /_synapse/admin/v1/background_updates/status
```

Returning:

```json
{
    "enabled": true,
    "current_updates": {
        "<db_name>": {
            "name": "<background_update_name>",
            "total_item_count": 50,
            "total_duration_ms": 10000.0,
            "average_items_per_ms": 2.2,
        },
    }
}
```

`enabled` whether the background updates are enabled or disabled.

`db_name` the database name (usually Synapse is configured with a single database named 'master').

For each update:

`name` the name of the update.
`total_item_count` total number of "items" processed (the meaning of 'items' depends on the update in question).
`total_duration_ms` how long the background process has been running, not including time spent sleeping.
`average_items_per_ms` how many items are processed per millisecond based on an exponential average.


## Enabled

This API allow pausing background updates.

Background updates should *not* be paused for significant periods of time, as
this can affect the performance of Synapse.

*Note*: This won't persist over restarts.

*Note*: This won't cancel any update query that is currently running. This is
usually fine since most queries are short lived, except for `CREATE INDEX`
background updates which won't be cancelled once started.


The API is:

```
POST /_synapse/admin/v1/background_updates/enabled
```

with the following body:

```json
{
    "enabled": false
}
```

`enabled` sets whether the background updates are enabled or disabled.

The API returns the `enabled` param.

```json
{
    "enabled": false
}
```

There is also a `GET` version which returns the `enabled` state.


## Run

This API schedules a specific background update to run. The job starts immediately after calling the API.


The API is:

```
POST /_synapse/admin/v1/background_updates/start_job
```

with the following body:

```json
{
    "job_name": "populate_stats_process_rooms"
}
```

The following JSON body parameters are available:

- `job_name` - A string which job to run. Valid values are:
  - `populate_stats_process_rooms` - Recalculate the stats for all rooms.
  - `regenerate_directory` - Recalculate the [user directory](../../../user_directory.md) if it is stale or out of sync.
