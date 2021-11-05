# Background Updates API

This API allows a server administrator to manage the background updates being
run against the database.

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
    "enabled": 0
}
```

There is also a `GET` version which returns the `enabled` state.
