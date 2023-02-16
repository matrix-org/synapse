# Purge History API

The purge history API allows server admins to purge historic events from their
database, reclaiming disk space.

Depending on the amount of history being purged a call to the API may take
several minutes or longer. During this period users will not be able to
paginate further back in the room from the point being purged from.

Note that Synapse requires at least one message in each room, so it will never
delete the last message in a room.

To use it, you will need to authenticate by providing an `access_token`
for a server admin: see [Admin API](../usage/administration/admin_api/).

The API is:

```
POST /_synapse/admin/v1/purge_history/<room_id>[/<event_id>]
```

By default, events sent by local users are not deleted, as they may represent
the only copies of this content in existence. (Events sent by remote users are
deleted.)

Room state data (such as joins, leaves, topic) is always preserved.

To delete local message events as well, set `delete_local_events` in the body:

```json
{
   "delete_local_events": true
}
```

The caller must specify the point in the room to purge up to. This can be
specified by including an event_id in the URI, or by setting a
`purge_up_to_event_id` or `purge_up_to_ts` in the request body. If an event
id is given, that event (and others at the same graph depth) will be retained.
If `purge_up_to_ts` is given, it should be a timestamp since the unix epoch,
in milliseconds.

The API starts the purge running, and returns immediately with a JSON body with
a purge id:

```json
{
    "purge_id": "<opaque id>"
}
```

## Purge status query

It is possible to poll for updates on recent purges with a second API;

```
GET /_synapse/admin/v1/purge_history_status/<purge_id>
```

This API returns a JSON body like the following:

```json
{
    "status": "active"
}
```

The status will be one of `active`, `complete`, or `failed`.

If `status` is `failed` there will be a string `error` with the error message.

## Reclaim disk space (Postgres)

To reclaim the disk space and return it to the operating system, you need to run
`VACUUM FULL;` on the database.

<https://www.postgresql.org/docs/current/sql-vacuum.html>
