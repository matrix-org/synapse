# Federation API

This API allows a server administrator to manage Synapse's federation with other homeservers.

Note: This API is new, experimental and "subject to change".

## List of destinations

This API gets the current destination retry timing info for all remote servers.

The list contains all the servers with which the server federates,
regardless of whether an error occurred or not.
If an error occurs, it may take up to 20 minutes for the error to be displayed here,
as a complete retry must have failed.

The API is:

A standard request with no filtering:

```
GET /_synapse/admin/v1/federation/destinations
```

A response body like the following is returned:

```json
{
   "destinations":[
      {
         "destination": "matrix.org",
         "retry_last_ts": 1557332397936,
         "retry_interval": 3000000,
         "failure_ts": 1557329397936,
         "last_successful_stream_ordering": null
      }
   ],
   "total": 1
}
```

To paginate, check for `next_token` and if present, call the endpoint again
with `from` set to the value of `next_token`. This will return a new page.

If the endpoint does not return a `next_token` then there are no more destinations
to paginate through.

**Parameters**

The following query parameters are available:

- `from` - Offset in the returned list. Defaults to `0`.
- `limit` - Maximum amount of destinations to return. Defaults to `100`.
- `order_by` - The method in which to sort the returned list of destinations.
  Valid values are:
  - `destination` - Destinations are ordered alphabetically by remote server name.
    This is the default.
  - `retry_last_ts` - Destinations are ordered by time of last retry attempt in ms.
  - `retry_interval` - Destinations are ordered by how long until next retry in ms.
  - `failure_ts` - Destinations are ordered by when the server started failing in ms.
  - `last_successful_stream_ordering` - Destinations are ordered by the stream ordering
    of the most recent successfully-sent PDU.
- `dir` - Direction of room order. Either `f` for forwards or `b` for backwards. Setting
  this value to `b` will reverse the above sort order. Defaults to `f`.

*Caution:* The database only has an index on the column `destination`.
This means that if a different sort order is used,
this can cause a large load on the database, especially for large environments.

**Response**

The following fields are returned in the JSON response body:

- `destinations` - An array of objects, each containing information about a destination.
  Destination objects contain the following fields:
  - `destination` - string - Name of the remote server to federate.
  - `retry_last_ts` - integer - The last time Synapse tried and failed to reach the
    remote server, in ms. This is `0` if the last attempt to communicate with the
    remote server was successful.
  - `retry_interval` - integer - How long since the last time Synapse tried to reach
    the remote server before trying again, in ms. This is `0` if no further retrying occurring.
  - `failure_ts` - nullable integer - The first time Synapse tried and failed to reach the
    remote server, in ms. This is `null` if communication with the remote server has never failed.
  - `last_successful_stream_ordering` - nullable integer - The stream ordering of the most
    recent successfully-sent [PDU](../understanding_synapse_through_grafana_graphs.md#federation)
    to this destination, or `null` if this information has not been tracked yet.
- `next_token`: string representing a positive integer - Indication for pagination. See above.
- `total` - integer - Total number of destinations.

## Destination Details API

This API gets the retry timing info for a specific remote server.

The API is:

```
GET /_synapse/admin/v1/federation/destinations/<destination>
```

A response body like the following is returned:

```json
{
   "destination": "matrix.org",
   "retry_last_ts": 1557332397936,
   "retry_interval": 3000000,
   "failure_ts": 1557329397936,
   "last_successful_stream_ordering": null
}
```

**Parameters**

The following parameters should be set in the URL:

- `destination` - Name of the remote server.

**Response**

The response fields are the same like in the `destinations` array in
[List of destinations](#list-of-destinations) response.

## Destination rooms

This API gets the rooms that federate with a specific remote server.

The API is:

```
GET /_synapse/admin/v1/federation/destinations/<destination>/rooms
```

A response body like the following is returned:

```json
{
   "rooms":[
      {
         "room_id": "!OGEhHVWSdvArJzumhm:matrix.org",
         "stream_ordering": 8326
      },
      {
         "room_id": "!xYvNcQPhnkrdUmYczI:matrix.org",
         "stream_ordering": 93534
      }
   ],
   "total": 2
}
```

To paginate, check for `next_token` and if present, call the endpoint again
with `from` set to the value of `next_token`. This will return a new page.

If the endpoint does not return a `next_token` then there are no more destinations
to paginate through.

**Parameters**

The following parameters should be set in the URL:

- `destination` - Name of the remote server.

The following query parameters are available:

- `from` - Offset in the returned list. Defaults to `0`.
- `limit` - Maximum amount of destinations to return. Defaults to `100`.
- `dir` - Direction of room order by `room_id`. Either `f` for forwards or `b` for
  backwards. Defaults to `f`.

**Response**

The following fields are returned in the JSON response body:

- `rooms` - An array of objects, each containing information about a room.
  Room objects contain the following fields:
  - `room_id` - string - The ID of the room.
  - `stream_ordering` - integer -  The stream ordering of the most recent
    successfully-sent [PDU](../understanding_synapse_through_grafana_graphs.md#federation)
    to this destination in this room.
- `next_token`: string representing a positive integer - Indication for pagination. See above.
- `total` - integer - Total number of destinations.

## Reset connection timeout

Synapse makes federation requests to other homeservers. If a federation request fails,
Synapse will mark the destination homeserver as offline, preventing any future requests
to that server for a "cooldown" period. This period grows over time if the server
continues to fail its responses
([exponential backoff](https://en.wikipedia.org/wiki/Exponential_backoff)).

Admins can cancel the cooldown period with this API.

This API resets the retry timing for a specific remote server and tries to connect to
the remote server again. It does not wait for the next `retry_interval`.
The connection must have previously run into an error and `retry_last_ts`
([Destination Details API](#destination-details-api)) must not be equal to `0`.

The connection attempt is carried out in the background and can take a while
even if the API already returns the http status 200.

The API is:

```
POST /_synapse/admin/v1/federation/destinations/<destination>/reset_connection

{}
```

**Parameters**

The following parameters should be set in the URL:

- `destination` - Name of the remote server.
