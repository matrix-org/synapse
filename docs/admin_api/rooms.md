# List Room API

The List Room admin API allows server admins to get a list of rooms on their
server. There are various parameters available that allow for filtering and
sorting the returned list. This API supports pagination.

To use it, you will need to authenticate by providing an `access_token`
for a server admin: see [Admin API](../usage/administration/admin_api/).

**Parameters**

The following query parameters are available:

* `from` - Offset in the returned list. Defaults to `0`.
* `limit` - Maximum amount of rooms to return. Defaults to `100`.
* `order_by` - The method in which to sort the returned list of rooms. Valid values are:
  - `alphabetical` - Same as `name`. This is deprecated.
  - `size` - Same as `joined_members`. This is deprecated.
  - `name` - Rooms are ordered alphabetically by room name. This is the default.
  - `canonical_alias` - Rooms are ordered alphabetically by main alias address of the room.
  - `joined_members` - Rooms are ordered by the number of members. Largest to smallest.
  - `joined_local_members` - Rooms are ordered by the number of local members. Largest to smallest.
  - `version` - Rooms are ordered by room version. Largest to smallest.
  - `creator` - Rooms are ordered alphabetically by creator of the room.
  - `encryption` - Rooms are ordered alphabetically by the end-to-end encryption algorithm.
  - `federatable` - Rooms are ordered by whether the room is federatable.
  - `public` - Rooms are ordered by visibility in room list.
  - `join_rules` - Rooms are ordered alphabetically by join rules of the room.
  - `guest_access` - Rooms are ordered alphabetically by guest access option of the room.
  - `history_visibility` - Rooms are ordered alphabetically by visibility of history of the room.
  - `state_events` - Rooms are ordered by number of state events. Largest to smallest.
* `dir` - Direction of room order. Either `f` for forwards or `b` for backwards. Setting
  this value to `b` will reverse the above sort order. Defaults to `f`.
* `search_term` - Filter rooms by their room name, canonical alias and room id.
  Specifically, rooms are selected if the search term is contained in
  - the room's name,
  - the local part of the room's canonical alias, or
  - the complete (local and server part) room's id (case sensitive).

  Defaults to no filtering.

**Response**

The following fields are possible in the JSON response body:

* `rooms` - An array of objects, each containing information about a room.
  - Room objects contain the following fields:
    - `room_id` - The ID of the room.
    - `name` - The name of the room.
    - `canonical_alias` - The canonical (main) alias address of the room.
    - `joined_members` - How many users are currently in the room.
    - `joined_local_members` - How many local users are currently in the room.
    - `version` - The version of the room as a string.
    - `creator` - The `user_id` of the room creator.
    - `encryption` - Algorithm of end-to-end encryption of messages. Is `null` if encryption is not active.
    - `federatable` - Whether users on other servers can join this room.
    - `public` - Whether the room is visible in room directory.
    - `join_rules` - The type of rules used for users wishing to join this room. One of: ["public", "knock", "invite", "private"].
    - `guest_access` - Whether guests can join the room. One of: ["can_join", "forbidden"].
    - `history_visibility` - Who can see the room history. One of: ["invited", "joined", "shared", "world_readable"].
    - `state_events` - Total number of state_events of a room. Complexity of the room.
    - `room_type` - The type of the room taken from the room's creation event; for example "m.space" if the room is a space. If the room does not define a type, the value will be `null`.
* `offset` - The current pagination offset in rooms. This parameter should be
             used instead of `next_token` for room offset as `next_token` is
             not intended to be parsed.
* `total_rooms` - The total number of rooms this query can return. Using this
                  and `offset`, you have enough information to know the current
                  progression through the list.
* `next_batch` - If this field is present, we know that there are potentially
                 more rooms on the server that did not all fit into this response.
                 We can use `next_batch` to get the "next page" of results. To do
                 so, simply repeat your request, setting the `from` parameter to
                 the value of `next_batch`.
* `prev_batch` - If this field is present, it is possible to paginate backwards.
                 Use `prev_batch` for the `from` value in the next request to
                 get the "previous page" of results.

The API is:

A standard request with no filtering:

```
GET /_synapse/admin/v1/rooms
```

A response body like the following is returned:

```json
{
  "rooms": [
    {
      "room_id": "!OGEhHVWSdvArJzumhm:matrix.org",
      "name": "Matrix HQ",
      "canonical_alias": "#matrix:matrix.org",
      "joined_members": 8326,
      "joined_local_members": 2,
      "version": "1",
      "creator": "@foo:matrix.org",
      "encryption": null,
      "federatable": true,
      "public": true,
      "join_rules": "invite",
      "guest_access": null,
      "history_visibility": "shared",
      "state_events": 93534,
      "room_type": "m.space"
    },
    ... (8 hidden items) ...
    {
      "room_id": "!xYvNcQPhnkrdUmYczI:matrix.org",
      "name": "This Week In Matrix (TWIM)",
      "canonical_alias": "#twim:matrix.org",
      "joined_members": 314,
      "joined_local_members": 20,
      "version": "4",
      "creator": "@foo:matrix.org",
      "encryption": "m.megolm.v1.aes-sha2",
      "federatable": true,
      "public": false,
      "join_rules": "invite",
      "guest_access": null,
      "history_visibility": "shared",
      "state_events": 8345,
      "room_type": null
    }
  ],
  "offset": 0,
  "total_rooms": 10
}
```

Filtering by room name:

```
GET /_synapse/admin/v1/rooms?search_term=TWIM
```

A response body like the following is returned:

```json
{
  "rooms": [
    {
      "room_id": "!xYvNcQPhnkrdUmYczI:matrix.org",
      "name": "This Week In Matrix (TWIM)",
      "canonical_alias": "#twim:matrix.org",
      "joined_members": 314,
      "joined_local_members": 20,
      "version": "4",
      "creator": "@foo:matrix.org",
      "encryption": "m.megolm.v1.aes-sha2",
      "federatable": true,
      "public": false,
      "join_rules": "invite",
      "guest_access": null,
      "history_visibility": "shared",
      "state_events": 8,
      "room_type": null
    }
  ],
  "offset": 0,
  "total_rooms": 1
}
```

Paginating through a list of rooms:

```
GET /_synapse/admin/v1/rooms?order_by=size
```

A response body like the following is returned:

```json
{
  "rooms": [
    {
      "room_id": "!OGEhHVWSdvArJzumhm:matrix.org",
      "name": "Matrix HQ",
      "canonical_alias": "#matrix:matrix.org",
      "joined_members": 8326,
      "joined_local_members": 2,
      "version": "1",
      "creator": "@foo:matrix.org",
      "encryption": null,
      "federatable": true,
      "public": true,
      "join_rules": "invite",
      "guest_access": null,
      "history_visibility": "shared",
      "state_events": 93534,
      "room_type": null
    },
    ... (98 hidden items) ...
    {
      "room_id": "!xYvNcQPhnkrdUmYczI:matrix.org",
      "name": "This Week In Matrix (TWIM)",
      "canonical_alias": "#twim:matrix.org",
      "joined_members": 314,
      "joined_local_members": 20,
      "version": "4",
      "creator": "@foo:matrix.org",
      "encryption": "m.megolm.v1.aes-sha2",
      "federatable": true,
      "public": false,
      "join_rules": "invite",
      "guest_access": null,
      "history_visibility": "shared",
      "state_events": 8345,
      "room_type": "m.space"
    }
  ],
  "offset": 0,
  "total_rooms": 150,
  "next_token": 100
}
```

The presence of the `next_token` parameter tells us that there are more rooms
than returned in this request, and we need to make another request to get them.
To get the next batch of room results, we repeat our request, setting the `from`
parameter to the value of `next_token`.

```
GET /_synapse/admin/v1/rooms?order_by=size&from=100
```

A response body like the following is returned:

```json
{
  "rooms": [
    {
      "room_id": "!mscvqgqpHYjBGDxNym:matrix.org",
      "name": "Music Theory",
      "canonical_alias": "#musictheory:matrix.org",
      "joined_members": 127,
      "joined_local_members": 2,
      "version": "1",
      "creator": "@foo:matrix.org",
      "encryption": null,
      "federatable": true,
      "public": true,
      "join_rules": "invite",
      "guest_access": null,
      "history_visibility": "shared",
      "state_events": 93534,
      "room_type": "m.space"

    },
    ... (48 hidden items) ...
    {
      "room_id": "!twcBhHVdZlQWuuxBhN:termina.org.uk",
      "name": "weechat-matrix",
      "canonical_alias": "#weechat-matrix:termina.org.uk",
      "joined_members": 137,
      "joined_local_members": 20,
      "version": "4",
      "creator": "@foo:termina.org.uk",
      "encryption": null,
      "federatable": true,
      "public": true,
      "join_rules": "invite",
      "guest_access": null,
      "history_visibility": "shared",
      "state_events": 8345,
      "room_type": null

    }
  ],
  "offset": 100,
  "prev_batch": 0,
  "total_rooms": 150
}
```

Once the `next_token` parameter is no longer present, we know we've reached the
end of the list.

# Room Details API

The Room Details admin API allows server admins to get all details of a room.

The following fields are possible in the JSON response body:

* `room_id` - The ID of the room.
* `name` - The name of the room.
* `topic` - The topic of the room.
* `avatar` - The `mxc` URI to the avatar of the room.
* `canonical_alias` - The canonical (main) alias address of the room.
* `joined_members` - How many users are currently in the room.
* `joined_local_members` - How many local users are currently in the room.
* `joined_local_devices` - How many local devices are currently in the room.
* `version` - The version of the room as a string.
* `creator` - The `user_id` of the room creator.
* `encryption` - Algorithm of end-to-end encryption of messages. Is `null` if encryption is not active.
* `federatable` - Whether users on other servers can join this room.
* `public` - Whether the room is visible in room directory.
* `join_rules` - The type of rules used for users wishing to join this room. One of: ["public", "knock", "invite", "private"].
* `guest_access` - Whether guests can join the room. One of: ["can_join", "forbidden"].
* `history_visibility` - Who can see the room history. One of: ["invited", "joined", "shared", "world_readable"].
* `state_events` - Total number of state_events of a room. Complexity of the room.
* `room_type` - The type of the room taken from the room's creation event; for example "m.space" if the room is a space.
  If the room does not define a type, the value will be `null`.
* `forgotten` - Whether all local users have
  [forgotten](https://spec.matrix.org/latest/client-server-api/#leaving-rooms) the room.

The API is:

```
GET /_synapse/admin/v1/rooms/<room_id>
```

A response body like the following is returned:

```json
{
  "room_id": "!mscvqgqpHYjBGDxNym:matrix.org",
  "name": "Music Theory",
  "avatar": "mxc://matrix.org/AQDaVFlbkQoErdOgqWRgiGSV",
  "topic": "Theory, Composition, Notation, Analysis",
  "canonical_alias": "#musictheory:matrix.org",
  "joined_members": 127,
  "joined_local_members": 2,
  "joined_local_devices": 2,
  "version": "1",
  "creator": "@foo:matrix.org",
  "encryption": null,
  "federatable": true,
  "public": true,
  "join_rules": "invite",
  "guest_access": null,
  "history_visibility": "shared",
  "state_events": 93534,
  "room_type": "m.space",
  "forgotten": false
}
```

_Changed in Synapse 1.66:_ Added the `forgotten` key to the response body.

# Room Members API

The Room Members admin API allows server admins to get a list of all members of a room.

The response includes the following fields:

* `members` - A list of all the members that are present in the room, represented by their ids.
* `total` - Total number of members in the room.

The API is:

```
GET /_synapse/admin/v1/rooms/<room_id>/members
```

A response body like the following is returned:

```json
{
  "members": [
    "@foo:matrix.org",
    "@bar:matrix.org",
    "@foobar:matrix.org"
  ],
  "total": 3
}
```

# Room State API

The Room State admin API allows server admins to get a list of all state events in a room.

The response includes the following fields:

* `state` - The current state of the room at the time of request.

The API is:

```
GET /_synapse/admin/v1/rooms/<room_id>/state
```

A response body like the following is returned:

```json
{
  "state": [
    {"type": "m.room.create", "state_key": "", "etc": true},
    {"type": "m.room.power_levels", "state_key": "", "etc": true},
    {"type": "m.room.name", "state_key": "", "etc": true}
  ]
}
```

# Room Messages API

The Room Messages admin API allows server admins to get all messages
sent to a room in a given timeframe. There are various parameters available
that allow for filtering and ordering the returned list. This API supports pagination.

To use it, you will need to authenticate by providing an `access_token`
for a server admin: see [Admin API](../usage/administration/admin_api/).

This endpoint mirrors the [Matrix Spec defined Messages API](https://spec.matrix.org/v1.1/client-server-api/#get_matrixclientv3roomsroomidmessages).

The API is:
```
GET /_synapse/admin/v1/rooms/<room_id>/messages
```

**Parameters**

The following path parameters are required:

* `room_id` - The ID of the room you wish you fetch messages from.

The following query parameters are available:

* `from` (required) - The token to start returning events from. This token can be obtained from a prev_batch
  or next_batch token returned by the /sync endpoint, or from an end token returned by a previous request to this endpoint.
* `to` - The token to stop returning events at.
* `limit` - The maximum number of events to return. Defaults to `10`.
* `filter` - A JSON RoomEventFilter to filter returned events with.
* `dir` - The direction to return events from. Either `f` for forwards or `b` for backwards. Setting
  this value to `b` will reverse the above sort order. Defaults to `f`.

**Response**

The following fields are possible in the JSON response body:

* `chunk` - A list of room events. The order depends on the dir parameter.
          Note that an empty chunk does not necessarily imply that no more events are available. Clients should continue to paginate until no end property is returned.
* `end` - A token corresponding to the end of chunk. This token can be passed back to this endpoint to request further events.
          If no further events are available, this property is omitted from the response.
* `start` - A token corresponding to the start of chunk.
* `state` - A list of state events relevant to showing the chunk.

**Example**

For more details on each chunk, read [the Matrix specification](https://spec.matrix.org/v1.1/client-server-api/#get_matrixclientv3roomsroomidmessages).

```json
{
  "chunk": [
    {
      "content": {
        "body": "This is an example text message",
        "format": "org.matrix.custom.html",
        "formatted_body": "<b>This is an example text message</b>",
        "msgtype": "m.text"
      },
      "event_id": "$143273582443PhrSn:example.org",
      "origin_server_ts": 1432735824653,
      "room_id": "!636q39766251:example.com",
      "sender": "@example:example.org",
      "type": "m.room.message",
      "unsigned": {
        "age": 1234
      }
    },
    {
      "content": {
        "name": "The room name"
      },
      "event_id": "$143273582443PhrSn:example.org",
      "origin_server_ts": 1432735824653,
      "room_id": "!636q39766251:example.com",
      "sender": "@example:example.org",
      "state_key": "",
      "type": "m.room.name",
      "unsigned": {
        "age": 1234
      }
    },
    {
      "content": {
        "body": "Gangnam Style",
        "info": {
          "duration": 2140786,
          "h": 320,
          "mimetype": "video/mp4",
          "size": 1563685,
          "thumbnail_info": {
            "h": 300,
            "mimetype": "image/jpeg",
            "size": 46144,
            "w": 300
          },
          "thumbnail_url": "mxc://example.org/FHyPlCeYUSFFxlgbQYZmoEoe",
          "w": 480
        },
        "msgtype": "m.video",
        "url": "mxc://example.org/a526eYUSFFxlgbQYZmo442"
      },
      "event_id": "$143273582443PhrSn:example.org",
      "origin_server_ts": 1432735824653,
      "room_id": "!636q39766251:example.com",
      "sender": "@example:example.org",
      "type": "m.room.message",
      "unsigned": {
        "age": 1234
      }
    }
  ],
  "end": "t47409-4357353_219380_26003_2265",
  "start": "t47429-4392820_219380_26003_2265"
}
```

# Room Timestamp to Event API

The Room Timestamp to Event API endpoint fetches the `event_id` of the closest event to the given
timestamp (`ts` query parameter) in the given direction (`dir` query parameter).

Useful for cases like jump to date so you can start paginating messages from
a given date in the archive.

The API is:
```
  GET /_synapse/admin/v1/rooms/<room_id>/timestamp_to_event
```

**Parameters**

The following path parameters are required:

* `room_id` - The ID of the room you wish to check.

The following query parameters are available:

* `ts` - a timestamp in milliseconds where we will find the closest event in
  the given direction.
* `dir` - can be `f` or `b` to indicate forwards and backwards in time from the
  given timestamp. Defaults to `f`.

**Response**

* `event_id` - The event ID closest to the given timestamp.
* `origin_server_ts` - The timestamp of the event in milliseconds since the Unix epoch.

# Block Room API
The Block Room admin API allows server admins to block and unblock rooms,
and query to see if a given room is blocked.
This API can be used to pre-emptively block a room, even if it's unknown to this
homeserver. Users will be prevented from joining a blocked room.

## Block or unblock a room

The API is:

```
PUT /_synapse/admin/v1/rooms/<room_id>/block
```

with a body of:

```json
{
    "block": true
}
```

A response body like the following is returned:

```json
{
    "block": true
}
```

**Parameters**

The following parameters should be set in the URL:

- `room_id` - The ID of the room.

The following JSON body parameters are available:

- `block` - If `true` the room will be blocked and if `false` the room will be unblocked.

**Response**

The following fields are possible in the JSON response body:

- `block` - A boolean. `true` if the room is blocked, otherwise `false`

## Get block status

The API is:

```
GET /_synapse/admin/v1/rooms/<room_id>/block
```

A response body like the following is returned:

```json
{
    "block": true,
    "user_id": "<user_id>"
}
```

**Parameters**

The following parameters should be set in the URL:

- `room_id` - The ID of the room.

**Response**

The following fields are possible in the JSON response body:

- `block` - A boolean. `true` if the room is blocked, otherwise `false`
- `user_id` - An optional string. If the room is blocked (`block` is `true`) shows
  the user who has add the room to blocking list. Otherwise it is not displayed.

# Delete Room API

The Delete Room admin API allows server admins to remove rooms from the server
and block these rooms.

Shuts down a room. Moves all local users and room aliases automatically to a
new room if `new_room_user_id` is set. Otherwise local users only
leave the room without any information.

The new room will be created with the user specified by the `new_room_user_id` parameter
as room administrator and will contain a message explaining what happened. Users invited
to the new room will have power level `-10` by default, and thus be unable to speak.

If `block` is `true`, users will be prevented from joining the old room.
This option can in [Version 1](#version-1-old-version) also be used to pre-emptively
block a room, even if it's unknown to this homeserver. In this case, the room will be
blocked, and no further action will be taken. If `block` is `false`, attempting to
delete an unknown room is invalid and will be rejected as a bad request.

This API will remove all trace of the old room from your database after removing
all local users. If `purge` is `true` (the default), all traces of the old room will
be removed from your database after removing all local users. If you do not want
this to happen, set `purge` to `false`.
Depending on the amount of history being purged, a call to the API may take
several minutes or longer.

The local server will only have the power to move local user and room aliases to
the new room. Users on other servers will be unaffected.

## Version 1 (old version)

This version works synchronously. That means you only get the response once the server has
finished the action, which may take a long time. If you request the same action
a second time, and the server has not finished the first one, the second request will block.
This is fixed in version 2 of this API. The parameters are the same in both APIs.
This API will become deprecated in the future.

The API is:

```
DELETE /_synapse/admin/v1/rooms/<room_id>
```

with a body of:

```json
{
    "new_room_user_id": "@someuser:example.com",
    "room_name": "Content Violation Notification",
    "message": "Bad Room has been shutdown due to content violations on this server. Please review our Terms of Service.",
    "block": true,
    "purge": true
}
```

A response body like the following is returned:

```json
{
    "kicked_users": [
        "@foobar:example.com"
    ],
    "failed_to_kick_users": [],
    "local_aliases": [
        "#badroom:example.com",
        "#evilsaloon:example.com"
    ],
    "new_room_id": "!newroomid:example.com"
}
```

The parameters and response values have the same format as
[version 2](#version-2-new-version) of the API.

## Version 2 (new version)

**Note**: This API is new, experimental and "subject to change".

This version works asynchronously, meaning you get the response from server immediately
while the server works on that task in background. You can then request the status of the action
to check if it has completed.

The API is:

```
DELETE /_synapse/admin/v2/rooms/<room_id>
```

with a body of:

```json
{
    "new_room_user_id": "@someuser:example.com",
    "room_name": "Content Violation Notification",
    "message": "Bad Room has been shutdown due to content violations on this server. Please review our Terms of Service.",
    "block": true,
    "purge": true
}
```

The API starts the shut down and purge running, and returns immediately with a JSON body with
a purge id:

```json
{
    "delete_id": "<opaque id>"
}
```

**Parameters**

The following parameters should be set in the URL:

* `room_id` - The ID of the room.

The following JSON body parameters are available:

* `new_room_user_id` - Optional. If set, a new room will be created with this user ID
      as the creator and admin, and all users in the old room will be moved into that
      room. If not set, no new room will be created and the users will just be removed
      from the old room. The user ID must be on the local server, but does not necessarily
      have to belong to a registered user.
* `room_name` - Optional. A string representing the name of the room that new users will be
                invited to. Defaults to `Content Violation Notification`
* `message` - Optional. A string containing the first message that will be sent as
              `new_room_user_id` in the new room. Ideally this will clearly convey why the
               original room was shut down. Defaults to `Sharing illegal content on this server
               is not permitted and rooms in violation will be blocked.`
* `block` - Optional. If set to `true`, this room will be added to a blocking list,
            preventing future attempts to join the room. Rooms can be blocked
            even if they're not yet known to the homeserver (only with
            [Version 1](#version-1-old-version) of the API). Defaults to `false`.
* `purge` - Optional. If set to `true`, it will remove all traces of the room from your database.
            Defaults to `true`.
* `force_purge` - Optional, and ignored unless `purge` is `true`. If set to `true`, it
  will force a purge to go ahead even if there are local users still in the room. Do not
  use this unless a regular `purge` operation fails, as it could leave those users'
  clients in a confused state.

The JSON body must not be empty. The body must be at least `{}`.

## Status of deleting rooms

**Note**: This API is new, experimental and "subject to change".

It is possible to query the status of the background task for deleting rooms.
The status can be queried up to 24 hours after completion of the task,
or until Synapse is restarted (whichever happens first).

### Query by `room_id`

With this API you can get the status of all active deletion tasks, and all those completed in the last 24h,
for the given `room_id`.

The API is:

```
GET /_synapse/admin/v2/rooms/<room_id>/delete_status
```

A response body like the following is returned:

```json
{
    "results": [
        {
            "delete_id": "delete_id1",
            "status": "failed",
            "error": "error message",
            "shutdown_room": {
                "kicked_users": [],
                "failed_to_kick_users": [],
                "local_aliases": [],
                "new_room_id": null
            }
        }, {
            "delete_id": "delete_id2",
            "status": "purging",
            "shutdown_room": {
                "kicked_users": [
                    "@foobar:example.com"
                ],
                "failed_to_kick_users": [],
                "local_aliases": [
                    "#badroom:example.com",
                    "#evilsaloon:example.com"
                ],
                "new_room_id": "!newroomid:example.com"
            }
        }
    ]
}
```

**Parameters**

The following parameters should be set in the URL:

* `room_id` - The ID of the room.

### Query by `delete_id`

With this API you can get the status of one specific task by `delete_id`.

The API is:

```
GET /_synapse/admin/v2/rooms/delete_status/<delete_id>
```

A response body like the following is returned:

```json
{
    "status": "purging",
    "shutdown_room": {
        "kicked_users": [
            "@foobar:example.com"
        ],
        "failed_to_kick_users": [],
        "local_aliases": [
            "#badroom:example.com",
            "#evilsaloon:example.com"
        ],
        "new_room_id": "!newroomid:example.com"
    }
}
```

**Parameters**

The following parameters should be set in the URL:

* `delete_id` - The ID for this delete.

### Response

The following fields are returned in the JSON response body:

- `results` - An array of objects, each containing information about one task.
  This field is omitted from the result when you query by `delete_id`.
  Task objects contain the following fields:
  - `delete_id` - The ID for this purge if you query by `room_id`.
  - `status` - The status will be one of:
    - `shutting_down` - The process is removing users from the room.
    - `purging` - The process is purging the room and event data from database.
    - `complete` - The process has completed successfully.
    - `failed` - The process is aborted, an error has occurred.
  - `error` - A string that shows an error message if `status` is `failed`.
    Otherwise this field is hidden.
  - `shutdown_room` - An object containing information about the result of shutting down the room.
    *Note:* The result is shown after removing the room members.
    The delete process can still be running. Please pay attention to the `status`.
    - `kicked_users` - An array of users (`user_id`) that were kicked.
    - `failed_to_kick_users` - An array of users (`user_id`) that that were not kicked.
    - `local_aliases` - An array of strings representing the local aliases that were
      migrated from the old room to the new.
    - `new_room_id` - A string representing the room ID of the new room, or `null` if
      no such room was created.

## Undoing room deletions

*Note*: This guide may be outdated by the time you read it. By nature of room deletions being performed at the database level,
the structure can and does change without notice.

First, it's important to understand that a room deletion is very destructive. Undoing a deletion is not as simple as pretending it
never happened - work has to be done to move forward instead of resetting the past. In fact, in some cases it might not be possible
to recover at all:

* If the room was invite-only, your users will need to be re-invited.
* If the room no longer has any members at all, it'll be impossible to rejoin.
* The first user to rejoin will have to do so via an alias on a different
  server (or receive an invite from a user on a different server).

With all that being said, if you still want to try and recover the room:

1. If the room was `block`ed, you must unblock it on your server. This can be
   accomplished as follows:

   1. For safety reasons, shut down Synapse.
   2. In the database, run `DELETE FROM blocked_rooms WHERE room_id = '!example:example.org';`
      * For caution: it's recommended to run this in a transaction: `BEGIN; DELETE ...;`, verify you got 1 result, then `COMMIT;`.
      * The room ID is the same one supplied to the delete room API, not the Content Violation room.
   3. Restart Synapse.

   This step is unnecessary if `block` was not set.

2. Any room aliases on your server that pointed to the deleted room may have
   been deleted, or redirected to the Content Violation room. These will need
   to be restored manually.

3. Users on your server that were in the deleted room will have been kicked
   from the room. Consider whether you want to update their membership
   (possibly via the [Edit Room Membership API](room_membership.md)) or let
   them handle rejoining themselves.

4. If `new_room_user_id` was given, a 'Content Violation' will have been
   created. Consider whether you want to delete that roomm.

# Make Room Admin API

Grants another user the highest power available to a local user who is in the room.
If the user is not in the room, and it is not publicly joinable, then invite the user.

By default the server admin (the caller) is granted power, but another user can
optionally be specified, e.g.:

```
POST /_synapse/admin/v1/rooms/<room_id_or_alias>/make_room_admin
{
    "user_id": "@foo:example.com"
}
```

# Forward Extremities Admin API

Enables querying and deleting forward extremities from rooms. When a lot of forward
extremities accumulate in a room, performance can become degraded. For details, see
[#1760](https://github.com/matrix-org/synapse/issues/1760).

## Check for forward extremities

To check the status of forward extremities for a room:

```
GET /_synapse/admin/v1/rooms/<room_id_or_alias>/forward_extremities
```

A response as follows will be returned:

```json
{
  "count": 1,
  "results": [
    {
      "event_id": "$M5SP266vsnxctfwFgFLNceaCo3ujhRtg_NiiHabcdefgh",
      "state_group": 439,
      "depth": 123,
      "received_ts": 1611263016761
    }
  ]
}
```

## Deleting forward extremities

**WARNING**: Please ensure you know what you're doing and have read
the related issue [#1760](https://github.com/matrix-org/synapse/issues/1760).
Under no situations should this API be executed as an automated maintenance task!

If a room has lots of forward extremities, the extra can be
deleted as follows:

```
DELETE /_synapse/admin/v1/rooms/<room_id_or_alias>/forward_extremities
```

A response as follows will be returned, indicating the amount of forward extremities
that were deleted.

```json
{
  "deleted": 1
}
```

# Event Context API

This API lets a client find the context of an event. This is designed primarily to investigate abuse reports.

```
GET /_synapse/admin/v1/rooms/<room_id>/context/<event_id>
```

This API mimmicks [GET /_matrix/client/r0/rooms/{roomId}/context/{eventId}](https://matrix.org/docs/spec/client_server/r0.6.1#get-matrix-client-r0-rooms-roomid-context-eventid). Please refer to the link for all details on parameters and reseponse.

Example response:

```json
{
  "end": "t29-57_2_0_2",
  "events_after": [
    {
      "content": {
        "body": "This is an example text message",
        "msgtype": "m.text",
        "format": "org.matrix.custom.html",
        "formatted_body": "<b>This is an example text message</b>"
      },
      "type": "m.room.message",
      "event_id": "$143273582443PhrSn:example.org",
      "room_id": "!636q39766251:example.com",
      "sender": "@example:example.org",
      "origin_server_ts": 1432735824653,
      "unsigned": {
        "age": 1234
      }
    }
  ],
  "event": {
    "content": {
      "body": "filename.jpg",
      "info": {
        "h": 398,
        "w": 394,
        "mimetype": "image/jpeg",
        "size": 31037
      },
      "url": "mxc://example.org/JWEIFJgwEIhweiWJE",
      "msgtype": "m.image"
    },
    "type": "m.room.message",
    "event_id": "$f3h4d129462ha:example.com",
    "room_id": "!636q39766251:example.com",
    "sender": "@example:example.org",
    "origin_server_ts": 1432735824653,
    "unsigned": {
      "age": 1234
    }
  },
  "events_before": [
    {
      "content": {
        "body": "something-important.doc",
        "filename": "something-important.doc",
        "info": {
          "mimetype": "application/msword",
          "size": 46144
        },
        "msgtype": "m.file",
        "url": "mxc://example.org/FHyPlCeYUSFFxlgbQYZmoEoe"
      },
      "type": "m.room.message",
      "event_id": "$143273582443PhrSn:example.org",
      "room_id": "!636q39766251:example.com",
      "sender": "@example:example.org",
      "origin_server_ts": 1432735824653,
      "unsigned": {
        "age": 1234
      }
    }
  ],
  "start": "t27-54_2_0_2",
  "state": [
    {
      "content": {
        "creator": "@example:example.org",
        "room_version": "1",
        "m.federate": true,
        "predecessor": {
          "event_id": "$something:example.org",
          "room_id": "!oldroom:example.org"
        }
      },
      "type": "m.room.create",
      "event_id": "$143273582443PhrSn:example.org",
      "room_id": "!636q39766251:example.com",
      "sender": "@example:example.org",
      "origin_server_ts": 1432735824653,
      "unsigned": {
        "age": 1234
      },
      "state_key": ""
    },
    {
      "content": {
        "membership": "join",
        "avatar_url": "mxc://example.org/SEsfnsuifSDFSSEF",
        "displayname": "Alice Margatroid"
      },
      "type": "m.room.member",
      "event_id": "$143273582443PhrSn:example.org",
      "room_id": "!636q39766251:example.com",
      "sender": "@example:example.org",
      "origin_server_ts": 1432735824653,
      "unsigned": {
        "age": 1234
      },
      "state_key": "@alice:example.org"
    }
  ]
}
```
