# Contents
- [List Room API](#list-room-api)
  * [Parameters](#parameters)
  * [Usage](#usage)
- [Room Details API](#room-details-api)
- [Room Members API](#room-members-api)
- [Delete Room API](#delete-room-api)
  * [Parameters](#parameters-1)
  * [Response](#response)
  * [Undoing room shutdowns](#undoing-room-shutdowns)
- [Make Room Admin API](#make-room-admin-api)

# List Room API

The List Room admin API allows server admins to get a list of rooms on their
server. There are various parameters available that allow for filtering and
sorting the returned list. This API supports pagination.

## Parameters

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
* `search_term` - Filter rooms by their room name. Search term can be contained in any
                  part of the room name. Defaults to no filtering.

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

## Usage

A standard request with no filtering:

```
GET /_synapse/admin/v1/rooms

{}
```

Response:

```jsonc
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
      "state_events": 93534
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
      "state_events": 8345
    }
  ],
  "offset": 0,
  "total_rooms": 10
}
```

Filtering by room name:

```
GET /_synapse/admin/v1/rooms?search_term=TWIM

{}
```

Response:

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
      "state_events": 8
    }
  ],
  "offset": 0,
  "total_rooms": 1
}
```

Paginating through a list of rooms:

```
GET /_synapse/admin/v1/rooms?order_by=size

{}
```

Response:

```jsonc
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
      "state_events": 93534
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
      "state_events": 8345
    }
  ],
  "offset": 0,
  "total_rooms": 150
  "next_token": 100
}
```

The presence of the `next_token` parameter tells us that there are more rooms
than returned in this request, and we need to make another request to get them.
To get the next batch of room results, we repeat our request, setting the `from`
parameter to the value of `next_token`.

```
GET /_synapse/admin/v1/rooms?order_by=size&from=100

{}
```

Response:

```jsonc
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
      "state_events": 93534
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
      "state_events": 8345
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

## Usage

A standard request:

```
GET /_synapse/admin/v1/rooms/<room_id>

{}
```

Response:

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
  "state_events": 93534
}
```

# Room Members API

The Room Members admin API allows server admins to get a list of all members of a room.

The response includes the following fields:

* `members` - A list of all the members that are present in the room, represented by their ids.
* `total` - Total number of members in the room.

## Usage

A standard request:

```
GET /_synapse/admin/v1/rooms/<room_id>/members

{}
```

Response:

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

# Delete Room API

The Delete Room admin API allows server admins to remove rooms from server
and block these rooms.

Shuts down a room. Moves all local users and room aliases automatically to a
new room if `new_room_user_id` is set. Otherwise local users only
leave the room without any information.

The new room will be created with the user specified by the `new_room_user_id` parameter
as room administrator and will contain a message explaining what happened. Users invited
to the new room will have power level `-10` by default, and thus be unable to speak.

If `block` is `True` it prevents new joins to the old room.

This API will remove all trace of the old room from your database after removing
all local users. If `purge` is `true` (the default), all traces of the old room will
be removed from your database after removing all local users. If you do not want
this to happen, set `purge` to `false`.
Depending on the amount of history being purged a call to the API may take
several minutes or longer.

The local server will only have the power to move local user and room aliases to
the new room. Users on other servers will be unaffected.

The API is:

```
POST /_synapse/admin/v1/rooms/<room_id>/delete
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

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see [README.rst](README.rst).

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

## Parameters

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
* `block` - Optional. If set to `true`, this room will be added to a blocking list, preventing
            future attempts to join the room. Defaults to `false`.
* `purge` - Optional. If set to `true`, it will remove all traces of the room from your database.
            Defaults to `true`.
* `force_purge` - Optional, and ignored unless `purge` is `true`. If set to `true`, it
  will force a purge to go ahead even if there are local users still in the room. Do not
  use this unless a regular `purge` operation fails, as it could leave those users'
  clients in a confused state.

The JSON body must not be empty. The body must be at least `{}`.

## Response

The following fields are returned in the JSON response body:

* `kicked_users` - An array of users (`user_id`) that were kicked.
* `failed_to_kick_users` - An array of users (`user_id`) that that were not kicked.
* `local_aliases` - An array of strings representing the local aliases that were migrated from
                    the old room to the new.
* `new_room_id` - A string representing the room ID of the new room.


## Undoing room shutdowns

*Note*: This guide may be outdated by the time you read it. By nature of room shutdowns being performed at the database level,
the structure can and does change without notice.

First, it's important to understand that a room shutdown is very destructive. Undoing a shutdown is not as simple as pretending it
never happened - work has to be done to move forward instead of resetting the past. In fact, in some cases it might not be possible
to recover at all:

* If the room was invite-only, your users will need to be re-invited.
* If the room no longer has any members at all, it'll be impossible to rejoin.
* The first user to rejoin will have to do so via an alias on a different server.

With all that being said, if you still want to try and recover the room:

1. For safety reasons, shut down Synapse.
2. In the database, run `DELETE FROM blocked_rooms WHERE room_id = '!example:example.org';`
   * For caution: it's recommended to run this in a transaction: `BEGIN; DELETE ...;`, verify you got 1 result, then `COMMIT;`.
   * The room ID is the same one supplied to the shutdown room API, not the Content Violation room.
3. Restart Synapse.

You will have to manually handle, if you so choose, the following:

* Aliases that would have been redirected to the Content Violation room.
* Users that would have been booted from the room (and will have been force-joined to the Content Violation room).
* Removal of the Content Violation room if desired.


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
