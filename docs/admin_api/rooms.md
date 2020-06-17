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

```
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

```
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

```
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

```
{
  "rooms": [
    {
      "room_id": "!mscvqgqpHYjBGDxNym:matrix.org",
      "name": "Music Theory",
      "canonical_alias": "#musictheory:matrix.org",
      "joined_members": 127
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
      "joined_members": 137
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

# DRAFT: Room Details API

The Room Details admin API allows server admins to get all details of a room.

This API is still a draft and details might change!

The following fields are possible in the JSON response body:

* `room_id` - The ID of the room.
* `name` - The name of the room.
* `canonical_alias` - The canonical (main) alias address of the room.
* `joined_members` - How many users are currently in the room.
* `joined_local_members` - How many local users are currently in the room.
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

```
{
  "room_id": "!mscvqgqpHYjBGDxNym:matrix.org",
  "name": "Music Theory",
  "canonical_alias": "#musictheory:matrix.org",
  "joined_members": 127
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
}
```
