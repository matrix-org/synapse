# List Room API

The List Room admin API allows server admins to get a list of rooms on their
server. There are various parameters available that allow for filtering and
sorting the returned list. This API supports pagination.

## Parameters

The following query parameters are available:

* `from` - Offset in the returned list. Defaults to `0`.
* `limit` - Maximum amount of rooms to return. Defaults to `100`.
* `order_by` - The method in which to sort the returned list of rooms. Valid values are:
  - `alphabetical` - Rooms are ordered alphabetically by room name. This is the default.
  - `size` - Rooms are ordered by the number of members. Largest to smallest.
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
      "joined_members": 8326
    },
    ... (8 hidden items) ...
    {
      "room_id": "!xYvNcQPhnkrdUmYczI:matrix.org",
      "name": "This Week In Matrix (TWIM)",
      "canonical_alias": "#twim:matrix.org",
      "joined_members": 314
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
      "joined_members": 314
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
      "joined_members": 8326
    },
    ... (98 hidden items) ...
    {
      "room_id": "!xYvNcQPhnkrdUmYczI:matrix.org",
      "name": "This Week In Matrix (TWIM)",
      "canonical_alias": "#twim:matrix.org",
      "joined_members": 314
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
    },
    ... (48 hidden items) ...
    {
      "room_id": "!twcBhHVdZlQWuuxBhN:termina.org.uk",
      "name": "weechat-matrix",
      "canonical_alias": "#weechat-matrix:termina.org.uk",
      "joined_members": 137
    }
  ],
  "offset": 100,
  "prev_batch": 0,
  "total_rooms": 150
}
```

Once the `next_token` parameter is no longer present, we know we've reached the
end of the list.
