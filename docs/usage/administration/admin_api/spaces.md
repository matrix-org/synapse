# Spaces API

This API allows a server administrator to manage spaces.

## Remove local user

This API forces a local user to leave all non-public rooms in a space.

The space itself is always left, regardless of whether it is public.

May succeed partially if the user fails to leave some rooms.

The API is:

```
DELETE /_synapse/admin/v1/rooms/<room_id>/hierarchy/members/<user_id>
```

with an optional body of:

```json
{
  "include_remote_spaces": true,
}
```

`include_remote_spaces` controls whether to process subspaces that the
local homeserver is not participating in. The listings of such subspaces
have to be retrieved over federation and their accuracy cannot be
guaranteed.

Returning:

```json
{
    "left_rooms": ["!room1:example.net", "!room2:example.net", ...],
    "inaccessible_rooms": ["!subspace1:example.net", ...],
    "failed_rooms": {
        "!room4:example.net": "Failed to leave room.",
        ...
    }
}
```

`left_rooms`: A list of rooms that the user has been made to leave.

`inaccessible_rooms`: A list of rooms and spaces that the local
homeserver is not in, and may have not been fully processed. Rooms may
appear here if:
  * The room is a space that the local homeserver is not in, and so its
    full list of child rooms could not be determined.
  * The room is inaccessible to the local homeserver, and it is not
    known whether the room is a subspace containing further rooms.

`failed_rooms`: A dictionary of errors encountered when leaving rooms.
The keys of the dictionary are room IDs and the values of the dictionary
are error messages.
