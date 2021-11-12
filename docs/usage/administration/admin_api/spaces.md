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

Returning:

```json
{
    "left": ["!room1:example.net", "!room2:example.net", ...],
    "failed": {
        "!room3:example.net": [
            "Could not explore space or room fully."
        ],
        "!room4:example.net": [
            "Failed to leave room."
        ],
        ...
    }
}
```

`left`: A list of rooms that the user has been made to leave.

`failed`: A dictionary with entries for rooms that could not be fully
processed. The values of the dictionary are lists of failure reasons.
Rooms may appear here if:
  * The user failed to leave them for any reason.
  * The room is a space that the local homeserver is not in, and so
    its full list of child rooms could not be determined.
  * The room is inaccessible to the local homeserver, and it is not
    known whether the room is a subspace containing further rooms.
  * Some combination of the above.
