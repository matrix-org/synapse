Purge room API
==============

This API will remove all trace of a room from your database.

All local users must have left the room before it can be removed.

The API is:

```
POST /_synapse/admin/v1/purge_room

{
    "room_id": "!room:id"
}
```

You must authenticate using the access token of an admin user.
