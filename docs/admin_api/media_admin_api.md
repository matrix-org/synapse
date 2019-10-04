# List all media in a room

This API gets a list of known media in a room.

The API is:
```
GET /_synapse/admin/v1/room/<room_id>/media
```
including an `access_token` of a server admin.

It returns a JSON body like the following:
```
{
    "local": [
        "mxc://localhost/xwvutsrqponmlkjihgfedcba",
        "mxc://localhost/abcdefghijklmnopqrstuvwx"
    ],
    "remote": [
        "mxc://matrix.org/xwvutsrqponmlkjihgfedcba",
        "mxc://matrix.org/abcdefghijklmnopqrstuvwx"
    ]
}
```
