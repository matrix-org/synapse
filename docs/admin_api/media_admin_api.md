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

# Quarantine media in a room

This API 'quarantines' all the media in a room.

The API is:

```
POST /_synapse/admin/v1/quarantine_media/<room_id>

{}
```

Quarantining media means that it is marked as inaccessible by users. It applies
to any local media, and any locally-cached copies of remote media.

The media file itself (and any thumbnails) is not deleted from the server.
