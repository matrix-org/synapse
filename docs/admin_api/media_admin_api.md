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

# Quarantine media

Quarantining media means that it is marked as inaccessible by users. It applies
to any local media, and any locally-cached copies of remote media.

The media file itself (and any thumbnails) is not deleted from the server.

## Quarantining media by ID

This API quarantines a single piece of local or remote media.

```
POST /_synapse/admin/v1/quarantine_media/<media_id>

{}
```

Where `media_id` is in the form of `example.org/abcdefg12345...`.

## Quarantining media in a room

This API quarantines all local and remote media in a room.

```
POST /_synapse/admin/v1/quarantine_media/<room_id>

{
  "num_quarantined": 10  # The number of media items successfully quarantined
}
```

Where `room_id` is in the form of `!roomid12345:example.org`.

## Quarantining all media of a user

This API quarantines all *local* media that a *local* user has uploaded. That is to say, if
you would like to quarantine media uploaded by a user on a remote homeserver, you should
instead use one of the other APIs.

```
POST /_synapse/admin/v1/quarantine_media/<user_id>
{
  "num_quarantined": 10  # The number of media items successfully quarantined
}
```

Where `user_id` is in the form of `@bob:example.org`.
