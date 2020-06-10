# List all media in a room

This API gets a list of known media in a room.

The API is:
```
GET /_synapse/admin/v1/room/<room_id>/media
```
To use it, you will need to authenticate by providing an `access_token` for a
server admin: see [README.rst](README.rst).

The API returns a JSON body like the following:
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

Request:

```
POST /_synapse/admin/v1/media/quarantine/<server_name>/<media_id>

{}
```

Where `server_name` is in the form of `example.org`, and `media_id` is in the
form of `abcdefg12345...`.

Response:

```
{}
```

## Quarantining media in a room

This API quarantines all local and remote media in a room.

Request:

```
POST /_synapse/admin/v1/room/<room_id>/media/quarantine

{}
```

Where `room_id` is in the form of `!roomid12345:example.org`.

Response:

```
{
  "num_quarantined": 10  # The number of media items successfully quarantined
}
```

Note that there is a legacy endpoint, `POST
/_synapse/admin/v1/quarantine_media/<room_id >`, that operates the same.
However, it is deprecated and may be removed in a future release.

## Quarantining all media of a user

This API quarantines all *local* media that a *local* user has uploaded. That is to say, if
you would like to quarantine media uploaded by a user on a remote homeserver, you should
instead use one of the other APIs.

Request:

```
POST /_synapse/admin/v1/user/<user_id>/media/quarantine

{}
```

Where `user_id` is in the form of `@bob:example.org`.

Response:

```
{
  "num_quarantined": 10  # The number of media items successfully quarantined
}
```
