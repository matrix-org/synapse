# Querying media

These APIs allow extracting media information from the homeserver.

Details about the format of the `media_id` and storage of the media in the file system
are documented under [media repository](../media_repository.md).

To use it, you will need to authenticate by providing an `access_token`
for a server admin: see [Admin API](../usage/administration/admin_api/).

## List all media in a room

This API gets a list of known media in a room.
However, it only shows media from unencrypted events or rooms.

The API is:
```
GET /_synapse/admin/v1/room/<room_id>/media
```

The API returns a JSON body like the following:
```json
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

## List all media uploaded by a user

Listing all media that has been uploaded by a local user can be achieved through
the use of the
[List media uploaded by a user](user_admin_api.md#list-media-uploaded-by-a-user)
Admin API.

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

```json
{}
```

## Remove media from quarantine by ID

This API removes a single piece of local or remote media from quarantine.

Request:

```
POST /_synapse/admin/v1/media/unquarantine/<server_name>/<media_id>

{}
```

Where `server_name` is in the form of `example.org`, and `media_id` is in the
form of `abcdefg12345...`.

Response:

```json
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

```json
{
  "num_quarantined": 10
}
```

The following fields are returned in the JSON response body:

* `num_quarantined`: integer - The number of media items successfully quarantined

Note that there is a legacy endpoint, `POST
/_synapse/admin/v1/quarantine_media/<room_id>`, that operates the same.
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

URL Parameters

* `user_id`: string - User ID in the form of `@bob:example.org`

Response:

```json
{
  "num_quarantined": 10
}
```

The following fields are returned in the JSON response body:

* `num_quarantined`: integer - The number of media items successfully quarantined

## Protecting media from being quarantined

This API protects a single piece of local media from being quarantined using the
above APIs. This is useful for sticker packs and other shared media which you do
not want to get quarantined, especially when
[quarantining media in a room](#quarantining-media-in-a-room).

Request:

```
POST /_synapse/admin/v1/media/protect/<media_id>

{}
```

Where `media_id` is in the  form of `abcdefg12345...`.

Response:

```json
{}
```

## Unprotecting media from being quarantined

This API reverts the protection of a media.

Request:

```
POST /_synapse/admin/v1/media/unprotect/<media_id>

{}
```

Where `media_id` is in the  form of `abcdefg12345...`.

Response:

```json
{}
```

# Delete local media
This API deletes the *local* media from the disk of your own server.
This includes any local thumbnails and copies of media downloaded from
remote homeservers.
This API will not affect media that has been uploaded to external
media repositories (e.g https://github.com/turt2live/matrix-media-repo/).
See also [Purge Remote Media API](#purge-remote-media-api).

## Delete a specific local media
Delete a specific `media_id`.

Request:

```
DELETE /_synapse/admin/v1/media/<server_name>/<media_id>

{}
```

URL Parameters

* `server_name`: string - The name of your local server (e.g `matrix.org`)
* `media_id`: string - The ID of the media (e.g `abcdefghijklmnopqrstuvwx`)

Response:

```json
{
  "deleted_media": [
    "abcdefghijklmnopqrstuvwx"
  ],
  "total": 1
}
```

The following fields are returned in the JSON response body:

* `deleted_media`: an array of strings - List of deleted `media_id`
* `total`: integer - Total number of deleted `media_id`

## Delete local media by date or size

Request:

```
POST /_synapse/admin/v1/media/delete?before_ts=<before_ts>

{}
```

*Deprecated in Synapse v1.78.0:* This API is available at the deprecated endpoint:

```
POST /_synapse/admin/v1/media/<server_name>/delete?before_ts=<before_ts>

{}
```

URL Parameters

* `server_name`: string - The name of your local server (e.g `matrix.org`). *Deprecated in Synapse v1.78.0.*
* `before_ts`: string representing a positive integer - Unix timestamp in milliseconds.
Files that were last used before this timestamp will be deleted. It is the timestamp of
last access, not the timestamp when the file was created.
* `size_gt`: Optional - string representing a positive integer - Size of the media in bytes.
Files that are larger will be deleted. Defaults to `0`.
* `keep_profiles`: Optional - string representing a boolean - Switch to also delete files
that are still used in image data (e.g user profile, room avatar).
If `false` these files will be deleted. Defaults to `true`.

Response:

```json
{
  "deleted_media": [
    "abcdefghijklmnopqrstuvwx",
    "abcdefghijklmnopqrstuvwz"
  ],
  "total": 2
}
```

The following fields are returned in the JSON response body:

* `deleted_media`: an array of strings - List of deleted `media_id`
* `total`: integer - Total number of deleted `media_id`

## Delete media uploaded by a user

You can find details of how to delete multiple media uploaded by a user in
[User Admin API](user_admin_api.md#delete-media-uploaded-by-a-user).

# Purge Remote Media API

The purge remote media API allows server admins to purge old cached remote media.

The API is:

```
POST /_synapse/admin/v1/purge_media_cache?before_ts=<unix_timestamp_in_ms>

{}
```

URL Parameters

* `before_ts`: string representing a positive integer - Unix timestamp in milliseconds.
All cached media that was last accessed before this timestamp will be removed.

Response:

```json
{
  "deleted": 10
}
```

The following fields are returned in the JSON response body:

* `deleted`: integer - The number of media items successfully deleted

If the user re-requests purged remote media, synapse will re-request the media
from the originating server.
