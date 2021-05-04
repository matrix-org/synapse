# Edit Room Membership API

This API allows an administrator to join an user account with a given `user_id`
to a room with a given `room_id_or_alias`. You can only modify the membership of
local users. The server administrator must be in the room and have permission to
invite users.

## Parameters

The following parameters are available:

* `user_id` - Fully qualified user: for example, `@user:server.com`.
* `room_id_or_alias` - The room identifier or alias to join: for example,
  `!636q39766251:server.com`.

## Usage

```
POST /_synapse/admin/v1/join/<room_id_or_alias>

{
  "user_id": "@user:server.com"
}
```

To use it, you will need to authenticate by providing an `access_token` for a
server admin: see [README.rst](README.rst).

Response:

```
{
  "room_id": "!636q39766251:server.com"
}
```
