# Edit Room Membership API

The API allows an administrator to join an user account with a given `user_id`
to a room with a given `roomIdOrAlias`. You can only modify the membership of
local users. The room must have join rule `JoinRules.PUBLIC`, which is the
default for public rooms. If the room has the join rule `JoinRules.INVITE`
(default for private rooms), the server administrator must have permissions
to invite users to this room. Per default you can invite users if you are
member of a room.

## Parameters

The following parameters are available:

* `user_id` - Fully qualified user: for example, `@user:server.com`.
* `roomIdOrAlias` - The room identifier or alias to join: for example, `!636q39766251:server.com`.

## Usage

```
POST /_synapse/admin/v1/join/<roomIdOrAlias>

{
  "user_id": "@user:server.com"
}
```
Including an `access_token` of a server admin.

Response:

```
{
  "room_id": "!636q39766251:server.com"
}
```
