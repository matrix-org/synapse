# Edit Room Membership API

The API allow an administrator to join an user account with a specific `user_id`
to a room with a specific `roomIdOrAlias`.
You can only modify local users.

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
