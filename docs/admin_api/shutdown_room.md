# Shutdown room API

Shuts down a room, preventing new joins and moves local users and room aliases automatically
to a new room. The new room will be created with the user specified by the
`new_room_user_id` parameter as room administrator and will contain a message
explaining what happened. Users invited to the new room will have power level
-10 by default, and thus be unable to speak. The old room's power levels will be changed to
disallow any further invites or joins.

The local server will only have the power to move local user and room aliases to
the new room. Users on other servers will be unaffected.

## API

You will need to authenticate with an access token for an admin user.

### URL

`POST /_synapse/admin/v1/shutdown_room/{room_id}`

### URL Parameters

* `room_id` - The ID of the room (e.g `!someroom:example.com`)

### JSON Body Parameters

* `new_room_user_id` - Required. A string representing the user ID of the user that will admin
                       the new room that all users in the old room will be moved to.
* `room_name` - Optional. A string representing the name of the room that new users will be
                invited to.
* `message` - Optional. A string containing the first message that will be sent as
              `new_room_user_id` in the new room. Ideally this will clearly convey why the
               original room was shut down.
              
If not specified, the default value of `room_name` is "Content Violation
Notification". The default value of `message` is "Sharing illegal content on
othis server is not permitted and rooms in violation will be blocked."

### Response Parameters

* `kicked_users` - An integer number representing the number of users that
                   were kicked.
* `failed_to_kick_users` - An integer number representing the number of users
                           that were not kicked.
* `local_aliases` - An array of strings representing the local aliases that were migrated from
                    the old room to the new.
* `new_room_id` - A string representing the room ID of the new room.

## Example

Request:

```
POST /_synapse/admin/v1/shutdown_room/!somebadroom%3Aexample.com

{
    "new_room_user_id": "@someuser:example.com",
    "room_name": "Content Violation Notification",
    "message": "Bad Room has been shutdown due to content violations on this server. Please review our Terms of Service."
}
```

Response:

```
{
    "kicked_users": 5,
    "failed_to_kick_users": 0,
    "local_aliases": ["#badroom:example.com", "#evilsaloon:example.com],
    "new_room_id": "!newroomid:example.com",
},
```
