# Server Notices

The API to send notices is as follows:

```
POST /_matrix/client/r0/admin/send_server_notice/[<user_id>]
```

including an `access_token` of a server admin.

If the user_id is missing, the message is meant to go to all users on the server.

The request body should contain the following:

```json
{
    "event": {
        "msgtype":"m.text",
        "body": "This is my message"
    }
}
```
or as shortcut you can also send
```json
{
    "event_body": "This is my message"
}
```

## Notes:
1) You have to configure server notices in [homeserver.yaml](../server_notices.md) before
you can use this API
2) This query sends a message to all users (and creates a room for each one if it was not
done before). So please be aware that you will put your server under heavy load if you
have a large number of registered users.