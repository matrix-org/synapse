# Server Notices

The API to send notices is as follows:

```
POST /_synapse/admin/v1/send_server_notice
```

or:

```
PUT /_synapse/admin/v1/send_server_notice/{txnId}
```

You will need to authenticate with an access token for an admin user.

When using the `PUT` form, retransmissions with the same transaction ID will be
ignored in the same way as with `PUT
/_matrix/client/r0/rooms/{roomId}/send/{eventType}/{txnId}`.

The request body should look something like the following:

```json
{
    "user_id": "@target_user:server_name",
    "content": {
        "msgtype": "m.text",
        "body": "This is my message"
    }
}
```

You can optionally include the following additional parameters:

* `type`: the type of event. Defaults to `m.room.message`.
* `state_key`: Setting this will result in a state event being sent.

You can also use HTML in server notices, for example:
```curl -X POST --header "Authorization: Bearer TOKEN" -d "{\"user_id\":\"@user:server\",\"content\":{\"msgtype\":\"m.text\", \"body\": \"**bold**\", \"format\": \"org.matrix.custom.html\", \"formatted_body\": \"<h3><u>Upcoming Chat (Matrix) Maintenance</u></h3><b>When:</b> Wednesday June 2 - 00:30 UTC<br><b>Duration:</b> 2 hours.\"}}" http://localhost:8008/_synapse/admin/v1/send_server_notice
```


Once the notice has been sent, the API will return the following response:

```json
{
    "event_id": "<event_id>"
}
```

Note that server notices must be enabled in `homeserver.yaml` before this API
can be used. See [server_notices.md](../server_notices.md) for more information.
