# Server Notices

'Server Notices' are a new feature introduced in Synapse 0.30. They provide a
channel whereby server administrators can send messages to users on the server.

They are used as part of communication of the server polices (see
[Consent Tracking](consent_tracking.md)), however the intention is that
they may also find a use for features such as "Message of the day".

This is a feature specific to Synapse, but it uses standard Matrix
communication mechanisms, so should work with any Matrix client.

## User experience

When the user is first sent a server notice, they will get an invitation to a
room (typically called 'Server Notices', though this is configurable in
`homeserver.yaml`). They will be **unable to reject** this invitation -
attempts to do so will receive an error.

Once they accept the invitation, they will see the notice message in the room
history; it will appear to have come from the 'server notices user' (see
below).

The user is prevented from sending any messages in this room by the power
levels.

Having joined the room, the user can leave the room if they want. Subsequent
server notices will then cause a new room to be created.

## Synapse configuration

Server notices come from a specific user id on the server. Server
administrators are free to choose the user id - something like `server` is
suggested, meaning the notices will come from
`@server:<your_server_name>`. Once the Server Notices user is configured, that
user id becomes a special, privileged user, so administrators should ensure
that **it is not already allocated**.

In order to support server notices, it is necessary to add some configuration
to the `homeserver.yaml` file. In particular, you should add a `server_notices`
section, which should look like this:

```yaml
server_notices:
   system_mxid_localpart: server
   system_mxid_display_name: "Server Notices"
   system_mxid_avatar_url: "mxc://example.com/oumMVlgDnLYFaPVkExemNVVZ"
   room_name: "Server Notices"
   room_avatar_url: "mxc://example.com/oumMVlgDnLYFaPVkExemNVVZ"
   room_topic: "Room used by your server admin to notice you of important information"
   auto_join: true
```

The only compulsory setting is `system_mxid_localpart`, which defines the user
id of the Server Notices user, as above. `room_name` defines the name of the
room which will be created, `room_avatar_url` its avatar and `room_topic` its topic.

`system_mxid_display_name` and `system_mxid_avatar_url` can be used to set the
displayname and avatar of the Server Notices user.

`auto_join` will autojoin users to the notices room instead of sending an invite.

## Sending notices

To send server notices to users you can use the
[admin_api](admin_api/server_notices.md).
