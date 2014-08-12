=========================
Client-Server URL Summary
=========================

A brief overview of the URL scheme involved in the Synapse Client-Server API.


URLs
====

Fetch events:
  GET /events

Registering an account
  POST /register

Unregistering an account
  POST /unregister

Rooms
-----

Creating a room by ID
  PUT /rooms/$roomid

Creating an anonymous room
  POST /rooms

Room topic
  GET /rooms/$roomid/topic
  PUT /rooms/$roomid/topic

List rooms
  GET /rooms/list

Invite/Join/Leave
  GET    /rooms/$roomid/members/$userid/state
  PUT    /rooms/$roomid/members/$userid/state
  DELETE /rooms/$roomid/members/$userid/state

List members
  GET  /rooms/$roomid/members/list

Sending/reading messages
  PUT /rooms/$roomid/messages/$sender/$msgid

Feedback
  GET /rooms/$roomid/messages/$sender/$msgid/feedback/$feedbackuser/$feedback
  PUT /rooms/$roomid/messages/$sender/$msgid/feedback/$feedbackuser/$feedback

Paginating messages
  GET /rooms/$roomid/messages/list

Profiles
--------

Display name
  GET /profile/$userid/displayname
  PUT /profile/$userid/displayname

Avatar URL
  GET /profile/$userid/avatar_url
  PUT /profile/$userid/avatar_url

Metadata
  GET  /profile/$userid/metadata
  POST /profile/$userid/metadata

Presence
--------

My state or status message
  GET /presence/$userid/status
  PUT /presence/$userid/status
    also 'GET' for fetching others

TODO(paul): per-device idle time, device type; similar to above

My presence list
  GET  /presence_list/$myuserid
  POST /presence_list/$myuserid
    body is JSON-encoded dict of keys:
      invite: list of UserID strings to invite
      drop: list of UserID strings to remove
      TODO(paul): define other ops: accept, group management, ordering?

Presence polling start/stop
  POST /presence_list/$myuserid?op=start
  POST /presence_list/$myuserid?op=stop

Presence invite
  POST /presence_list/$myuserid/invite/$targetuserid
