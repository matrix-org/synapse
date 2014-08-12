==================
Room Join Workflow
==================

An outline of the workflows required when a user joins a room.

Discovery
=========

To join a room, a user has to discover the room by some mechanism in order to
obtain the (opaque) Room ID and a candidate list of likely home servers that
contain it.

Sending an Invitation
---------------------

The most direct way a user discovers the existence of a room is from a
invitation from some other user who is a member of that room.

The inviter's HS sets the membership status of the invitee to "invited" in the
"m.members" state key by sending a state update PDU. The HS then broadcasts this
PDU among the existing members in the usual way. An invitation message is also
sent to the invited user, containing the Room ID and the PDU ID of this
invitation state change and potentially a list of some other home servers to use
to accept the invite. The user's client can then choose to display it in some
way to alert the user.

[[TODO(paul): At present, no API has been designed or described to actually send
that invite to the invited user. Likely it will be some facet of the larger
user-user API required for presence, profile management, etc...]]

Directory Service
-----------------

Alternatively, the user may discover the channel via a directory service; either
by performing a name lookup, or some kind of browse or search acitivty. However
this is performed, the end result is that the user's home server requests the
Room ID and candidate list from the directory service.

[[TODO(paul): At present, no API has been designed or described for this
directory service]]


Joining
=======

Once the ID and home servers are obtained, the user can then actually join the
room.

Accepting an Invite
-------------------

If a user has received and accepted an invitation to join a room, the invitee's
home server can now send an invite acceptance message to a chosen candidate
server from the list given in the invitation, citing also the PDU ID of the
invitation as "proof" of their invite. (This is required as due to late message
propagation it could be the case that the acceptance is received before the
invite by some servers). If this message is allowed by the candidate server, it
generates a new PDU that updates the invitee's membership status to "joined",
referring back to the acceptance PDU, and broadcasts that as a state change in
the usual way. The newly-invited user is now a full member of the room, and
state propagation proceeds as usual.

Joining a Public Room
---------------------

If a user has discovered the existence of a room they wish to join but does not
have an active invitation, they can request to join it directly by sending a
join message to a candidate server on the list provided by the directory
service. As this list may be out of date, the HS should be prepared to retry
other candidates if the chosen one is no longer aware of the room, because it
has no users as members in it.

Once a candidate server that is aware of the room has been found, it can
broadcast an update PDU to add the member into the "m.members" key setting their
state directly to "joined" (i.e. bypassing the two-phase invite semantics),
remembering to include the new user's HS in that list.

Knocking on a Semi-Public Room
------------------------------

If a user requests to join a room but the join mode of the room is "knock", the
join is not immediately allowed. Instead, if the user wishes to proceed, they
can instead post a "knock" message, which informs other members of the room that
the would-be joiner wishes to become a member and sets their membership value to
"knocked". If any of them wish to accept this, they can then send an invitation
in the usual way described above. Knowing that the user has already knocked and
expressed an interest in joining, the invited user's home server should
immediately accept that invitation on the user's behalf, and go on to join the
room in the usual way.

[[NOTE(Erik): Though this may confuse users who expect 'X has joined' to
actually be a user initiated action, i.e. they may expect that 'X' is actually
looking at synapse right now?]]

[[NOTE(paul): Yes, a fair point maybe we should suggest HSes don't do that, and
just offer an invite to the user as normal]]

Private and Non-Existent Rooms
------------------------------

If a user requests to join a room but the room is either unknown by the home
server receiving the request, or is known by the join mode is "invite" and the
user has not been invited, the server must respond that the room does not exist.
This is to prevent leaking information about the existence and identity of
private rooms.


Outstanding Questions
=====================

 * Do invitations or knocks time out and expire at some point? If so when? Time
   is hard in distributed systems.
