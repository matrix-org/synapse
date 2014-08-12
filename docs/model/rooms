===========
Rooms Model
===========

A description of the general data model used to implement Rooms, and the
user-level visible effects and implications.


Overview
========

"Rooms" in Synapse are shared messaging channels over which all the participant
users can exchange messages. Rooms have an opaque persistent identify, a
globally-replicated set of state (consisting principly of a membership set of
users, and other management and miscellaneous metadata), and a message history.


Room Identity and Naming
========================

Rooms can be arbitrarily created by any user on any home server; at which point
the home server will sign the message that creates the channel, and the
fingerprint of this signature becomes the strong persistent identify of the
room. This now identifies the room to any home server in the network regardless
of its original origin. This allows the identify of the room to outlive any
particular server. Subject to appropriate permissions [to be discussed later],
any current member of a room can invite others to join it, can post messages
that become part of its history, and can change the persistent state of the room
(including its current set of permissions).

Home servers can provide a directory service, allowing a lookup from a
convenient human-readable form of room label to a room ID. This mapping is
scoped to the particular home server domain and so simply represents that server
administrator's opinion of what room should take that label; it does not have to
be globally replicated and does not form part of the stored state of that room.

This room name takes the form

  #localname:some.domain.name

for similarity and consistency with user names on directories.

To join a room (and therefore to be allowed to inspect past history, post new
messages to it, and read its state), a user must become aware of the room's
fingerprint ID. There are two mechanisms to allow this:

 * An invite message from someone else in the room

 * A referral from a room directory service

As room IDs are opaque and ephemeral, they can serve as a mechanism to create
"ad-hoc" rooms deliberately unnamed, for small group-chats or even private
one-to-one message exchange.


Stored State and Permissions
============================

Every room has a globally-replicated set of stored state. This state is a set of
key/value or key/subkey/value pairs. The value of every (sub)key is a
JSON-representable object. The main key of a piece of stored state establishes
its meaning; some keys store sub-keys to allow a sub-structure within them [more
detail below]. Some keys have special meaning to Synapse, as they relate to
management details of the room itself, storing such details as user membership,
and permissions of users to alter the state of the room itself. Other keys may
store information to present to users, which the system does not directly rely
on. The key space itself is namespaced, allowing 3rd party extensions, subject
to suitable permission.

Permission management is based on the concept of "power-levels". Every user
within a room has an integer assigned, being their "power-level" within that
room. Along with its actual data value, each key (or subkey) also stores the
minimum power-level a user must have in order to write to that key, the
power-level of the last user who actually did write to it, and the PDU ID of
that state change.

To be accepted as valid, a change must NOT:

 * Be made by a user having a power-level lower than required to write to the
   state key

 * Alter the required power-level for that state key to a value higher than the
   user has

 * Increase that user's own power-level

 * Grant any other user a power-level higher than the level of the user making
   the change

[[TODO(paul): consider if relaxations should be allowed; e.g. is the current
outright-winner allowed to raise their own level, to allow for "inflation"?]]


Room State Keys
===============

[[TODO(paul): if this list gets too big it might become necessary to move it
into its own doc]]

The following keys have special semantics or meaning to Synapse itself:

m.member (has subkeys)
  Stores a sub-key for every Synapse User ID which is currently a member of
  this room. Its value gives the membership type ("knocked", "invited",
  "joined").

m.power_levels
  Stores a mapping from Synapse User IDs to their power-level in the room. If
  they are not present in this mapping, the default applies.

  The reason to store this as a single value rather than a value with subkeys
  is that updates to it are atomic; allowing a number of colliding-edit
  problems to be avoided.

m.default_level
  Gives the default power-level for members of the room that do not have one
  specified in their membership key.

m.invite_level
  If set, gives the minimum power-level required for members to invite others
  to join, or to accept knock requests from non-members requesting access. If
  absent, then invites are not allowed. An invitation involves setting their
  membership type to "invited", in addition to sending the invite message.

m.join_rules
  Encodes the rules on how non-members can join the room. Has the following
  possibilities:
    "public" - a non-member can join the room directly
    "knock" - a non-member cannot join the room, but can post a single "knock"
        message requesting access, which existing members may approve or deny
    "invite" - non-members cannot join the room without an invite from an
        existing member
    "private" - nobody who is not in the 'may_join' list or already a member
        may join by any mechanism

  In any of the first three modes, existing members with sufficient permission
  can send invites to non-members if allowed by the "m.invite_level" key. A
  "private" room is not allowed to have the "m.invite_level" set.

  A client may use the value of this key to hint at the user interface
  expectations to provide; in particular, a private chat with one other use
  might warrant specific handling in the client.

m.may_join
  A list of User IDs that are always allowed to join the room, regardless of any
  of the prevailing join rules and invite levels. These apply even to private
  rooms. These are stored in a single list with normal update-powerlevel
  permissions applied; users cannot arbitrarily remove themselves from the list.

m.add_state_level
  The power-level required for a user to be able to add new state keys.

m.public_history
  If set and true, anyone can request the history of the room, without needing
  to be a member of the room.

m.archive_servers
  For "public" rooms with public history, gives a list of home servers that
  should be included in message distribution to the room, even if no users on
  that server are present. These ensure that a public room can still persist
  even if no users are currently members of it. This list should be consulted by
  the dirctory servers as the candidate list they respond with.

The following keys are provided by Synapse for user benefit, but their value is
not otherwise used by Synapse.

m.name
  Stores a short human-readable name for the room, such that clients can display
  to a user to assist in identifying which room is which.
  
  This name specifically is not the strong ID used by the message transport
  system to refer to the room, because it may be changed from time to time.

m.topic
  Stores the current human-readable topic


Room Creation Templates
=======================

A client (or maybe home server?) could offer a few templates for the creation of
new rooms. For example, for a simple private one-to-one chat the channel could
assign the creator a power-level of 1, requiring a level of 1 to invite, and
needing an invite before members can join. An invite is then sent to the other
party, and if accepted and the other user joins, the creator's power-level can
now be reduced to 0. This now leaves a room with two participants in it being
unable to add more.


Rooms that Continue History
===========================

An option that could be considered for room creation, is that when a new room is
created the creator could specify a PDU ID into an existing room, as the history
continuation point. This would be stored as an extra piece of meta-data on the
initial PDU of the room's creation. (It does not appear in the normal previous
PDU linkage).

This would allow users in rooms to "fork" a room, if it is considered that the
conversations in the room no longer fit its original purpose, and wish to
diverge. Existing permissions on the original room would continue to apply of
course, for viewing that history. If both rooms are considered "public" we might
also want to define a message to post into the original room to represent this
fork point, and give a reference to the new room.


User Direct Message Rooms
=========================

There is no need to build a mechanism for directly sending messages between
users, because a room can handle this ability. To allow direct user-to-user chat
messaging we simply need to be able to create rooms with specific set of
permissions to allow this direct messaging.

Between any given pair of user IDs that wish to exchange private messages, there
will exist a single shared Room, created lazily by either side. These rooms will
need a certain amount of special handling in both home servers and display on
clients, but as much as possible should be treated by the lower layers of code
the same as other rooms.

Specially, a client would likely offer a special menu choice associated with
another user (in room member lists, presence list, etc..) as "direct chat". That
would perform all the necessary steps to create the private chat room. Receiving
clients should display these in a special way too as the room name is not
important; instead it should distinguish them on the Display Name of the other
party.

Home Servers will need a client-API option to request setting up a new user-user
chat room, which will then need special handling within the server. It will
create a new room with the following 

  m.member: the proposing user
  m.join_rules: "private"
  m.may_join: both users
  m.power_levels: empty
  m.default_level: 0
  m.add_state_level: 0
  m.public_history: False

Having created the room, it can send an invite message to the other user in the
normal way - the room permissions state that no users can be set to the invited
state, but because they're in the may_join list then they'd be allowed to join
anyway.

In this arrangement there is now a room with both users may join but neither has
the power to invite any others. Both users now have the confidence that (at
least within the messaging system itself) their messages remain private and
cannot later be provably leaked to a third party. They can freely set the topic
or name if they choose and add or edit any other state of the room. The update
powerlevel of each of these fixed properties should be 1, to lock out the users
from being able to alter them.


Anti-Glare
==========

There exists the possibility of a race condition if two users who have no chat
history with each other simultaneously create a room and invite the other to it.
This is called a "glare" situation. There are two possible ideas for how to
resolve this:

 * Each Home Server should persist the mapping of (user ID pair) to room ID, so
   that duplicate requests can be suppressed. On receipt of a room creation
   request that the HS thinks there already exists a room for, the invitation to
   join can be rejected if:
      a) the HS believes the sending user is already a member of the room (and
         maybe their HS has forgotten this fact), or
      b) the proposed room has a lexicographically-higher ID than the existing
         room (to resolve true race condition conflicts)
      
 * The room ID for a private 1:1 chat has a special form, determined by
   concatenting the User IDs of both members in a deterministic order, such that
   it doesn't matter which side creates it first; the HSes can just ignore
   (or merge?) received PDUs that create the room twice.
