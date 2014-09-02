Matrix Specification
====================

WARNING
=======

.. NOTE::
  The Matrix specification is still very much evolving: the API is not yet frozen
  and this document is in places incomplete, stale, and may contain security
  issues. Needless to say, we have made every effort to highlight the problem
  areas that we're aware of.
  
  We're publishing it at this point because it's complete enough to be more than
  useful and provide a canonical reference to how Matrix is evolving. Our end
  goal is to mirror WHATWG's "Living Standard" approach (see
  http://wiki.whatwg.org/wiki/FAQ#What_does_.22Living_Standard.22_mean.3F) -
  except right now Matrix is more in the process of being born than actually being
  living!

Introduction
============

Matrix is a new set of open APIs for open-federated Instant Messaging and VoIP
functionality, designed to create and support a new global real-time
communication ecosystem on the internet. This specification is the ongoing
result of standardising the APIs used by the various components of the Matrix
ecosystem to communicate with one another.

The principles that Matrix attempts to follow are:

 - Pragmatic Web-friendly APIs (i.e. JSON over REST)
 - Keep It Simple & Stupid
   - provide a simple architecture with minimal third-party dependencies.
 - Fully open:
   - Fully open federation - anyone should be able to participate in the global Matrix network
   - Fully open standard - publicly documented standard with no IP or patent licensing encumbrances
   - Fully open source reference implementation - liberally-licensed example implementations
     with no IP or patent licensing encumbrances
 - Empowering the end-user
   - The user should be able to choose the server and clients they use
   - The user should be control how private their communication is
   - The user should know precisely where their data is stored
 - Fully decentralised - no single points of control over conversations or the network as a whole
 - Learning from history to avoid repeating it
   - Trying to take the best aspects of XMPP, SIP, IRC, SMTP, IMAP and NNTP whilst trying to avoid their failings

The functionality that Matrix provides includes:

 - Creation and management of fully distributed chat rooms with no
   single points of control or failure
 - Eventually-consistent cryptographically secure synchronisation of room 
   state across a global open network of federated servers and services
 - Sending and receiving extensible messages in a room with (optional)
   end-to-end encryption
 - Extensible user management (inviting, joining, leaving, kicking, banning)
   mediated by a power-level based user privilege system.
 - Extensible room state management (room naming, aliasing, topics, bans)
 - Extensible user profile management (avatars, displaynames, etc)
 - Managing user accounts (registration, login, logout)
 - Use of 3rd Party IDs (3PIDs) such as email addresses, phone numbers,
   Facebook accounts to authenticate, identify and discover users on Matrix.
 - Trusted federation of Identity servers for:
   - Publishing user public keys for PKI
   - Mapping of 3PIDs to Matrix IDs

The end goal of Matrix is to be a ubiquitous messaging layer for synchronising
arbitrary data between sets of people, devices and services - be that for instant
messages, VoIP call setups, or any other objects that need to be reliably and
persistently pushed from A to B in an interoperable and federated manner.


Architecture
============

Clients transmit data to other clients through home servers (HSes). Clients do not communicate with each
other directly.

::

                         How data flows between clients
                         ==============================

       { Matrix client A }                             { Matrix client B }
           ^          |                                    ^          |
           |  events  |                                    |  events  |
           |          V                                    |          V
       +------------------+                            +------------------+
       |                  |---------( HTTP )---------->|                  |
       |   Home Server    |                            |   Home Server    |
       |                  |<--------( HTTP )-----------|                  |
       +------------------+        Federation          +------------------+

A "Client" typically represents a human using a web application or mobile app. Clients use the
"Client-to-Server" (C-S) API to communicate with their home server, which stores their profile data and
their record of the conversations in which they participate. Each client is associated with a user account
(and may optionally support multiple user accounts). A user account is represented by a unique "User ID". This
ID is namespaced to the home server which allocated the account and looks like::

  @localpart:domain

The ``localpart`` of a user ID may be a user name, or an opaque ID identifying this user. They are
case-insensitive.

.. TODO
    - Need to specify precise grammar for Matrix IDs

A "Home Server" is a server which provides C-S APIs and has the ability to federate with other HSes.
It is typically responsible for multiple clients. "Federation" is the term used to describe the
sharing of data between two or more home servers.

Data in Matrix is encapsulated in an "event". An event is an action within the system. Typically each
action (e.g. sending a message) correlates with exactly one event. Each event has a ``type`` which is used
to differentiate different kinds of data. ``type`` values MUST be uniquely globally namespaced following
Java's `package naming conventions <http://docs.oracle.com/javase/specs/jls/se5.0/html/packages.html#7.7>`,
e.g. ``com.example.myapp.event``. The special top-level namespace ``m.`` is reserved for events defined
in the Matrix specification. Events are usually sent in the context of a "Room".

Room structure
--------------

A room is a conceptual place where users can send and receive events. Rooms 
can be created, joined and left. Events are sent to a room, and all 
participants in that room with sufficient access will receive the event. Rooms are uniquely 
identified internally via a "Room ID", which look like::

  !opaque_id:domain

There is exactly one room ID for each room. Whilst the room ID does contain a
domain, it is simply for globally namespacing room IDs. The room does NOT reside on the
domain specified. Room IDs are not meant to be human readable. They ARE
case-sensitive.

The following diagram shows an ``m.room.message`` event being sent in the room 
``!qporfwt:matrix.org``::

       { @alice:matrix.org }                             { @bob:domain.com }
               |                                                 ^
               |                                                 |
      Room ID: !qporfwt:matrix.org                 Room ID: !qporfwt:matrix.org
      Event type: m.room.message                   Event type: m.room.message
      Content: { JSON object }                     Content: { JSON object }
               |                                                 |
               V                                                 |
       +------------------+                          +------------------+
       |   Home Server    |                          |   Home Server    |
       |   matrix.org     |<-------Federation------->|   domain.com     |
       +------------------+                          +------------------+
                |       .................................        |
                |______|     Partially Shared State      |_______|
                       | Room ID: !qporfwt:matrix.org    |
                       | Servers: matrix.org, domain.com |
                       | Members:                        |
                       |  - @alice:matrix.org            |
                       |  - @bob:domain.com              |
                       |.................................|

Federation maintains shared state between multiple home servers, such that when an event is
sent to a room, the home server knows where to forward the event on to, and how to process
the event. Home servers do not need to have completely shared state in order to participate 
in a room. State is scoped to a single room, and federation ensures that all home servers 
have the information they need, even if that means the home server has to request more 
information from another home server before processing the event.

Room Aliases
------------

Each room can also have multiple "Room Aliases", which looks like::

  #room_alias:domain

  .. TODO
      - Need to specify precise grammar for Room IDs

A room alias "points" to a room ID and is the human-readable label by which rooms are
publicised and discovered.  The room ID the alias is pointing to can be obtained
by visiting the domain specified. They are case-insensitive. Note that the mapping 
from a room alias to a room ID is not fixed, and may change over time to point to a 
different room ID. For this reason, Clients SHOULD resolve the room alias to a room ID 
once and then use that ID on subsequent requests.

::

          GET    
   #matrix:domain.com      !aaabaa:matrix.org
           |                    ^
           |                    |
    _______V____________________|____
   |          domain.com            |
   | Mappings:                      |
   | #matrix >> !aaabaa:matrix.org  |
   | #golf   >> !wfeiofh:sport.com  |
   | #bike   >> !4rguxf:matrix.org  |
   |________________________________|

.. TODO kegan
   - show the actual API rather than pseudo-API?

       
Identity
--------

Users in Matrix are identified via their user ID. However, existing ID namespaces can also
be used in order to identify Matrix users. A Matrix "Identity" describes both the user ID
and any other existing IDs from third party namespaces *linked* to their account.

Matrix users can *link* third-party IDs (3PIDs) such as email addresses, social
network accounts and phone numbers to their 
user ID. Linking 3PIDs creates a mapping from a 3PID to a user ID. This mapping
can then be used by other Matrix users in order to discover other users, according
to a strict set of privacy permissions.

In order to ensure that the mapping from 3PID to user ID is genuine, a globally federated
cluster of trusted "Identity Servers" (IS) are used to perform authentication of the 3PID.
Identity servers are also used to preserve the mapping indefinitely, by replicating the
mappings across multiple ISes.

Usage of an IS is not required in order for a client application to be part of 
the Matrix ecosystem. However, by not using an IS, discovery of users is greatly
impacted.

API Standards
-------------

The mandatory baseline for communication in Matrix is exchanging JSON objects over RESTful
HTTP APIs. HTTPS is mandated as the baseline for server-server (federation) communication.
HTTPS is recommended for client-server communication, although HTTP may be supported as a
fallback to support basic HTTP clients. More efficient optional transports for
client-server communication will in future be supported as optional extensions - e.g. a
packed binary encoding over stream-cipher encrypted TCP socket for
low-bandwidth/low-roundtrip mobile usage.

.. TODO
  We need to specify capability negotiation for extensible transports

For the default HTTP transport, all API calls use a Content-Type of ``application/json``.
In addition, all strings MUST be encoded as UTF-8.

Clients are authenticated using opaque ``access_token`` strings (see `Registration and
Login`_ for details), passed as a querystring parameter on all requests.

.. TODO
  Need to specify any HMAC or access_token lifetime/ratcheting tricks

Any errors which occur on the Matrix API level 
MUST return a "standard error response". This is a JSON object which looks like::

  {
    "errcode": "<error code>",
    "error": "<error message>"
  }

The ``error`` string will be a human-readable error message, usually a sentence
explaining what went wrong. The ``errcode`` string will be a unique string which can be 
used to handle an error message e.g. ``M_FORBIDDEN``. These error codes should have their 
namespace first in ALL CAPS, followed by a single _. For example, if there was a custom
namespace ``com.mydomain.here``, and a ``FORBIDDEN`` code, the error code should look
like ``COM.MYDOMAIN.HERE_FORBIDDEN``. There may be additional keys depending on 
the error, but the keys ``error`` and ``errcode`` MUST always be present. 

Some standard error codes are below:

:``M_FORBIDDEN``:
  Forbidden access, e.g. joining a room without permission, failed login.

:``M_UNKNOWN_TOKEN``:
  The access token specified was not recognised.

:``M_BAD_JSON``:
  Request contained valid JSON, but it was malformed in some way, e.g. missing
  required keys, invalid values for keys.

:``M_NOT_JSON``:
  Request did not contain valid JSON.

:``M_NOT_FOUND``:
  No resource was found for this request.

:``M_LIMIT_EXCEEDED``:
  Too many requests have been sent in a short period of time. Wait a while then
  try again.

Some requests have unique error codes:

:``M_USER_IN_USE``:
  Encountered when trying to register a user ID which has been taken.

:``M_ROOM_IN_USE``:
  Encountered when trying to create a room which has been taken.

:``M_BAD_PAGINATION``:
  Encountered when specifying bad pagination query parameters.

:``M_LOGIN_EMAIL_URL_NOT_YET``:
  Encountered when polling for an email link which has not been clicked yet.

The C-S API typically uses ``HTTP POST`` to submit requests. This means these requests are
not idempotent. The C-S API also allows ``HTTP PUT`` to make requests idempotent. In order
to use a ``PUT``, paths should be suffixed with ``/{txnId}``. ``{txnId}`` is a
unique client-generated transaction ID which identifies the request, and is scoped to a given
Client (identified by that client's ``access_token``). Crucially, it **only** serves to
identify new requests from retransmits. After the request has finished, the ``{txnId}``
value should be changed (how is not specified; a monotonically increasing integer is
recommended). It is preferable to use ``HTTP PUT`` to make sure requests to send messages
do not get sent more than once should clients need to retransmit requests.

Valid requests look like::

    POST /some/path/here?access_token=secret
    {
      "key": "This is a post."
    }

    PUT /some/path/here/11?access_token=secret
    {
      "key": "This is a put with a txnId of 11."
    }

In contrast, these are invalid requests::

    POST /some/path/here/11?access_token=secret
    {
      "key": "This is a post, but it has a txnId."
    }

    PUT /some/path/here?access_token=secret
    {
      "key": "This is a put but it is missing a txnId."
    }

Receiving live updates on a client
----------------------------------

Clients can receive new events by long-polling the home server. This will hold open the
HTTP connection for a short period of time waiting for new events, returning early if an
event occurs. This is called the `Event Stream`_. All events which are visible to the
client and match the client's query will appear in the event stream. When the request
returns, an ``end`` token is included in the response. This token can be used in the next
request to continue where the client left off.

.. TODO
  Do we ever return multiple events in a single request?  Don't we get lots of request
  setup RTT latency if we only do one event per request? Do we ever support streaming
  requests? Why not websockets?

When the client first logs in, they will need to initially synchronise with their home
server. This is achieved via the |initialSync|_ API. This API also returns an ``end``
token which can be used with the event stream.

Rooms
=====

Creation
--------
.. TODO kegan
  - TODO: Key for invite these users?
  
To create a room, a client has to use the |createRoom|_ API. There are various options
which can be set when creating a room:

``visibility``
  Type: 
    String
  Optional: 
    Yes
  Value:
    Either ``public`` or ``private``.
  Description:
    A ``public`` visibility indicates that the room will be shown in the public room list. A
    ``private`` visibility will hide the room from the public room list. Rooms default to
    ``public`` visibility if this key is not included.

``room_alias_name``
  Type: 
    String
  Optional: 
    Yes
  Value:
    The room alias localpart.
  Description:
    If this is included, a room alias will be created and mapped to the newly created room.
    The alias will belong on the same home server which created the room, e.g.
    ``!qadnasoi:domain.com >>> #room_alias_name:domain.com``

``name``
  Type: 
    String
  Optional: 
    Yes
  Value:
    The ``name`` value for the ``m.room.name`` state event.
  Description:
    If this is included, an ``m.room.name`` event will be sent into the room to indicate the
    name of the room. See `Room Events`_ for more information on ``m.room.name``.

``topic``
  Type: 
    String
  Optional: 
    Yes
  Value:
    The ``topic`` value for the ``m.room.topic`` state event.
  Description:
    If this is included, an ``m.room.topic`` event will be sent into the room to indicate the
    topic for the room. See `Room Events`_ for more information on ``m.room.topic``.

Example::

  {
    "visibility": "public", 
    "room_alias_name": "the pub",
    "name": "The Grand Duke Pub",
    "topic": "All about happy hour"
  }

The home server will create a ``m.room.create`` event when the room is
created, which serves as the root of the PDU graph for this room. This
event also has a ``creator`` key which contains the user ID of the room
creator. It will also generate several other events in order to manage
permissions in this room. This includes:

 - ``m.room.power_levels`` : Sets the authority of the room creator.
 - ``m.room.join_rules`` : Whether the room is "invite-only" or not.
 - ``m.room.add_state_level``
 - ``m.room.send_event_level`` : The power level required in order to
   send a message in this room.
 - ``m.room.ops_level`` : The power level required in order to kick or
   ban a user from the room.

See `Room Events`_ for more information on these events.

Modifying aliases
-----------------
.. NOTE::
  This section is a work in progress.

.. TODO kegan
    - path to edit aliases 
    - PUT /directory/room/<room alias>  { room_id : foo }
    - GET /directory/room/<room alias> { room_id : foo, servers: [a.com, b.com] }
    - format when retrieving list of aliases. NOT complete list.
    - format for adding/removing aliases.

Permissions
-----------
.. NOTE::
  This section is a work in progress.

.. TODO kegan
    - TODO: What is a power level? How do they work? Defaults / required levels for X. How do they change
      as people join and leave rooms? What do you do if you get a clash? Examples.
    - TODO: List all actions which use power levels (sending msgs, inviting users, banning people, etc...)
    - TODO: Room config - what is the event and what are the keys/values and explanations for them.
      Link through to respective sections where necessary. How does this tie in with permissions, e.g.
      give example of creating a read-only room.


Joining rooms
-------------
.. TODO kegan
  - TODO: What does the home server have to do to join a user to a room?

Users need to join a room in order to send and receive events in that room. A user can join a
room by making a request to |/join/<room_alias_or_id>|_ with::

  {}

Alternatively, a user can make a request to |/rooms/<room_id>/join|_ with the same request content.
This is only provided for symmetry with the other membership APIs: ``/rooms/<room id>/invite`` and
``/rooms/<room id>/leave``. If a room alias was specified, it will be automatically resolved to
a room ID, which will then be joined. The room ID that was joined will be returned in response::

  {
    "room_id": "!roomid:domain"
  }

The membership state for the joining user can also be modified directly to be ``join``
by sending the following request to 
``/rooms/<room id>/state/m.room.member/<url encoded user id>``::

  {
    "membership": "join"
  }

See the `Room events`_ section for more information on ``m.room.member``.

After the user has joined a room, they will receive subsequent events in that room. This room
will now appear as an entry in the |initialSync|_ API.

Some rooms enforce that a user is *invited* to a room before they can join that room. Other
rooms will allow anyone to join the room even if they have not received an invite.

Inviting users
--------------
.. TODO kegan
  - Can invite users to a room if the room config key TODO is set to TODO. Must have required power level.
  - Outline invite join dance. What is it? Why is it required? How does it work?
  - What does the home server have to do?
  - TODO: In what circumstances will direct member editing NOT be equivalent to ``/invite``?

The purpose of inviting users to a room is to notify them that the room exists 
so they can choose to become a member of that room. Some rooms require that all 
users who join a room are previously invited to it (an "invite-only" room). 
Whether a given room is an "invite-only" room is determined by the room config 
key ``TODO``. It can have one of the following values:

 - TODO Room config invite only value explanation
 - TODO Room config free-to-join value explanation

Only users who have a membership state of ``join`` in a room can invite new 
users to said room. The person being invited must not be in the ``join`` state 
in the room. The fully-qualified user ID must be specified when inviting a user, 
as the user may reside on a different home server. To invite a user, send the 
following request to |/rooms/<room_id>/invite|_, which will manage the 
entire invitation process::

  {
    "user_id": "<user id to invite>"
  }

Alternatively, the membership state for this user in this room can be modified 
directly by sending the following request to 
``/rooms/<room id>/state/m.room.member/<url encoded user id>``::

  {
    "membership": "invite"
  }

See the `Room events`_ section for more information on ``m.room.member``.

Leaving rooms
-------------
.. TODO kegan
  - TODO: Grace period before deletion?
  - TODO: Under what conditions should a room NOT be purged?


A user can leave a room to stop receiving events for that room. A user must have
joined the room before they are eligible to leave the room. If the room is an
"invite-only" room, they will need to be re-invited before they can re-join the room.
To leave a room, a request should be made to |/rooms/<room_id>/leave|_ with::

  {}

Alternatively, the membership state for this user in this room can be modified 
directly by sending the following request to 
``/rooms/<room id>/state/m.room.member/<url encoded user id>``::

  {
    "membership": "leave"
  }

See the `Room events`_ section for more information on ``m.room.member``.

Once a user has left a room, that room will no longer appear on the |initialSync|_
API. Be aware that leaving a room is not equivalent to have never been
in that room. A user who has previously left a room still maintains some residual state in
that room. Their membership state will be marked as ``leave``. This contrasts with
a user who has *never been invited or joined to that room* who will not have any
membership state for that room. 

If all members in a room leave, that room becomes eligible for deletion. 

Banning users in a room
-----------------------
A user may decide to ban another user in a room. 'Banning' forces the target user
to leave the room and prevents them from re-joining the room. A banned user will
not be treated as a joined user, and so will not be able to send or receive events
in the room. In order to ban someone, the user performing the ban MUST have the 
required power level. To ban a user, a request should be made to 
|/rooms/<room_id>/ban|_ with::

  {
    "user_id": "<user id to ban"
    "reason": "string: <reason for the ban>"
  }
  
Banning a user adjusts the banned member's membership state to ``ban`` and adjusts
the power level of this event to a level higher than the banned person. Like 
with other membership changes, a user can directly adjust the target member's 
state, by making a request to ``/rooms/<room id>/state/m.room.member/<user id>``::

  {
    "membership": "ban"
  }

Events in a room
----------------
Room events can be split into two categories:

:State Events:
  These are events which replace events that came before it, depending on a set of unique keys.
  These keys are the event ``type`` and a ``state_key``. Events with the same set of keys will
  be overwritten. Typically, state events are used to store state, hence their name.

:Non-state events:
  These are events which cannot be overwritten after sending. The list of events continues
  to grow as more events are sent. As this list grows, it becomes necessary to
  provide a mechanism for navigating this list. Pagination APIs are used to view the list
  of historical non-state events. Typically, non-state events are used to send messages.

This specification outlines several events, all with the event type prefix ``m.``. However,
applications may wish to add their own type of event, and this can be achieved using the 
REST API detailed in the following sections. If new events are added, the event ``type`` 
key SHOULD follow the Java package naming convention, e.g. ``com.example.myapp.event``. 
This ensures event types are suitably namespaced for each application and reduces the 
risk of clashes.

State events
------------
State events can be sent by ``PUT`` ing to |/rooms/<room_id>/state/<event_type>/<state_key>|_.
These events will be overwritten if ``<room id>``, ``<event type>`` and ``<state key>`` all match.
If the state event has no ``state_key``, it can be omitted from the path. These requests 
**cannot use transaction IDs** like other ``PUT`` paths because they cannot be differentiated 
from the ``state_key``. Furthermore, ``POST`` is unsupported on state paths. Valid requests
look like::

  PUT /rooms/!roomid:domain/state/m.example.event
  { "key" : "without a state key" }

  PUT /rooms/!roomid:domain/state/m.another.example.event/foo
  { "key" : "with 'foo' as the state key" }

In contrast, these requests are invalid::

  POST /rooms/!roomid:domain/state/m.example.event/
  { "key" : "cannot use POST here" }

  PUT /rooms/!roomid:domain/state/m.another.example.event/foo/11
  { "key" : "txnIds are not supported" }

Care should be taken to avoid setting the wrong ``state key``::

  PUT /rooms/!roomid:domain/state/m.another.example.event/11
  { "key" : "with '11' as the state key, but was probably intended to be a txnId" }

The ``state_key`` is often used to store state about individual users, by using the user ID as the
``state_key`` value. For example::

  PUT /rooms/!roomid:domain/state/m.favorite.animal.event/%40my_user%3Adomain.com
  { "animal" : "cat", "reason": "fluffy" }

In some cases, there may be no need for a ``state_key``, so it can be omitted::

  PUT /rooms/!roomid:domain/state/m.room.bgd.color
  { "color": "red", "hex": "#ff0000" }

See `Room Events`_ for the ``m.`` event specification.

Non-state events
----------------
Non-state events can be sent by sending a request to |/rooms/<room_id>/send/<event_type>|_.
These requests *can* use transaction IDs and ``PUT``/``POST`` methods. Non-state events 
allow access to historical events and pagination, making it best suited for sending messages.
For example::

  POST /rooms/!roomid:domain/send/m.custom.example.message
  { "text": "Hello world!" }

  PUT /rooms/!roomid:domain/send/m.custom.example.message/11
  { "text": "Goodbye world!" }

See `Room Events`_ for the ``m.`` event specification.

Syncing rooms
-------------
.. NOTE::
  This section is a work in progress.

When a client logs in, they may have a list of rooms which they have already joined. These rooms
may also have a list of events associated with them. The purpose of 'syncing' is to present the
current room and event information in a convenient, compact manner. The events returned are not
limited to room events; presence events will also be returned. There are two APIs provided:

 - |initialSync|_ : A global sync which will present room and event information for all rooms
   the user has joined.

 - |/rooms/<room_id>/initialSync|_ : A sync scoped to a single room. Presents room and event
   information for this room only.

.. TODO kegan
  - TODO: JSON response format for both types
  - TODO: when would you use global? when would you use scoped?

Getting events for a room
-------------------------
There are several APIs provided to ``GET`` events for a room:

``/rooms/<room id>/state/<event type>/<state key>``
  Description:
    Get the state event identified.
  Response format:
    A JSON object representing the state event **content**.
  Example:
    ``/rooms/!room:domain.com/state/m.room.name`` returns ``{ "name": "Room name" }``

|/rooms/<room_id>/state|_
  Description:
    Get all state events for a room.
  Response format:
    ``[ { state event }, { state event }, ... ]``
  Example:
    TODO


|/rooms/<room_id>/members|_
  Description:
    Get all ``m.room.member`` state events.
  Response format:
    ``{ "start": "token", "end": "token", "chunk": [ { m.room.member event }, ... ] }``
  Example:
    TODO

|/rooms/<room_id>/messages|_
  Description:
    Get all ``m.room.message`` events.
  Response format:
    ``{ TODO }``
  Example:
    TODO
    
|/rooms/<room_id>/initialSync|_
  Description:
    Get all relevant events for a room. This includes state events, paginated non-state
    events and presence events.
  Response format:
    `` { TODO } ``
  Example:
    TODO


Room Events
===========
.. NOTE::
  This section is a work in progress.

.. TODO dave?
  - voip events?

This specification outlines several standard event types, all of which are
prefixed with ``m.``

``m.room.name``
  Summary:
    Set the human-readable name for the room.
  Type: 
    State event
  JSON format:
    ``{ "name" : "string" }``
  Example:
    ``{ "name" : "My Room" }``
  Description:
    A room has an opaque room ID which is not human-friendly to read. A room alias is
    human-friendly, but not all rooms have room aliases. The room name is a human-friendly
    string designed to be displayed to the end-user. The room name is not *unique*, as
    multiple rooms can have the same room name set. The room name can also be set when 
    creating a room using |createRoom|_ with the ``name`` key.

``m.room.topic``
  Summary:
    Set a topic for the room.
  Type: 
    State event
  JSON format:
    ``{ "topic" : "string" }``
  Example:
    ``{ "topic" : "Welcome to the real world." }``
  Description:
    A topic is a short message detailing what is currently being discussed in the room. 
    It can also be used as a way to display extra information about the room, which may
    not be suitable for the room name. The room topic can also be set when creating a
    room using |createRoom|_ with the ``topic`` key.

``m.room.member``
  Summary:
    The current membership state of a user in the room.
  Type: 
    State event
  JSON format:
    ``{ "membership" : "enum[ invite|join|leave|ban ]" }``
  Example:
    ``{ "membership" : "join" }``
  Description:
    Adjusts the membership state for a user in a room. It is preferable to use the
    membership APIs (``/rooms/<room id>/invite`` etc) when performing membership actions
    rather than adjusting the state directly as there are a restricted set of valid
    transformations. For example, user A cannot force user B to join a room, and trying
    to force this state change directly will fail. See the `Rooms`_ section for how to 
    use the membership APIs.

``m.room.config``
  Summary:
    The room config.
  Type: 
    State event
  JSON format:
    TODO
  Example:
    TODO
  Description:
    TODO : What it represents, What are the valid keys / values and what they represent, When is this event emitted and by what

``m.room.invite_join``
  Summary:
    TODO.
  Type: 
    State event
  JSON format:
    TODO
  Example:
    TODO
  Description:
    TODO : What it represents, What are the valid keys / values and what they represent, When is this event emitted and by what
    
``m.room.join_rules``
  Summary:
    TODO.
  Type: 
    State event
  JSON format:
    TODO
  Example:
    TODO
  Description:
    TODO : What it represents, What are the valid keys / values and what they represent, When is this event emitted and by what
    
``m.room.power_levels``
  Summary:
    TODO.
  Type: 
    State event
  JSON format:
    TODO
  Example:
    TODO
  Description:
    TODO : What it represents, What are the valid keys / values and what they represent, When is this event emitted and by what
    
``m.room.add_state_level``
  Summary:
    TODO.
  Type: 
    State event
  JSON format:
    TODO
  Example:
    TODO
  Description:
    TODO : What it represents, What are the valid keys / values and what they represent, When is this event emitted and by what
    
``m.room.send_event_level``
  Summary:
    TODO.
  Type: 
    State event
  JSON format:
    TODO
  Example:
    TODO
  Description:
    TODO : What it represents, What are the valid keys / values and what they represent, When is this event emitted and by what
    
``m.room.ops_levels``
  Summary:
    TODO.
  Type: 
    State event
  JSON format:
    TODO
  Example:
    TODO
  Description:
    TODO : What it represents, What are the valid keys / values and what they represent, When is this event emitted and by what

``m.room.message``
  Summary:
    A message.
  Type: 
    Non-state event
  JSON format:
    ``{ "msgtype": "string" }``
  Example:
    ``{ "msgtype": "m.text", "body": "Testing" }``
  Description:
    This event is used when sending messages in a room. Messages are not limited to be text.
    The ``msgtype`` key outlines the type of message, e.g. text, audio, image, video, etc.
    Whilst not required, the ``body`` key SHOULD be used with every kind of ``msgtype`` as
    a fallback mechanism when a client cannot render the message. For more information on 
    the types of messages which can be sent, see `m.room.message msgtypes`_.

``m.room.message.feedback``
  Summary:
    A receipt for a message.
  Type: 
    Non-state event
  JSON format:
    ``{ "type": "enum [ delivered|read ]", "target_event_id": "string" }``
  Example:
    ``{ "type": "delivered", "target_event_id": "e3b2icys" }``
  Description:
    Feedback events are events sent to acknowledge a message in some way. There are two
    supported acknowledgements: ``delivered`` (sent when the event has been received) and 
    ``read`` (sent when the event has been observed by the end-user). The ``target_event_id``
    should reference the ``m.room.message`` event being acknowledged. 

m.room.message msgtypes
-----------------------
Each ``m.room.message`` MUST have a ``msgtype`` key which identifies the type of
message being sent. Each type has their own required and optional keys, as outlined
below:

``m.text``
  Required keys:
    - ``body`` : "string" - The body of the message.
  Optional keys:
    None.
  Example:
    ``{ "msgtype": "m.text", "body": "I am a fish" }``

``m.emote``
  Required keys:
    - ``body`` : "string" - The emote action to perform.
  Optional keys:
    None.
  Example:
    ``{ "msgtype": "m.emote", "body": "tries to come up with a witty explanation" }``

``m.image``
  Required keys:
    - ``url`` : "string" - The URL to the image.
  Optional keys:
    - ``info`` : "string" - info : JSON object (ImageInfo) - The image info for image 
      referred to in ``url``.
    - ``thumbnail_url`` : "string" - The URL to the thumbnail.
    - ``thumbnail_info`` : JSON object (ImageInfo) - The image info for the image 
      referred to in ``thumbnail_url``.
    - ``body`` : "string" - The alt text of the image, or some kind of content 
      description for accessibility e.g. "image attachment".

  ImageInfo: 
    Information about an image::
    
      { 
        "size" : integer (size of image in bytes),
        "w" : integer (width of image in pixels),
        "h" : integer (height of image in pixels),
        "mimetype" : "string (e.g. image/jpeg)",
      }

``m.audio``
  Required keys:
    - ``url`` : "string" - The URL to the audio.
  Optional keys:
    - ``info`` : JSON object (AudioInfo) - The audio info for the audio referred to in 
      ``url``.
    - ``body`` : "string" - A description of the audio e.g. "Bee Gees - 
      Stayin' Alive", or some kind of content description for accessibility e.g. 
      "audio attachment".
  AudioInfo: 
    Information about a piece of audio::

      {
        "mimetype" : "string (e.g. audio/aac)",
        "size" : integer (size of audio in bytes),
        "duration" : integer (duration of audio in milliseconds),
      }

``m.video``
  Required keys:
    - ``url`` : "string" - The URL to the video.
  Optional keys:
    - ``info`` : JSON object (VideoInfo) - The video info for the video referred to in 
      ``url``.
    - ``body`` : "string" - A description of the video e.g. "Gangnam style", 
      or some kind of content description for accessibility e.g. "video attachment".

  VideoInfo: 
    Information about a video::

      {
        "mimetype" : "string (e.g. video/mp4)",
        "size" : integer (size of video in bytes),
        "duration" : integer (duration of video in milliseconds),
        "w" : integer (width of video in pixels),
        "h" : integer (height of video in pixels),
        "thumbnail_url" : "string (URL to image)",
        "thumbanil_info" : JSON object (ImageInfo)
      }

``m.location``
  Required keys:
    - ``geo_uri`` : "string" - The geo URI representing the location.
  Optional keys:
    - ``thumbnail_url`` : "string" - The URL to a thumnail of the location being 
      represented.
    - ``thumbnail_info`` : JSON object (ImageInfo) - The image info for the image 
      referred to in ``thumbnail_url``.
    - ``body`` : "string" - A description of the location e.g. "Big Ben, 
      London, UK", or some kind of content description for accessibility e.g. 
      "location attachment".

The following keys can be attached to any ``m.room.message``:

  Optional keys:
    - ``sender_ts`` : integer - A timestamp (ms resolution) representing the 
      wall-clock time when the message was sent from the client.

Presence
========
.. NOTE::
  This section is a work in progress.

Each user has the concept of presence information. This encodes the
"availability" of that user, suitable for display on other user's clients. This
is transmitted as an ``m.presence`` event and is one of the few events which
are sent *outside the context of a room*. The basic piece of presence information 
is represented by the ``presence`` key, which is an enum of one of the following:

  - ``online`` : The default state when the user is connected to an event stream.
  - ``unavailable`` : The user is not reachable at this time.
  - ``offline`` : The user is not connected to an event stream.
  - ``free_for_chat`` : The user is generally willing to receive messages 
    moreso than default.
  - ``hidden`` : TODO. Behaves as offline, but allows the user to see the client 
    state anyway and generally interact with client features.

This basic ``presence`` field applies to the user as a whole, regardless of how many
client devices they have connected. The home server should synchronise this
status choice among multiple devices to ensure the user gets a consistent
experience.

In addition, the server maintains a timestamp of the last time it saw an active
action from the user; either sending a message to a room, or changing presence
state from a lower to a higher level of availability (thus: changing state from
``unavailable`` to ``online`` will count as an action for being active, whereas
in the other direction will not). This timestamp is presented via a key called
``last_active_ago``, which gives the relative number of miliseconds since the
message is generated/emitted, that the user was last seen active.

Idle Time
---------
As well as the basic ``presence`` field, the presence information can also show
a sense of an "idle timer". This should be maintained individually by the
user's clients, and the home server can take the highest reported time as that
to report. When a user is offline, the home server can still report when the
user was last seen online.

Transmission
------------
.. NOTE::
  This section is a work in progress.

.. TODO:
  - Transmitted as an EDU.
  - Presence lists determine who to send to.

Presence List
-------------
Each user's home server stores a "presence list" for that user. This stores a
list of other user IDs the user has chosen to add to it. To be added to this 
list, the user being added must receive permission from the list owner. Once
granted, both user's HS(es) store this information. Since such subscriptions
are likely to be bidirectional, HSes may wish to automatically accept requests
when a reverse subscription already exists.

Presence and Permissions
------------------------
For a viewing user to be allowed to see the presence information of a target
user, either:

 - The target user has allowed the viewing user to add them to their presence
   list, or
 - The two users share at least one room in common

In the latter case, this allows for clients to display some minimal sense of
presence information in a user list for a room.

Typing notifications
====================
.. NOTE::
  This section is a work in progress.

.. TODO Leo
    - what is the event type. Are they bundled with other event types? If so, which.
    - what are the valid keys / values. What do they represent. Any gotchas?
    - Timeouts. How do they work, who sets them and how do they expire. Does one
      have priority over another? Give examples.

Voice over IP
=============
.. NOTE::
  This section is a work in progress.

.. TODO Dave
    - what are the event types.
    - what are the valid keys/values. What do they represent. Any gotchas?
    - In what sequence should the events be sent?
    - How do you accept / decline inbound calls? How do you make outbound calls?
      Give examples.
    - How does negotiation work? Give examples.
    - How do you hang up?
    - What does call log information look like e.g. duration of call?

Profiles
========
.. NOTE::
  This section is a work in progress.

.. TODO
  - Metadata extensibility
  - Changing profile info generates m.presence events ("presencelike")
  - keys on m.presence are optional, except presence which is required
  - m.room.member is populated with the current displayname at that point in time.
  - That is added by the HS, not you.
  - Display name changes also generates m.room.member with displayname key f.e. room
    the user is in.

Internally within Matrix users are referred to by their user ID, which is not a
human-friendly string. Profiles grant users the ability to see human-readable 
names for other users that are in some way meaningful to them. Additionally, 
profiles can publish additional information, such as the user's age or location.

A Profile consists of a display name, an avatar picture, and a set of other 
metadata fields that the user may wish to publish (email address, phone
numbers, website URLs, etc...). This specification puts no requirements on the 
display name other than it being a valid unicode string.



Registration and login
======================
.. WARNING::
  The registration API is likely to change.

.. TODO
  - TODO Kegan : Make registration like login (just omit the "user" key on the 
    initial request?)

Clients must register with a home server in order to use Matrix. After 
registering, the client will be given an access token which must be used in ALL
requests to that home server as a query parameter 'access_token'.

If the client has already registered, they need to be able to login to their
account. The home server may provide many different ways of logging in, such
as user/password auth, login via a social network (OAuth2), login by confirming 
a token sent to their email address, etc. This specification does not define how
home servers should authorise their users who want to login to their existing 
accounts, but instead defines the standard interface which implementations 
should follow so that ANY client can login to ANY home server. Clients login
using the |login|_ API.

The login process breaks down into the following:
  1. Determine the requirements for logging in.
  2. Submit the login stage credentials.
  3. Get credentials or be told the next stage in the login process and repeat 
     step 2.
     
As each home server may have different ways of logging in, the client needs to know how
they should login. All distinct login stages MUST have a corresponding ``type``.
A ``type`` is a namespaced string which details the mechanism for logging in.

A client may be able to login via multiple valid login flows, and should choose a single
flow when logging in. A flow is a series of login stages. The home server MUST respond 
with all the valid login flows when requested::

  The client can login via 3 paths: 1a and 1b, 2a and 2b, or 3. The client should
  select one of these paths.
  
  {
    "flows": [
      {
        "type": "<login type1a>",
        "stages": [ "<login type 1a>", "<login type 1b>" ]
      },
      {
        "type": "<login type2a>",
        "stages": [ "<login type 2a>", "<login type 2b>" ]
      },
      {
        "type": "<login type3>"
      }
    ]
  }

After the login is completed, the client's fully-qualified user ID and a new access 
token MUST be returned::

  {
    "user_id": "@user:matrix.org",
    "access_token": "abcdef0123456789"
  }

The ``user_id`` key is particularly useful if the home server wishes to support 
localpart entry of usernames (e.g. "user" rather than "@user:matrix.org"), as the
client may not be able to determine its ``user_id`` in this case.

If a login has multiple requests, the home server may wish to create a session. If
a home server responds with a 'session' key to a request, clients MUST submit it in 
subsequent requests until the login is completed::

  {
    "session": "<session id>"
  }

This specification defines the following login types:
 - ``m.login.password``
 - ``m.login.oauth2``
 - ``m.login.email.code``
 - ``m.login.email.url``


Password-based
--------------
:Type: 
  ``m.login.password``
:Description: 
  Login is supported via a username and password.

To respond to this type, reply with::

  {
    "type": "m.login.password",
    "user": "<user_id or user localpart>",
    "password": "<password>"
  }

The home server MUST respond with either new credentials, the next stage of the login
process, or a standard error response.

OAuth2-based
------------
:Type: 
  ``m.login.oauth2``
:Description:
  Login is supported via OAuth2 URLs. This login consists of multiple requests.

To respond to this type, reply with::

  {
    "type": "m.login.oauth2",
    "user": "<user_id or user localpart>"
  }

The server MUST respond with::

  {
    "uri": <Authorization Request URI OR service selection URI>
  }

The home server acts as a 'confidential' client for the purposes of OAuth2.
If the uri is a ``sevice selection URI``, it MUST point to a webpage which prompts the 
user to choose which service to authorize with. On selection of a service, this
MUST link through to an ``Authorization Request URI``. If there is only 1 service which the
home server accepts when logging in, this indirection can be skipped and the
"uri" key can be the ``Authorization Request URI``. 

The client then visits the ``Authorization Request URI``, which then shows the OAuth2 
Allow/Deny prompt. Hitting 'Allow' returns the ``redirect URI`` with the auth code. 
Home servers can choose any path for the ``redirect URI``. The client should visit 
the ``redirect URI``, which will then finish the OAuth2 login process, granting the 
home server an access token for the chosen service. When the home server gets 
this access token, it verifies that the cilent has authorised with the 3rd party, and 
can now complete the login. The OAuth2 ``redirect URI`` (with auth code) MUST respond 
with either new credentials, the next stage of the login process, or a standard error 
response.
    
For example, if a home server accepts OAuth2 from Google, it would return the 
Authorization Request URI for Google::

  {
    "uri": "https://accounts.google.com/o/oauth2/auth?response_type=code&
    client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&scope=photos"
  }

The client then visits this URI and authorizes the home server. The client then
visits the REDIRECT_URI with the auth code= query parameter which returns::

  {
    "user_id": "@user:matrix.org",
    "access_token": "0123456789abcdef"
  }

Email-based (code)
------------------
:Type: 
  ``m.login.email.code``
:Description:
  Login is supported by typing in a code which is sent in an email. This login 
  consists of multiple requests.

To respond to this type, reply with::

  {
    "type": "m.login.email.code",
    "user": "<user_id or user localpart>",
    "email": "<email address>"
  }

After validating the email address, the home server MUST send an email containing
an authentication code and return::

  {
    "type": "m.login.email.code",
    "session": "<session id>"
  }

The second request in this login stage involves sending this authentication code::

  {
    "type": "m.login.email.code",
    "session": "<session id>",
    "code": "<code in email sent>"
  }

The home server MUST respond to this with either new credentials, the next stage of 
the login process, or a standard error response.

Email-based (url)
-----------------
:Type: 
  ``m.login.email.url``
:Description:
  Login is supported by clicking on a URL in an email. This login consists of 
  multiple requests.

To respond to this type, reply with::

  {
    "type": "m.login.email.url",
    "user": "<user_id or user localpart>",
    "email": "<email address>"
  }

After validating the email address, the home server MUST send an email containing
an authentication URL and return::

  {
    "type": "m.login.email.url",
    "session": "<session id>"
  }

The email contains a URL which must be clicked. After it has been clicked, the
client should perform another request::

  {
    "type": "m.login.email.url",
    "session": "<session id>"
  }

The home server MUST respond to this with either new credentials, the next stage of 
the login process, or a standard error response. 

A common client implementation will be to periodically poll until the link is clicked.
If the link has not been visited yet, a standard error response with an errcode of 
``M_LOGIN_EMAIL_URL_NOT_YET`` should be returned.


N-Factor Authentication
-----------------------
Multiple login stages can be combined to create N-factor authentication during login.

This can be achieved by responding with the ``next`` login type on completion of a 
previous login stage::

  {
    "next": "<next login type>"
  }

If a home server implements N-factor authentication, it MUST respond with all 
``stages`` when initially queried for their login requirements::

  {
    "type": "<1st login type>",
    "stages": [ <1st login type>, <2nd login type>, ... , <Nth login type> ]
  }

This can be represented conceptually as::

   _______________________
  |    Login Stage 1      |
  | type: "<login type1>" |
  |  ___________________  |
  | |_Request_1_________| | <-- Returns "session" key which is used throughout.
  |  ___________________  |     
  | |_Request_2_________| | <-- Returns a "next" value of "login type2"
  |_______________________|
            |
            |
   _________V_____________
  |    Login Stage 2      |
  | type: "<login type2>" |
  |  ___________________  |
  | |_Request_1_________| |
  |  ___________________  |
  | |_Request_2_________| |
  |  ___________________  |
  | |_Request_3_________| | <-- Returns a "next" value of "login type3"
  |_______________________|
            |
            |
   _________V_____________
  |    Login Stage 3      |
  | type: "<login type3>" |
  |  ___________________  |
  | |_Request_1_________| | <-- Returns user credentials
  |_______________________|

Fallback
--------
Clients cannot be expected to be able to know how to process every single
login type. If a client determines it does not know how to handle a given
login type, it should request a login fallback page::

  GET matrix/client/api/v1/login/fallback

This MUST return an HTML page which can perform the entire login process.

Identity
========
.. NOTE::
  This section is a work in progress.

.. TODO Dave
  - 3PIDs and identity server, functions

Federation
==========

Federation is the term used to describe how to communicate between Matrix home 
servers. Federation is a mechanism by which two home servers can exchange
Matrix event messages, both as a real-time push of current events, and as a
historic fetching mechanism to synchronise past history for clients to view. It
uses HTTP connections between each pair of servers involved as the underlying
transport. Messages are exchanged between servers in real-time by active pushing
from each server's HTTP client into the server of the other. Queries to fetch
historic data for the purpose of back-filling scrollback buffers and the like
can also be performed.

There are three main kinds of communication that occur between home servers:

:Queries:
   These are single request/response interactions between a given pair of
   servers, initiated by one side sending an HTTP GET request to obtain some
   information, and responded by the other. They are not persisted and contain
   no long-term significant history. They simply request a snapshot state at the
   instant the query is made.

:Ephemeral Data Units (EDUs):
   These are notifications of events that are pushed from one home server to
   another. They are not persisted and contain no long-term significant history,
   nor does the receiving home server have to reply to them.

:Persisted Data Units (PDUs):
   These are notifications of events that are broadcast from one home server to
   any others that are interested in the same "context" (namely, a Room ID).
   They are persisted to long-term storage and form the record of history for
   that context.

EDUs and PDUs are further wrapped in an envelope called a Transaction, which is 
transferred from the origin to the destination home server using an HTTP PUT request.


Transactions
------------
.. WARNING::
  This section may be misleading or inaccurate.

The transfer of EDUs and PDUs between home servers is performed by an exchange
of Transaction messages, which are encoded as JSON objects, passed over an 
HTTP PUT request. A Transaction is meaningful only to the pair of home servers that 
exchanged it; they are not globally-meaningful.

Each transaction has:
 - An opaque transaction ID.
 - A timestamp (UNIX epoch time in milliseconds) generated by its origin server.
 - An origin and destination server name.
 - A list of "previous IDs".
 - A list of PDUs and EDUs - the actual message payload that the Transaction carries.

::

 {
  "transaction_id":"916d630ea616342b42e98a3be0b74113",
  "ts":1404835423000,
  "origin":"red",
  "destination":"blue",
  "prev_ids":["e1da392e61898be4d2009b9fecce5325"],
  "pdus":[...],
  "edus":[...]
 }

The ``prev_ids`` field contains a list of previous transaction IDs that
the ``origin`` server has sent to this ``destination``. Its purpose is to act as a
sequence checking mechanism - the destination server can check whether it has
successfully received that Transaction, or ask for a retransmission if not.

The ``pdus`` field of a transaction is a list, containing zero or more PDUs.[*]
Each PDU is itself a JSON object containing a number of keys, the exact details of
which will vary depending on the type of PDU. Similarly, the ``edus`` field is
another list containing the EDUs. This key may be entirely absent if there are
no EDUs to transfer.

(* Normally the PDU list will be non-empty, but the server should cope with
receiving an "empty" transaction, as this is useful for informing peers of other
transaction IDs they should be aware of. This effectively acts as a push
mechanism to encourage peers to continue to replicate content.)

PDUs and EDUs
-------------
.. WARNING::
  This section may be misleading or inaccurate.

All PDUs have:
 - An ID
 - A context
 - A declaration of their type
 - A list of other PDU IDs that have been seen recently on that context (regardless of which origin
   sent them)

[[TODO(paul): Update this structure so that 'pdu_id' is a two-element
[origin,ref] pair like the prev_pdus are]]

::

 {
  "pdu_id":"a4ecee13e2accdadf56c1025af232176",
  "context":"#example.green",
  "origin":"green",
  "ts":1404838188000,
  "pdu_type":"m.text",
  "prev_pdus":[["blue","99d16afbc857975916f1d73e49e52b65"]],
  "content":...
  "is_state":false
 }

In contrast to Transactions, it is important to note that the ``prev_pdus``
field of a PDU refers to PDUs that any origin server has sent, rather than
previous IDs that this ``origin`` has sent. This list may refer to other PDUs sent
by the same origin as the current one, or other origins.

Because of the distributed nature of participants in a Matrix conversation, it
is impossible to establish a globally-consistent total ordering on the events.
However, by annotating each outbound PDU at its origin with IDs of other PDUs it
has received, a partial ordering can be constructed allowing causallity
relationships to be preserved. A client can then display these messages to the
end-user in some order consistent with their content and ensure that no message
that is semantically in reply of an earlier one is ever displayed before it.

PDUs fall into two main categories: those that deliver Events, and those that
synchronise State. For PDUs that relate to State synchronisation, additional
keys exist to support this:

::

 {...,
  "is_state":true,
  "state_key":TODO
  "power_level":TODO
  "prev_state_id":TODO
  "prev_state_origin":TODO}

[[TODO(paul): At this point we should probably have a long description of how
State management works, with descriptions of clobbering rules, power levels, etc
etc... But some of that detail is rather up-in-the-air, on the whiteboard, and
so on. This part needs refining. And writing in its own document as the details
relate to the server/system as a whole, not specifically to server-server
federation.]]

EDUs, by comparison to PDUs, do not have an ID, a context, or a list of
"previous" IDs. The only mandatory fields for these are the type, origin and
destination home server names, and the actual nested content.

::

 {"edu_type":"m.presence",
  "origin":"blue",
  "destination":"orange",
  "content":...}

Backfilling
-----------
.. NOTE::
  This section is a work in progress.

.. TODO
  - What it is, when is it used, how is it done

SRV Records
-----------
.. NOTE::
  This section is a work in progress.

.. TODO
  - Why it is needed

Security
========
.. NOTE::
  This section is a work in progress.

Rate limiting
-------------
Home servers SHOULD implement rate limiting to reduce the risk of being overloaded. If a
request is refused due to rate limiting, it should return a standard error response of
the form::

  {
    "errcode": "M_LIMIT_EXCEEDED",
    "error": "string",
    "retry_after_ms": integer (optional)
  }

The ``retry_after_ms`` key SHOULD be included to tell the client how long they have to wait
in milliseconds before they can try again.

.. TODO
  - crypto (s-s auth)
  - E2E
  - Lawful intercept + Key Escrow
  TODO Mark

Policy Servers
==============
.. NOTE::
  This section is a work in progress.

Content repository
==================
.. NOTE::
  This section is a work in progress.

.. TODO
  - path to upload
  - format for thumbnail paths, mention what it is protecting against.
  - content size limit and associated M_ERROR.

Address book repository
=======================
.. NOTE::
  This section is a work in progress.

.. TODO
  - format: POST(?) wodges of json, some possible processing, then return wodges of json on GET.
  - processing may remove dupes, merge contacts, pepper with extra info (e.g. matrix-ability of
    contacts), etc.
  - Standard json format for contacts? Piggy back off vcards?


Glossary
========
.. NOTE::
  This section is a work in progress.

.. TODO
  - domain specific words/acronyms with definitions

User ID:
  An opaque ID which identifies an end-user, which consists of some opaque 
  localpart combined with the domain name of their home server. 


.. Links through the external API docs are below
.. =============================================

.. |createRoom| replace:: ``/createRoom``
.. _createRoom: /-rooms/create_room

.. |initialSync| replace:: ``/initialSync``
.. _initialSync: /-events/initial_sync

.. |/rooms/<room_id>/initialSync| replace:: ``/rooms/<room_id>/initialSync``
.. _/rooms/<room_id>/initialSync: /-rooms/get_room_sync_data

.. |login| replace:: ``/login``
.. _login: /-login

.. |/rooms/<room_id>/messages| replace:: ``/rooms/<room_id>/messages``
.. _/rooms/<room_id>/messages: /-rooms/get_messages

.. |/rooms/<room_id>/members| replace:: ``/rooms/<room_id>/members``
.. _/rooms/<room_id>/members: /-rooms/get_members

.. |/rooms/<room_id>/state| replace:: ``/rooms/<room_id>/state``
.. _/rooms/<room_id>/state: /-rooms/get_state_events

.. |/rooms/<room_id>/send/<event_type>| replace:: ``/rooms/<room_id>/send/<event_type>``
.. _/rooms/<room_id>/send/<event_type>: /-rooms/send_non_state_event

.. |/rooms/<room_id>/state/<event_type>/<state_key>| replace:: ``/rooms/<room_id>/state/<event_type>/<state_key>``
.. _/rooms/<room_id>/state/<event_type>/<state_key>: /-rooms/send_state_event

.. |/rooms/<room_id>/invite| replace:: ``/rooms/<room_id>/invite``
.. _/rooms/<room_id>/invite: /-rooms/invite

.. |/rooms/<room_id>/join| replace:: ``/rooms/<room_id>/join``
.. _/rooms/<room_id>/join: /-rooms/join_room

.. |/rooms/<room_id>/leave| replace:: ``/rooms/<room_id>/leave``
.. _/rooms/<room_id>/leave: /-rooms/leave

.. |/rooms/<room_id>/ban| replace:: ``/rooms/<room_id>/ban``
.. _/rooms/<room_id>/ban: /-rooms/ban

.. |/join/<room_alias_or_id>| replace:: ``/join/<room_alias_or_id>``
.. _/join/<room_alias_or_id>: /-rooms/join

.. _`Event Stream`: /-events/get_event_stream
