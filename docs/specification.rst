Matrix Specification
====================

WARNING
=======

.. WARNING::
  The Matrix specification is still very much evolving: the API is not yet frozen
  and this document is in places incomplete, stale, and may contain security
  issues. Needless to say, we have made every effort to highlight the problem
  areas that we're aware of.

  We're publishing it at this point because it's complete enough to be more than
  useful and provide a canonical reference to how Matrix is evolving. Our end
  goal is to mirror WHATWG's `Living Standard <http://wiki.whatwg.org/wiki/FAQ#What_does_.22Living_Standard.22_mean.3F>`_   
  approach except right now Matrix is more in the process of being born than actually being
  living!

.. contents:: Table of Contents
.. sectnum::

Matrix is a new set of open APIs for open-federated Instant Messaging and VoIP
functionality, designed to create and support a new global real-time
communication ecosystem on the internet. This specification is the ongoing
result of standardising the APIs used by the various components of the Matrix
ecosystem to communicate with one another.

The principles that Matrix attempts to follow are:

- Pragmatic Web-friendly APIs (i.e. JSON over REST)
- Keep It Simple & Stupid

  + provide a simple architecture with minimal third-party dependencies.

- Fully open:

  + Fully open federation - anyone should be able to participate in the global
    Matrix network
  + Fully open standard - publicly documented standard with no IP or patent
    licensing encumbrances
  + Fully open source reference implementation - liberally-licensed example
    implementations with no IP or patent licensing encumbrances

- Empowering the end-user

  + The user should be able to choose the server and clients they use
  + The user should be control how private their communication is
  + The user should know precisely where their data is stored

- Fully decentralised - no single points of control over conversations or the
  network as a whole
- Learning from history to avoid repeating it

  + Trying to take the best aspects of XMPP, SIP, IRC, SMTP, IMAP and NNTP
    whilst trying to avoid their failings

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

  + Publishing user public keys for PKI
  + Mapping of 3PIDs to Matrix IDs

The end goal of Matrix is to be a ubiquitous messaging layer for synchronising
arbitrary data between sets of people, devices and services - be that for
instant messages, VoIP call setups, or any other objects that need to be
reliably and persistently pushed from A to B in an interoperable and federated
manner.

Basis
=====

Architecture
------------

Clients transmit data to other clients through home servers (HSes). Clients do
not communicate with each other directly.

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

A "Client" typically represents a human using a web application or mobile app.
Clients use the "Client-to-Server" (C-S) API to communicate with their home
server, which stores their profile data and their record of the conversations
in which they participate. Each client is associated with a user account (and
may optionally support multiple user accounts). A user account is represented
by a unique "User ID". This ID is namespaced to the home server which allocated
the account and looks like::

  @localpart:domain

The ``localpart`` of a user ID may be a user name, or an opaque ID identifying
this user. They are case-insensitive.

.. TODO-spec
    - Need to specify precise grammar for Matrix IDs

A "Home Server" is a server which provides C-S APIs and has the ability to
federate with other HSes.  It is typically responsible for multiple clients.
"Federation" is the term used to describe the sharing of data between two or
more home servers.

Data in Matrix is encapsulated in an "event". An event is an action within the
system. Typically each action (e.g. sending a message) correlates with exactly
one event. Each event has a ``type`` which is used to differentiate different
kinds of data. ``type`` values MUST be uniquely globally namespaced following
Java's `package naming conventions
<http://docs.oracle.com/javase/specs/jls/se5.0/html/packages.html#7.7>`, e.g.
``com.example.myapp.event``. The special top-level namespace ``m.`` is reserved
for events defined in the Matrix specification. Events are usually sent in the
context of a "Room".

Room structure
~~~~~~~~~~~~~~

A room is a conceptual place where users can send and receive events. Rooms can
be created, joined and left. Events are sent to a room, and all participants in
that room with sufficient access will receive the event. Rooms are uniquely
identified internally via a "Room ID", which look like::

  !opaque_id:domain

There is exactly one room ID for each room. Whilst the room ID does contain a
domain, it is simply for globally namespacing room IDs. The room does NOT
reside on the domain specified. Room IDs are not meant to be human readable.
They ARE case-sensitive.

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
                |______|           Shared State          |_______|
                       | Room ID: !qporfwt:matrix.org    |
                       | Servers: matrix.org, domain.com |
                       | Members:                        |
                       |  - @alice:matrix.org            |
                       |  - @bob:domain.com              |
                       |.................................|

Federation maintains shared state between multiple home servers, such that when
an event is sent to a room, the home server knows where to forward the event on
to, and how to process the event. State is scoped to a single room, and
federation ensures that all home servers have the information they need, even
if that means the home server has to request more information from another home
server before processing the event.

Room Aliases
~~~~~~~~~~~~

Each room can also have multiple "Room Aliases", which looks like::

  #room_alias:domain

  .. TODO
      - Need to specify precise grammar for Room Aliases

A room alias "points" to a room ID and is the human-readable label by which
rooms are publicised and discovered.  The room ID the alias is pointing to can
be obtained by visiting the domain specified. They are case-insensitive. Note
that the mapping from a room alias to a room ID is not fixed, and may change
over time to point to a different room ID. For this reason, Clients SHOULD
resolve the room alias to a room ID once and then use that ID on subsequent
requests.

When resolving a room alias the server will also respond with a list of servers
that are in the room that can be used to join via.

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
       
Identity
~~~~~~~~

Users in Matrix are identified via their user ID. However, existing ID
namespaces can also be used in order to identify Matrix users. A Matrix
"Identity" describes both the user ID and any other existing IDs from third
party namespaces *linked* to their account.

Matrix users can *link* third-party IDs (3PIDs) such as email addresses, social
network accounts and phone numbers to their user ID. Linking 3PIDs creates a
mapping from a 3PID to a user ID. This mapping can then be used by other Matrix
users in order to discover other users, according to a strict set of privacy
permissions.

In order to ensure that the mapping from 3PID to user ID is genuine, a globally
federated cluster of trusted "Identity Servers" (IS) are used to perform
authentication of the 3PID.  Identity servers are also used to preserve the
mapping indefinitely, by replicating the mappings across multiple ISes.

Usage of an IS is not required in order for a client application to be part of
the Matrix ecosystem. However, without one clients will not be able to look up
user IDs using 3PIDs.

Presence
~~~~~~~~
.. NOTE::
  This section is a work in progress.

Each user has the concept of presence information. This encodes the
"availability" of that user, suitable for display on other user's clients. This
is transmitted as an ``m.presence`` event and is one of the few events which
are sent *outside the context of a room*. The basic piece of presence
information is represented by the ``presence`` key, which is an enum of one of
the following:

  - ``online`` : The default state when the user is connected to an event
    stream.
  - ``unavailable`` : The user is not reachable at this time.
  - ``offline`` : The user is not connected to an event stream.
  - ``free_for_chat`` : The user is generally willing to receive messages
    moreso than default.
  - ``hidden`` : Behaves as offline, but allows the user to see the client
    state anyway and generally interact with client features. (Not yet
    implemented in synapse).

This basic ``presence`` field applies to the user as a whole, regardless of how
many client devices they have connected. The home server should synchronise
this status choice among multiple devices to ensure the user gets a consistent
experience.

In addition, the server maintains a timestamp of the last time it saw an active
action from the user; either sending a message to a room, or changing presence
state from a lower to a higher level of availability (thus: changing state from
``unavailable`` to ``online`` will count as an action for being active, whereas
in the other direction will not). This timestamp is presented via a key called
``last_active_ago``, which gives the relative number of miliseconds since the
message is generated/emitted, that the user was last seen active.

Home servers can also use the user's choice of presence state as a signal for
how to handle new private one-to-one chat message requests. For example, it
might decide:

  - ``free_for_chat`` : accept anything
  - ``online`` : accept from anyone in my addres book list
  - ``busy`` : accept from anyone in this "important people" group in my
    address book list

Presence List
+++++++++++++
Each user's home server stores a "presence list" for that user. This stores a
list of other user IDs the user has chosen to add to it. To be added to this
list, the user being added must receive permission from the list owner. Once
granted, both user's HS(es) store this information. Since such subscriptions
are likely to be bidirectional, HSes may wish to automatically accept requests
when a reverse subscription already exists.

As a convenience, presence lists should support the ability to collect users
into groups, which could allow things like inviting the entire group to a new
("ad-hoc") chat room, or easy interaction with the profile information ACL
implementation of the HS.

Presence and Permissions
++++++++++++++++++++++++
For a viewing user to be allowed to see the presence information of a target
user, either:

 - The target user has allowed the viewing user to add them to their presence
   list, or
 - The two users share at least one room in common

In the latter case, this allows for clients to display some minimal sense of
presence information in a user list for a room.

Profiles
~~~~~~~~
.. NOTE::
  This section is a work in progress.

.. TODO-spec
  - Metadata extensibility

Internally within Matrix users are referred to by their user ID, which is
typically a compact unique identifier. Profiles grant users the ability to see
human-readable names for other users that are in some way meaningful to them.
Additionally, profiles can publish additional information, such as the user's
age or location.

A Profile consists of a display name, an avatar picture, and a set of other
metadata fields that the user may wish to publish (email address, phone
numbers, website URLs, etc...). This specification puts no requirements on the
display name other than it being a valid unicode string. Avatar images are not
stored directly; instead the home server stores an ``http``-scheme URL where
clients may fetch it from.

API Standards
-------------

The mandatory baseline for communication in Matrix is exchanging JSON objects
over RESTful HTTP APIs. HTTPS is mandated as the baseline for server-server
(federation) communication.  HTTPS is recommended for client-server
communication, although HTTP may be supported as a fallback to support basic
HTTP clients. More efficient optional transports for client-server
communication will in future be supported as optional extensions - e.g. a
packed binary encoding over stream-cipher encrypted TCP socket for
low-bandwidth/low-roundtrip mobile usage.

.. TODO
  We need to specify capability negotiation for extensible transports

For the default HTTP transport, all API calls use a Content-Type of
``application/json``.  In addition, all strings MUST be encoded as UTF-8.

Clients are authenticated using opaque ``access_token`` strings (see
`Registration and Login`_ for details), passed as a query string parameter on
all requests.

.. TODO
  Need to specify any HMAC or access_token lifetime/ratcheting tricks

Any errors which occur on the Matrix API level MUST return a "standard error
response". This is a JSON object which looks like::

  {
    "errcode": "<error code>",
    "error": "<error message>"
  }

The ``error`` string will be a human-readable error message, usually a sentence
explaining what went wrong. The ``errcode`` string will be a unique string
which can be used to handle an error message e.g. ``M_FORBIDDEN``. These error
codes should have their namespace first in ALL CAPS, followed by a single _.
For example, if there was a custom namespace ``com.mydomain.here``, and a
``FORBIDDEN`` code, the error code should look like
``COM.MYDOMAIN.HERE_FORBIDDEN``. There may be additional keys depending on the
error, but the keys ``error`` and ``errcode`` MUST always be present. 

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

The C-S API typically uses ``HTTP POST`` to submit requests. This means these
requests are not idempotent. The C-S API also allows ``HTTP PUT`` to make
requests idempotent. In order to use a ``PUT``, paths should be suffixed with
``/{txnId}``. ``{txnId}`` is a unique client-generated transaction ID which
identifies the request, and is scoped to a given Client (identified by that
client's ``access_token``). Crucially, it **only** serves to identify new
requests from retransmits. After the request has finished, the ``{txnId}``
value should be changed (how is not specified; a monotonically increasing
integer is recommended). It is preferable to use ``HTTP PUT`` to make sure
requests to send messages do not get sent more than once should clients need to
retransmit requests.

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

Glossary
--------
.. NOTE::
  This section is a work in progress.

Backfilling:
  The process of synchronising historic state from one home server to another,
  to backfill the event storage so that scrollback can be presented to the
  client(s). Not to be confused with pagination.

Context:
  A single human-level entity of interest (currently, a chat room)

EDU (Ephemeral Data Unit):
  A message that relates directly to a given pair of home servers that are
  exchanging it. EDUs are short-lived messages that related only to one single
  pair of servers; they are not persisted for a long time and are not forwarded
  on to other servers. Because of this, they have no internal ID nor previous
  EDUs reference chain.

Event:
  A record of activity that records a single thing that happened on to a context
  (currently, a chat room). These are the "chat messages" that Synapse makes
  available.

PDU (Persistent Data Unit):
  A message that relates to a single context, irrespective of the server that
  is communicating it. PDUs either encode a single Event, or a single State
  change. A PDU is referred to by its PDU ID; the pair of its origin server
  and local reference from that server.

PDU ID:
  The pair of PDU Origin and PDU Reference, that together globally uniquely
  refers to a specific PDU.

PDU Origin:
  The name of the origin server that generated a given PDU. This may not be the
  server from which it has been received, due to the way they are copied around
  from server to server. The origin always records the original server that
  created it.

PDU Reference:
  A local ID used to refer to a specific PDU from a given origin server. These
  references are opaque at the protocol level, but may optionally have some
  structured meaning within a given origin server or implementation.

Presence:
  The concept of whether a user is currently online, how available they declare
  they are, and so on. See also: doc/model/presence

Profile:
  A set of metadata about a user, such as a display name, provided for the
  benefit of other users. See also: doc/model/profiles

Room ID:
  An opaque string (of as-yet undecided format) that identifies a particular
  room and used in PDUs referring to it.

Room Alias:
  A human-readable string of the form #name:some.domain that users can use as a
  pointer to identify a room; a Directory Server will map this to its Room ID

State:
  A set of metadata maintained about a Context, which is replicated among the
  servers in addition to the history of Events.

User ID:
  A string of the form @localpart:domain.name that identifies a user for
  wire-protocol purposes. The localpart is meaningless outside of a particular
  home server. This takes a human-readable form that end-users can use directly
  if they so wish, avoiding the 3PIDs.

Transaction:
  A message which relates to the communication between a given pair of servers.
  A transaction contains possibly-empty lists of PDUs and EDUs.

.. TODO
  This glossary contradicts the terms used above - especially on State Events v. "State"
  and Non-State Events v. "Events".  We need better consistent names.

Events
======

Receiving live updates on a client
----------------------------------

Clients can receive new events by long-polling the home server. This will hold
open the HTTP connection for a short period of time waiting for new events,
returning early if an event occurs. This is called the `Event Stream`_. All
events which are visible to the client will appear in the event stream. When
the request returns, an ``end`` token is included in the response. This token
can be used in the next request to continue where the client left off.

.. TODO-spec
  How do we filter the event stream?
  Do we ever return multiple events in a single request?  Don't we get lots of request
  setup RTT latency if we only do one event per request? Do we ever support streaming
  requests? Why not websockets?

When the client first logs in, they will need to initially synchronise with
their home server. This is achieved via the |initialSync|_ API. This API also
returns an ``end`` token which can be used with the event stream.

Room Events
-----------
.. NOTE::
  This section is a work in progress.

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
    A room has an opaque room ID which is not human-friendly to read. A room
    alias is human-friendly, but not all rooms have room aliases. The room name
    is a human-friendly string designed to be displayed to the end-user. The
    room name is not *unique*, as multiple rooms can have the same room name
    set. The room name can also be set when creating a room using |createRoom|_
    with the ``name`` key.

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
    A topic is a short message detailing what is currently being discussed in
    the room.  It can also be used as a way to display extra information about
    the room, which may not be suitable for the room name. The room topic can
    also be set when creating a room using |createRoom|_ with the ``topic``
    key.

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
    Adjusts the membership state for a user in a room. It is preferable to use
    the membership APIs (``/rooms/<room id>/invite`` etc) when performing
    membership actions rather than adjusting the state directly as there are a
    restricted set of valid transformations. For example, user A cannot force
    user B to join a room, and trying to force this state change directly will
    fail. See the `Rooms`_ section for how to use the membership APIs.

``m.room.create``
  Summary:
    The first event in the room.
  Type: 
    State event
  JSON format:
    ``{ "creator": "string"}``
  Example:
    ``{ "creator": "@user:example.com" }``
  Description:
    This is the first event in a room and cannot be changed. It acts as the 
    root of all other events.

``m.room.join_rules``
  Summary:
    Descripes how/if people are allowed to join.
  Type: 
    State event
  JSON format:
    ``{ "join_rule": "enum [ public|knock|invite|private ]" }``
  Example:
    ``{ "join_rule": "public" }``
  Description:
    TODO-doc : Use docs/models/rooms.rst
   
``m.room.power_levels``
  Summary:
    Defines the power levels of users in the room.
  Type: 
    State event
  JSON format:
    ``{ "<user_id>": <int>, ..., "default": <int>}``
  Example:
    ``{ "@user:example.com": 5, "@user2:example.com": 10, "default": 0 }`` 
  Description:
    If a user is in the list, then they have the associated power level. 
    Otherwise they have the default level. If not ``default`` key is supplied,
    it is assumed to be 0.

``m.room.add_state_level``
  Summary:
    Defines the minimum power level a user needs to add state.
  Type: 
    State event
  JSON format:
    ``{ "level": <int> }``
  Example:
    ``{ "level": 5 }``
  Description:
    To add a new piece of state to the room a user must have the given power 
    level. This does not apply to updating current state, which is goverened
    by the ``required_power_level`` event key.
    
``m.room.send_event_level``
  Summary:
    Defines the minimum power level a user needs to send an event.
  Type: 
    State event
  JSON format:
    ``{ "level": <int> }``
  Example:
    ``{ "level": 0 }``
  Description:
    To send a new event into the room a user must have at least this power 
    level. This allows ops to make the room read only by increasing this level,
    or muting individual users by lowering their power level below this
    threshold.

``m.room.ops_levels``
  Summary:
    Defines the minimum power levels that a user must have before they can 
    kick and/or ban other users.
  Type: 
    State event
  JSON format:
    ``{ "ban_level": <int>, "kick_level": <int>, "redact_level": <int> }``
  Example:
    ``{ "ban_level": 5, "kick_level": 5 }``
  Description:
    This defines who can ban and/or kick people in the room. Most of the time
    ``ban_level`` will be greater than or equal to ``kick_level`` since 
    banning is more severe than kicking.

``m.room.aliases``
  Summary:
    These state events are used to inform the room about what room aliases it
    has.
  Type:
    State event
  JSON format:
    ``{ "aliases": ["string", ...] }``
  Example:
    ``{ "aliases": ["#foo:example.com"] }``
  Description:
    This event is sent by a homeserver directly to inform of changes to the
    list of aliases it knows about for that room. As a special-case, the
    ``state_key`` of the event is the homeserver which owns the room alias.
    For example, an event might look like::

      {
        "type": "m.room.aliases",
        "event_id": "012345678ab",
        "room_id": "!xAbCdEfG:example.com",
        "state_key": "example.com",
        "content": {
          "aliases": ["#foo:example.com"]
        }
      }

    The event contains the full list of aliases now stored by the home server
    that emitted it; additions or deletions are not explicitly mentioned as
    being such. The entire set of known aliases for the room is then the union
    of the individual lists declared by all such keys, one from each home
    server holding at least one alias.

    Clients `should` check the validity of any room alias given in this list
    before presenting it to the user as trusted fact. The lists given by this
    event should be considered simply as advice on which aliases might exist,
    for which the client can perform the lookup to confirm whether it receives
    the correct room ID.

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
    This event is used when sending messages in a room. Messages are not
    limited to be text.  The ``msgtype`` key outlines the type of message, e.g.
    text, audio, image, video, etc.  Whilst not required, the ``body`` key
    SHOULD be used with every kind of ``msgtype`` as a fallback mechanism when
    a client cannot render the message. For more information on the types of
    messages which can be sent, see `m.room.message msgtypes`_.

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
    Feedback events are events sent to acknowledge a message in some way. There
    are two supported acknowledgements: ``delivered`` (sent when the event has
    been received) and ``read`` (sent when the event has been observed by the
    end-user). The ``target_event_id`` should reference the ``m.room.message``
    event being acknowledged. 

``m.room.redaction``
  Summary:
    Indicates a previous event has been redacted.
  Type:
    Non-state event
  JSON format:
    ``{ "reason": "string" }``
  Description:
    Events can be redacted by either room or server admins. Redacting an event
    means that all keys not required by the protocol are stripped off, allowing
    admins to remove offensive or illegal content that may have been attached
    to any event. This cannot be undone, allowing server owners to physically
    delete the offending data.  There is also a concept of a moderator hiding a
    non-state event, which can be undone, but cannot be applied to state
    events.
    The event that has been redacted is specified in the ``redacts`` event
    level key.

m.room.message msgtypes
~~~~~~~~~~~~~~~~~~~~~~~

.. TODO-spec
   How a client should handle unknown message types.

Each ``m.room.message`` MUST have a ``msgtype`` key which identifies the type
of message being sent. Each type has their own required and optional keys, as
outlined below:

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
    - ``info`` : "string" - info : JSON object (ImageInfo) - The image info for
      image referred to in ``url``.
    - ``thumbnail_url`` : "string" - The URL to the thumbnail.
    - ``thumbnail_info`` : JSON object (ImageInfo) - The image info for the
      image referred to in ``thumbnail_url``.
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
    - ``info`` : JSON object (AudioInfo) - The audio info for the audio
      referred to in ``url``.
    - ``body`` : "string" - A description of the audio e.g. "Bee Gees - Stayin'
      Alive", or some kind of content description for accessibility e.g.
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
    - ``info`` : JSON object (VideoInfo) - The video info for the video
      referred to in ``url``.
    - ``body`` : "string" - A description of the video e.g. "Gangnam style", or
      some kind of content description for accessibility e.g. "video
      attachment".

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
    - ``thumbnail_url`` : "string" - The URL to a thumnail of the location
      being represented.
    - ``thumbnail_info`` : JSON object (ImageInfo) - The image info for the
      image referred to in ``thumbnail_url``.
    - ``body`` : "string" - A description of the location e.g. "Big Ben,
      London, UK", or some kind of content description for accessibility e.g.
      "location attachment".

The following keys can be attached to any ``m.room.message``:

  Optional keys:
    - ``sender_ts`` : integer - A timestamp (ms resolution) representing the
      wall-clock time when the message was sent from the client.

Events on Change of Profile Information
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Because the profile displayname and avatar information are likely to be used in
many places of a client's display, changes to these fields cause an automatic
propagation event to occur, informing likely-interested parties of the new
values. This change is conveyed using two separate mechanisms:

 - a ``m.room.member`` event is sent to every room the user is a member of,
   to update the ``displayname`` and ``avatar_url``.
 - a presence status update is sent, again containing the new values of the
   ``displayname`` and ``avatar_url`` keys, in addition to the required
   ``presence`` key containing the current presence state of the user.

Both of these should be done automatically by the home server when a user
successfully changes their displayname or avatar URL fields.

Additionally, when home servers emit room membership events for their own
users, they should include the displayname and avatar URL fields in these
events so that clients already have these details to hand, and do not have to
perform extra roundtrips to query it.

Voice over IP
-------------
Matrix can also be used to set up VoIP calls. This is part of the core
specification, although is still in a very early stage. Voice (and video) over
Matrix is based on the WebRTC standards.

Call events are sent to a room, like any other event. This means that clients
must only send call events to rooms with exactly two participants as currently
the WebRTC standard is based around two-party communication.

Events
~~~~~~
``m.call.invite``
This event is sent by the caller when they wish to establish a call.

  Required keys:
    - ``call_id`` : "string" - A unique identifier for the call
    - ``offer`` : "offer object" - The session description
    - ``version`` : "integer" - The version of the VoIP specification this
      message adheres to. This specification is version 0.
    - ``lifetime`` : "integer" - The time in milliseconds that the invite is
      valid for. Once the invite age exceeds this value, clients should discard
      it. They should also no longer show the call as awaiting an answer in the
      UI.
      
  Optional keys:
    None.
  Example:
    ``{ "version" : 0, "call_id": "12345", "offer": { "type" : "offer", "sdp" : "v=0\r\no=- 6584580628695956864 2 IN IP4 127.0.0.1[...]" } }``

``Offer Object``
  Required keys:
    - ``type`` : "string" - The type of session description, in this case
      'offer'
    - ``sdp`` : "string" - The SDP text of the session description

``m.call.candidates``
This event is sent by callers after sending an invite and by the callee after
answering.  Its purpose is to give the other party additional ICE candidates to
try using to communicate.

  Required keys:
    - ``call_id`` : "string" - The ID of the call this event relates to
    - ``version`` : "integer" - The version of the VoIP specification this
      messages adheres to. his specification is version 0.
    - ``candidates`` : "array of candidate objects" - Array of object
      describing the candidates.

``Candidate Object``

  Required Keys:
    - ``sdpMid`` : "string" - The SDP media type this candidate is intended
      for.
    - ``sdpMLineIndex`` : "integer" - The index of the SDP 'm' line this
      candidate is intended for
    - ``candidate`` : "string" - The SDP 'a' line of the candidate

``m.call.answer``

  Required keys:
    - ``call_id`` : "string" - The ID of the call this event relates to
    - ``version`` : "integer" - The version of the VoIP specification this
      messages
    - ``answer`` : "answer object" - Object giving the SDK answer

``Answer Object``

  Required keys:
    - ``type`` : "string" - The type of session description. 'answer' in this
      case.
    - ``sdp`` : "string" - The SDP text of the session description

``m.call.hangup``
Sent by either party to signal their termination of the call. This can be sent
either once the call has has been established or before to abort the call.

  Required keys:
    - ``call_id`` : "string" - The ID of the call this event relates to
    - ``version`` : "integer" - The version of the VoIP specification this
      messages

Message Exchange
~~~~~~~~~~~~~~~~
A call is set up with messages exchanged as follows:

::

   Caller                   Callee
 m.call.invite ----------->
 m.call.candidate -------->
 [more candidates events]
                         User answers call
                  <------ m.call.answer
               [...]
                  <------ m.call.hangup
                  
Or a rejected call:

::

   Caller                   Callee
 m.call.invite ----------->
 m.call.candidate -------->
 [more candidates events]
                        User rejects call
                 <------- m.call.hangup

Calls are negotiated according to the WebRTC specification.


Glare
~~~~~
This specification aims to address the problem of two users calling each other
at roughly the same time and their invites crossing on the wire. It is a far
better experience for the users if their calls are connected if it is clear
that their intention is to set up a call with one another.

In Matrix, calls are to rooms rather than users (even if those rooms may only
contain one other user) so we consider calls which are to the same room.

The rules for dealing with such a situation are as follows:

 - If an invite to a room is received whilst the client is preparing to send an
   invite to the same room, the client should cancel its outgoing call and
   instead automatically accept the incoming call on behalf of the user.
 - If an invite to a room is received after the client has sent an invite to
   the same room and is waiting for a response, the client should perform a
   lexicographical comparison of the call IDs of the two calls and use the
   lesser of the two calls, aborting the greater. If the incoming call is the
   lesser, the client should accept this call on behalf of the user.

The call setup should appear seamless to the user as if they had simply placed
a call and the other party had accepted. Thusly, any media stream that had been
setup for use on a call should be transferred and used for the call that
replaces it.

Client-Server API
=================

Registration and Login
----------------------

Clients must register with a home server in order to use Matrix. After
registering, the client will be given an access token which must be used in ALL
requests to that home server as a query parameter 'access_token'.

If the client has already registered, they need to be able to login to their
account. The home server may provide many different ways of logging in, such as
user/password auth, login via a social network (OAuth2), login by confirming a
token sent to their email address, etc. This specification does not define how
home servers should authorise their users who want to login to their existing
accounts, but instead defines the standard interface which implementations
should follow so that ANY client can login to ANY home server. Clients login
using the |login|_ API. Clients register using the |register|_ API.
Registration follows the same general procedure as login, but the path requests
are sent to and the details contained in them are different.

In both registration and login cases, the process takes the form of one or more
stages, where at each stage the client submits a set of data for a given stage
type and awaits a response from the server, which will either be a final
success or a request to perform an additional stage. This exchange continues
until the final success.

In order to determine up-front what the server's requirements are, the client
can request from the server a complete description of all of its acceptable
flows of the registration or login process. It can then inspect the list of
returned flows looking for one for which it believes it can complete all of the
required stages, and perform it. As each home server may have different ways of
logging in, the client needs to know how they should login. All distinct login
stages MUST have a corresponding ``type``. A ``type`` is a namespaced string
which details the mechanism for logging in.

A client may be able to login via multiple valid login flows, and should choose
a single flow when logging in. A flow is a series of login stages. The home
server MUST respond with all the valid login flows when requested by a simple
``GET`` request directly to the ``/login`` or ``/register`` paths::

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

The client can now select which flow it wishes to use, and begin making
``POST`` requests to the ``/login`` or ``/register`` paths with JSON body
content containing the name of the stage as the ``type`` key, along with
whatever additional parameters are required for that login or registration type
(see below). After the flow is completed, the client's fully-qualified user
ID and a new access token MUST be returned::

  {
    "user_id": "@user:matrix.org",
    "access_token": "abcdef0123456789"
  }

The ``user_id`` key is particularly useful if the home server wishes to support
localpart entry of usernames (e.g. "user" rather than "@user:matrix.org"), as
the client may not be able to determine its ``user_id`` in this case.

If the flow has multiple stages to it, the home server may wish to create a
session to store context between requests. If a home server responds with a
``session`` key to a request, clients MUST submit it in subsequent requests
until the flow is completed::

  {
    "session": "<session id>"
  }

This specification defines the following login types:
 - ``m.login.password``
 - ``m.login.oauth2``
 - ``m.login.email.code``
 - ``m.login.email.url``
 - ``m.login.email.identity``

Password-based
~~~~~~~~~~~~~~
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

The home server MUST respond with either new credentials, the next stage of the
login process, or a standard error response.

OAuth2-based
~~~~~~~~~~~~
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

The home server acts as a 'confidential' client for the purposes of OAuth2.  If
the uri is a ``sevice selection URI``, it MUST point to a webpage which prompts
the user to choose which service to authorize with. On selection of a service,
this MUST link through to an ``Authorization Request URI``. If there is only 1
service which the home server accepts when logging in, this indirection can be
skipped and the "uri" key can be the ``Authorization Request URI``. 

The client then visits the ``Authorization Request URI``, which then shows the
OAuth2 Allow/Deny prompt. Hitting 'Allow' returns the ``redirect URI`` with the
auth code.  Home servers can choose any path for the ``redirect URI``. The
client should visit the ``redirect URI``, which will then finish the OAuth2
login process, granting the home server an access token for the chosen service.
When the home server gets this access token, it verifies that the cilent has
authorised with the 3rd party, and can now complete the login. The OAuth2
``redirect URI`` (with auth code) MUST respond with either new credentials, the
next stage of the login process, or a standard error response.
    
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
~~~~~~~~~~~~~~~~~~
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

After validating the email address, the home server MUST send an email
containing an authentication code and return::

  {
    "type": "m.login.email.code",
    "session": "<session id>"
  }

The second request in this login stage involves sending this authentication
code::

  {
    "type": "m.login.email.code",
    "session": "<session id>",
    "code": "<code in email sent>"
  }

The home server MUST respond to this with either new credentials, the next
stage of the login process, or a standard error response.

Email-based (url)
~~~~~~~~~~~~~~~~~
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

After validating the email address, the home server MUST send an email
containing an authentication URL and return::

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

The home server MUST respond to this with either new credentials, the next
stage of the login process, or a standard error response. 

A common client implementation will be to periodically poll until the link is
clicked.  If the link has not been visited yet, a standard error response with
an errcode of ``M_LOGIN_EMAIL_URL_NOT_YET`` should be returned.


Email-based (identity server)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
:Type:
  ``m.login.email.identity``
:Description:
  Login is supported by authorising an email address with an identity server.

Prior to submitting this, the client should authenticate with an identity
server.  After authenticating, the session information should be submitted to
the home server.

To respond to this type, reply with::

  {
    "type": "m.login.email.identity",
    "threepidCreds": [
      {
        "sid": "<identity server session id>",
        "clientSecret": "<identity server client secret>",
        "idServer": "<url of identity server authed with, e.g. 'matrix.org:8090'>"
      }
    ]
  }



N-Factor Authentication
~~~~~~~~~~~~~~~~~~~~~~~
Multiple login stages can be combined to create N-factor authentication during
login.

This can be achieved by responding with the ``next`` login type on completion
of a previous login stage::

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
~~~~~~~~
Clients cannot be expected to be able to know how to process every single login
type. If a client determines it does not know how to handle a given login type,
it should request a login fallback page::

  GET matrix/client/api/v1/login/fallback

This MUST return an HTML page which can perform the entire login process.


Rooms
-----

Creation
~~~~~~~~
To create a room, a client has to use the |createRoom|_ API. There are various
options which can be set when creating a room:

``visibility``
  Type: 
    String
  Optional: 
    Yes
  Value:
    Either ``public`` or ``private``.
  Description:
    A ``public`` visibility indicates that the room will be shown in the public
    room list. A ``private`` visibility will hide the room from the public room
    list. Rooms default to ``private`` visibility if this key is not included.

``room_alias_name``
  Type: 
    String
  Optional: 
    Yes
  Value:
    The room alias localpart.
  Description:
    If this is included, a room alias will be created and mapped to the newly
    created room.  The alias will belong on the same home server which created
    the room, e.g.  ``!qadnasoi:domain.com >>> #room_alias_name:domain.com``

``name``
  Type: 
    String
  Optional: 
    Yes
  Value:
    The ``name`` value for the ``m.room.name`` state event.
  Description:
    If this is included, an ``m.room.name`` event will be sent into the room to
    indicate the name of the room. See `Room Events`_ for more information on
    ``m.room.name``.

``topic``
  Type: 
    String
  Optional: 
    Yes
  Value:
    The ``topic`` value for the ``m.room.topic`` state event.
  Description:
    If this is included, an ``m.room.topic`` event will be sent into the room
    to indicate the topic for the room. See `Room Events`_ for more information
    on ``m.room.topic``.

``invite``
  Type:
    List
  Optional:
    Yes
  Value:
    A list of user ids to invite.
  Description:
    This will tell the server to invite everyone in the list to the newly
    created room.

Example::

  {
    "visibility": "public", 
    "room_alias_name": "thepub",
    "name": "The Grand Duke Pub",
    "topic": "All about happy hour"
  }

The home server will create a ``m.room.create`` event when the room is created,
which serves as the root of the PDU graph for this room. This event also has a
``creator`` key which contains the user ID of the room creator. It will also
generate several other events in order to manage permissions in this room. This
includes:

 - ``m.room.power_levels`` : Sets the power levels of users.
 - ``m.room.join_rules`` : Whether the room is "invite-only" or not.
 - ``m.room.add_state_level``: The power level required in order to add new
   state to the room (as opposed to updating exisiting state)
 - ``m.room.send_event_level`` : The power level required in order to send a
   message in this room.
 - ``m.room.ops_level`` : The power level required in order to kick or ban a
   user from the room or redact an event in the room.

See `Room Events`_ for more information on these events.

Room aliases
~~~~~~~~~~~~
.. NOTE::
  This section is a work in progress.

Room aliases can be created by sending a ``PUT /directory/room/<room alias>``::

  {
    "room_id": <room id>
  }

They can be deleted by sending a ``DELETE /directory/room/<room alias>`` with
no content. Only some privileged users may be able to delete room aliases, e.g.
server admins, the creator of the room alias, etc. This specification does not
outline the privilege level required for deleting room aliases.

As room aliases are scoped to a particular home server domain name, it is
likely that a home server will reject attempts to maintain aliases on other
domain names. This specification does not provide a way for home servers to
send update requests to other servers.

Rooms store a *partial* list of room aliases via the ``m.room.aliases`` state
event. This alias list is partial because it cannot guarantee that the alias
list is in any way accurate or up-to-date, as room aliases can point to 
different room IDs over time. Crucially, the aliases in this event are
**purely informational** and SHOULD NOT be treated as accurate. They SHOULD
be checked before they are used or shared with another user. If a room
appears to have a room alias of ``#alias:example.com``, this SHOULD be checked
to make sure that the room's ID matches the ``room_id`` returned from the
request.

Room aliases can be checked in the same way they are resolved; by sending a 
``GET /directory/room/<room alias>``::

  {
    "room_id": <room id>,
    "servers": [ <domain>, <domain2>, <domain3> ]
  }

Home servers can respond to resolve requests for aliases on other domains than
their own by using the federation API to ask other domain name home servers.


Permissions
~~~~~~~~~~~
.. NOTE::
  This section is a work in progress.

Permissions for rooms are done via the concept of power levels - to do any
action in a room a user must have a suitable power level. Power levels are
stored as state events in a given room. 

Power levels for users are defined in ``m.room.power_levels``, where both a
default and specific users' power levels can be set::

  {
    "<user id 1>": <power level int>,
    "<user id 2>": <power level int>,
    "default": 0
  }

By default all users have a power level of 0, other than the room creator whose
power level defaults to 100. Users can grant other users increased power levels
up to their own power level. For example, user A with a power level of 50 could
increase the power level of user B to a maximum of level 50. Power levels for 
users are tracked per-room even if the user is not present in the room.

State events may contain a ``required_power_level`` key, which indicates the
minimum power a user must have before they can update that state key. The only
exception to this is when a user leaves a room, which revokes the user's right
to update state events in that room.

To perform certain actions there are additional power level requirements
defined in the following state events:

- ``m.room.send_event_level`` defines the minimum ``level`` for sending 
  non-state events. Defaults to 50.
- ``m.room.add_state_level`` defines the minimum ``level`` for adding new 
  state, rather than updating existing state. Defaults to 50.
- ``m.room.ops_level`` defines the minimum ``ban_level`` and ``kick_level`` to 
  ban and kick other users respectively. This defaults to a kick and ban levels
  of 50 each.


Joining rooms
~~~~~~~~~~~~~
.. TODO-doc What does the home server have to do to join a user to a room?
   -  See SPEC-30.

Users need to join a room in order to send and receive events in that room. A
user can join a room by making a request to |/join/<room_alias_or_id>|_ with::

  {}

Alternatively, a user can make a request to |/rooms/<room_id>/join|_ with the
same request content.  This is only provided for symmetry with the other
membership APIs: ``/rooms/<room id>/invite`` and ``/rooms/<room id>/leave``. If
a room alias was specified, it will be automatically resolved to a room ID,
which will then be joined. The room ID that was joined will be returned in
response::

  {
    "room_id": "!roomid:domain"
  }

The membership state for the joining user can also be modified directly to be
``join`` by sending the following request to
``/rooms/<room id>/state/m.room.member/<url encoded user id>``::

  {
    "membership": "join"
  }

See the `Room events`_ section for more information on ``m.room.member``.

After the user has joined a room, they will receive subsequent events in that
room. This room will now appear as an entry in the |initialSync|_ API.

Some rooms enforce that a user is *invited* to a room before they can join that
room. Other rooms will allow anyone to join the room even if they have not
received an invite.

Inviting users
~~~~~~~~~~~~~~
.. TODO-doc Invite-join dance 
  - Outline invite join dance. What is it? Why is it required? How does it work?
  - What does the home server have to do?

The purpose of inviting users to a room is to notify them that the room exists
so they can choose to become a member of that room. Some rooms require that all
users who join a room are previously invited to it (an "invite-only" room).
Whether a given room is an "invite-only" room is determined by the room config
key ``m.room.join_rules``. It can have one of the following values:

``public``
  This room is free for anyone to join without an invite.

``invite``
  This room can only be joined if you were invited.

Only users who have a membership state of ``join`` in a room can invite new
users to said room. The person being invited must not be in the ``join`` state
in the room. The fully-qualified user ID must be specified when inviting a
user, as the user may reside on a different home server. To invite a user, send
the following request to |/rooms/<room_id>/invite|_, which will manage the
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
~~~~~~~~~~~~~
.. TODO-spec - HS deleting rooms they are no longer a part of. Not implemented.
  - This is actually Very Tricky. If all clients a HS is serving leave a room,
  the HS will no longer get any new events for that room, because the servers
  who get the events are determined on the *membership list*. There should
  probably be a way for a HS to lurk on a room even if there are 0 of their
  members in the room.
  - Grace period before deletion?
  - Under what conditions should a room NOT be purged?


A user can leave a room to stop receiving events for that room. A user must
have joined the room before they are eligible to leave the room. If the room is
an "invite-only" room, they will need to be re-invited before they can re-join
the room.  To leave a room, a request should be made to
|/rooms/<room_id>/leave|_ with::

  {}

Alternatively, the membership state for this user in this room can be modified 
directly by sending the following request to 
``/rooms/<room id>/state/m.room.member/<url encoded user id>``::

  {
    "membership": "leave"
  }

See the `Room events`_ section for more information on ``m.room.member``.

Once a user has left a room, that room will no longer appear on the
|initialSync|_ API.

If all members in a room leave, that room becomes eligible for deletion. 

Banning users in a room
~~~~~~~~~~~~~~~~~~~~~~~
A user may decide to ban another user in a room. 'Banning' forces the target
user to leave the room and prevents them from re-joining the room. A banned
user will not be treated as a joined user, and so will not be able to send or
receive events in the room. In order to ban someone, the user performing the
ban MUST have the required power level. To ban a user, a request should be made
to |/rooms/<room_id>/ban|_ with::

  {
    "user_id": "<user id to ban"
    "reason": "string: <reason for the ban>"
  }
  
Banning a user adjusts the banned member's membership state to ``ban`` and
adjusts the power level of this event to a level higher than the banned person.
Like with other membership changes, a user can directly adjust the target
member's state, by making a request to
``/rooms/<room id>/state/m.room.member/<user id>``::

  {
    "membership": "ban"
  }

Events in a room
~~~~~~~~~~~~~~~~
Room events can be split into two categories:

:State Events:
  These are events which replace events that came before it, depending on a set
  of unique keys.  These keys are the event ``type`` and a ``state_key``.
  Events with the same set of keys will be overwritten. Typically, state events
  are used to store state, hence their name.

:Non-state events:
  These are events which cannot be overwritten after sending. The list of
  events continues to grow as more events are sent. As this list grows, it
  becomes necessary to provide a mechanism for navigating this list. Pagination
  APIs are used to view the list of historical non-state events. Typically,
  non-state events are used to send messages.

This specification outlines several events, all with the event type prefix
``m.``. However, applications may wish to add their own type of event, and this
can be achieved using the REST API detailed in the following sections. If new
events are added, the event ``type`` key SHOULD follow the Java package naming
convention, e.g. ``com.example.myapp.event``.  This ensures event types are
suitably namespaced for each application and reduces the risk of clashes.

State events
~~~~~~~~~~~~
State events can be sent by ``PUT`` ing to
|/rooms/<room_id>/state/<event_type>/<state_key>|_.  These events will be
overwritten if ``<room id>``, ``<event type>`` and ``<state key>`` all match.
If the state event has no ``state_key``, it can be omitted from the path. These
requests **cannot use transaction IDs** like other ``PUT`` paths because they
cannot be differentiated from the ``state_key``. Furthermore, ``POST`` is
unsupported on state paths. Valid requests look like::

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

The ``state_key`` is often used to store state about individual users, by using
the user ID as the ``state_key`` value. For example::

  PUT /rooms/!roomid:domain/state/m.favorite.animal.event/%40my_user%3Adomain.com
  { "animal" : "cat", "reason": "fluffy" }

In some cases, there may be no need for a ``state_key``, so it can be omitted::

  PUT /rooms/!roomid:domain/state/m.room.bgd.color
  { "color": "red", "hex": "#ff0000" }

See `Room Events`_ for the ``m.`` event specification.

Non-state events
~~~~~~~~~~~~~~~~
Non-state events can be sent by sending a request to
|/rooms/<room_id>/send/<event_type>|_.  These requests *can* use transaction
IDs and ``PUT``/``POST`` methods. Non-state events allow access to historical
events and pagination, making it best suited for sending messages.  For
example::

  POST /rooms/!roomid:domain/send/m.custom.example.message
  { "text": "Hello world!" }

  PUT /rooms/!roomid:domain/send/m.custom.example.message/11
  { "text": "Goodbye world!" }

See `Room Events`_ for the ``m.`` event specification.

Syncing rooms
~~~~~~~~~~~~~
.. NOTE::
  This section is a work in progress.

When a client logs in, they may have a list of rooms which they have already
joined. These rooms may also have a list of events associated with them. The
purpose of 'syncing' is to present the current room and event information in a
convenient, compact manner. The events returned are not limited to room events;
presence events will also be returned. A single syncing API is provided:

 - |initialSync|_ : A global sync which will present room and event information
   for all rooms the user has joined.

.. TODO-spec room-scoped initial sync
 - |/rooms/<room_id>/initialSync|_ : A sync scoped to a single room. Presents
   room and event information for this room only.
 - Room-scoped initial sync is Very Tricky because typically people would
   want to sync the room then listen for any new content from that point
   onwards. The event stream cannot do this for a single room currently.
   As a result, commenting room-scoped initial sync at this time.

The |initialSync|_ API contains the following keys:

``presence``
  Description:
    Contains a list of presence information for users the client is interested
    in.
  Format:
    A JSON array of ``m.presence`` events.

``end``
  Description:
    Contains an event stream token which can be used with the `Event Stream`_.
  Format:
    A string containing the event stream token.

``rooms``
  Description:
    Contains a list of room information for all rooms the client has joined,
    and limited room information on rooms the client has been invited to.
  Format:
    A JSON array containing Room Information JSON objects.

Room Information:
  Description:
    Contains all state events for the room, along with a limited amount of
    the most recent non-state events, configured via the ``limit`` query
    parameter. Also contains additional keys with room metadata, such as the
    ``room_id`` and the client's ``membership`` to the room.
  Format:
    A JSON object with the following keys:
      ``room_id``
        A string containing the ID of the room being described.
      ``membership``
        A string representing the client's membership status in this room.
      ``messages``
        An event stream JSON object containing a ``chunk`` of recent non-state
        events, along with an ``end`` token. *NB: The name of this key will be
        changed in a later version.*
      ``state``
        A JSON array containing all the current state events for this room.

Getting events for a room
~~~~~~~~~~~~~~~~~~~~~~~~~
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
    TODO-doc


|/rooms/<room_id>/members|_
  Description:
    Get all ``m.room.member`` state events.
  Response format:
    ``{ "start": "<token>", "end": "<token>", "chunk": [ { m.room.member event }, ... ] }``
  Example:
    TODO-doc

|/rooms/<room_id>/messages|_
  Description:
    Get all ``m.room.message`` and ``m.room.member`` events. This API supports
    pagination using ``from`` and ``to`` query parameters, coupled with the
    ``start`` and ``end`` tokens from an |initialSync|_ API.
  Response format:
    ``{ "start": "<token>", "end": "<token>" }``
  Example:
    TODO-doc
    
|/rooms/<room_id>/initialSync|_
  Description:
    Get all relevant events for a room. This includes state events, paginated
    non-state events and presence events.
  Response format:
    `` { TODO-doc } ``
  Example:
    TODO-doc

Redactions
~~~~~~~~~~
Since events are extensible it is possible for malicious users and/or servers
to add keys that are, for example offensive or illegal. Since some events
cannot be simply deleted, e.g. membership events, we instead 'redact' events.
This involves removing all keys from an event that are not required by the
protocol. This stripped down event is thereafter returned anytime a client or
remote server requests it.

Events that have been redacted include a ``redacted_because`` key whose value
is the event that caused it to be redacted, which may include a reason.

Redacting an event cannot be undone, allowing server owners to delete the
offending content from the databases.

Currently, only room admins can redact events by sending a ``m.room.redaction``
event, but server admins also need to be able to redact events by a similar
mechanism.

Upon receipt of a redaction event, the server should strip off any keys not in
the following list:

 - ``event_id``
 - ``type``
 - ``room_id``
 - ``user_id``
 - ``state_key``
 - ``prev_state``
 - ``content``

The content object should also be stripped of all keys, unless it is one of
one of the following event types:

 - ``m.room.member`` allows key ``membership``
 - ``m.room.create`` allows key ``creator``
 - ``m.room.join_rules`` allows key ``join_rule``
 - ``m.room.power_levels`` allows keys that are user ids or ``default``
 - ``m.room.add_state_level`` allows key ``level``
 - ``m.room.send_event_level`` allows key ``level``
 - ``m.room.ops_levels`` allows keys ``kick_level``, ``ban_level``
   and ``redact_level``
 - ``m.room.aliases`` allows key ``aliases``

The redaction event should be added under the key ``redacted_because``.


When a client receives a redaction event it should change the redacted event
in the same way a server does.

Presence
~~~~~~~~
The client API for presence is on the following set of REST calls.

Fetching basic status::

  GET $PREFIX/presence/:user_id/status

  Returned content: JSON object containing the following keys:
    presence: "offline"|"unavailable"|"online"|"free_for_chat"
    status_msg: (optional) string of freeform text
    last_active_ago: miliseconds since the last activity by the user

Setting basic status::

  PUT $PREFIX/presence/:user_id/status

  Content: JSON object containing the following keys:
    presence and status_msg: as above

When setting the status, the activity time is updated to reflect that activity;
the client does not need to specify the ``last_active_ago`` field.

Fetching the presence list::

  GET $PREFIX/presence/list

  Returned content: JSON array containing objects; each object containing the
    following keys:
    user_id: observed user ID
    presence: "offline"|"unavailable"|"online"|"free_for_chat"
    status_msg: (optional) string of freeform text
    last_active_ago: miliseconds since the last activity by the user

Maintaining the presence list::

  POST $PREFIX/presence/list

  Content: JSON object containing either or both of the following keys:
    invite: JSON array of strings giving user IDs to send invites to
    drop: JSON array of strings giving user IDs to remove from the list

.. TODO-spec
  - Define how users receive presence invites, and how they accept/decline them

Profiles
~~~~~~~~
The client API for profile management consists of the following REST calls.

Fetching a user account displayname::

  GET $PREFIX/profile/:user_id/displayname

  Returned content: JSON object containing the following keys:
    displayname: string of freeform text

This call may be used to fetch the user's own displayname or to query the name
of other users; either locally or on remote systems hosted on other home
servers.

Setting a new displayname::

  PUT $PREFIX/profile/:user_id/displayname

  Content: JSON object containing the following keys:
    displayname: string of freeform text

Fetching a user account avatar URL::

  GET $PREFIX/profile/:user_id/avatar_url

  Returned content: JSON object containing the following keys:
    avatar_url: string containing an http-scheme URL

As with displayname, this call may be used to fetch either the user's own, or
other users' avatar URL.

Setting a new avatar URL::

  PUT $PREFIX/profile/:user_id/avatar_url

  Content: JSON object containing the following keys:
    avatar_url: string containing an http-scheme URL

Fetching combined account profile information::

  GET $PREFIX/profile/:user_id

  Returned content: JSON object containing the following keys:
    displayname: string of freeform text
    avatar_url: string containing an http-scheme URL

At the current time, this API simply returns the displayname and avatar URL
information, though it is intended to return more fields about the user's
profile once they are defined. Client implementations should take care not to
expect that these are the only two keys returned as future versions of this
specification may yield more keys here.

Security
--------

Rate limiting
~~~~~~~~~~~~~
Home servers SHOULD implement rate limiting to reduce the risk of being
overloaded. If a request is refused due to rate limiting, it should return a
standard error response of the form::

  {
    "errcode": "M_LIMIT_EXCEEDED",
    "error": "string",
    "retry_after_ms": integer (optional)
  }

The ``retry_after_ms`` key SHOULD be included to tell the client how long they
have to wait in milliseconds before they can try again.

.. TODO-spec
  - Surely we should recommend an algorithm for the rate limiting, rather than letting every
    homeserver come up with their own idea, causing totally unpredictable performance over
    federated rooms?

End-to-End Encryption
~~~~~~~~~~~~~~~~~~~~~

.. TODO-doc
  - Why is this needed.
  - Overview of process
  - Implementation

Content repository
------------------
.. NOTE::
  This section is a work in progress.

.. TODO-spec
  - path to upload
  - format for thumbnail paths, mention what it is protecting against.
  - content size limit and associated M_ERROR.


Address book repository
-----------------------
.. NOTE::
  This section is a work in progress.

.. TODO-spec
  - format: POST(?) wodges of json, some possible processing, then return wodges of json on GET.
  - processing may remove dupes, merge contacts, pepper with extra info (e.g. matrix-ability of
    contacts), etc.
  - Standard json format for contacts? Piggy back off vcards?

Federation API
===============

Federation is the term used to describe how to communicate between Matrix home
servers. Federation is a mechanism by which two home servers can exchange
Matrix event messages, both as a real-time push of current events, and as a
historic fetching mechanism to synchronise past history for clients to view. It
uses HTTPS connections between each pair of servers involved as the underlying
transport. Messages are exchanged between servers in real-time by active
pushing from each server's HTTP client into the server of the other. Queries to
fetch historic data for the purpose of back-filling scrollback buffers and the
like can also be performed. Currently routing of messages between homeservers
is full mesh (like email) - however, fan-out refinements to this design are
currently under consideration.

There are three main kinds of communication that occur between home servers:

:Queries:
   These are single request/response interactions between a given pair of
   servers, initiated by one side sending an HTTPS GET request to obtain some
   information, and responded by the other. They are not persisted and contain
   no long-term significant history. They simply request a snapshot state at
   the instant the query is made.

:Ephemeral Data Units (EDUs):
   These are notifications of events that are pushed from one home server to
   another. They are not persisted and contain no long-term significant
   history, nor does the receiving home server have to reply to them.

:Persisted Data Units (PDUs):
   These are notifications of events that are broadcast from one home server to
   any others that are interested in the same "context" (namely, a Room ID).
   They are persisted to long-term storage and form the record of history for
   that context.

EDUs and PDUs are further wrapped in an envelope called a Transaction, which is
transferred from the origin to the destination home server using an HTTP PUT
request.


Transactions
------------
.. WARNING::
  This section may be misleading or inaccurate.

The transfer of EDUs and PDUs between home servers is performed by an exchange
of Transaction messages, which are encoded as JSON objects, passed over an HTTP
PUT request. A Transaction is meaningful only to the pair of home servers that
exchanged it; they are not globally-meaningful.

Each transaction has:
 - An opaque transaction ID.
 - A timestamp (UNIX epoch time in milliseconds) generated by its origin
   server.
 - An origin and destination server name.
 - A list of "previous IDs".
 - A list of PDUs and EDUs - the actual message payload that the Transaction
   carries.
 
``origin``
  Type: 
    String
  Description:
    DNS name of homeserver making this transaction.
    
``ts``
  Type: 
    Integer
  Description:
    Timestamp in milliseconds on originating homeserver when this transaction 
    started.
    
``previous_ids``
  Type:
    List of strings
  Description:
    List of transactions that were sent immediately prior to this transaction.
    
``pdus``
  Type:
    List of Objects.
  Description:
    List of updates contained in this transaction.

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

The ``prev_ids`` field contains a list of previous transaction IDs that the
``origin`` server has sent to this ``destination``. Its purpose is to act as a
sequence checking mechanism - the destination server can check whether it has
successfully received that Transaction, or ask for a retransmission if not.

The ``pdus`` field of a transaction is a list, containing zero or more PDUs.[*]
Each PDU is itself a JSON object containing a number of keys, the exact details
of which will vary depending on the type of PDU. Similarly, the ``edus`` field
is another list containing the EDUs. This key may be entirely absent if there
are no EDUs to transfer.

(* Normally the PDU list will be non-empty, but the server should cope with
receiving an "empty" transaction.)

PDUs and EDUs
-------------
.. WARNING::
  This section may be misleading or inaccurate.

All PDUs have:
 - An ID
 - A context
 - A declaration of their type
 - A list of other PDU IDs that have been seen recently on that context
   (regardless of which origin sent them)

``context``
  Type:
    String
  Description:
    Event context identifier
    
``origin``
  Type:
    String
  Description:
    DNS name of homeserver that created this PDU.
    
``pdu_id``
  Type:
    String
  Description:
    Unique identifier for PDU within the context for the originating homeserver

``ts``
  Type:
    Integer
  Description:
    Timestamp in milliseconds on originating homeserver when this PDU was
    created.

``pdu_type``
  Type:
    String
  Description:
    PDU event type.

``prev_pdus``
  Type:
    List of pairs of strings
  Description:
    The originating homeserver and PDU ids of the most recent PDUs the
    homeserver was aware of for this context when it made this PDU.

``depth``
  Type:
    Integer
  Description:
    The maximum depth of the previous PDUs plus one.


.. TODO-spec paul
  - Update this structure so that 'pdu_id' is a two-element [origin,ref] pair
    like the prev_pdus are

For state updates:

``is_state``
  Type:
    Boolean
  Description:
    True if this PDU is updating state.
    
``state_key``
  Type:
    String
  Description:
    Optional key identifying the updated state within the context.
    
``power_level``
  Type:
    Integer
  Description:
    The asserted power level of the user performing the update.
    
``required_power_level``
  Type:
    Integer
  Description:
    The required power level needed to replace this update.

``prev_state_id``
  Type:
    String
  Description:
    PDU event type.
    
``prev_state_origin``
  Type:
    String
  Description:
    The PDU id of the update this replaces.
    
``user_id``
  Type:
    String
  Description:
    The user updating the state.

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
previous IDs that this ``origin`` has sent. This list may refer to other PDUs
sent by the same origin as the current one, or other origins.

Because of the distributed nature of participants in a Matrix conversation, it
is impossible to establish a globally-consistent total ordering on the events.
However, by annotating each outbound PDU at its origin with IDs of other PDUs
it has received, a partial ordering can be constructed allowing causality
relationships to be preserved. A client can then display these messages to the
end-user in some order consistent with their content and ensure that no message
that is semantically in reply of an earlier one is ever displayed before it.

PDUs fall into two main categories: those that deliver Events, and those that
synchronise State. For PDUs that relate to State synchronisation, additional
keys exist to support this:

::

 {...,
  "is_state":true,
  "state_key":TODO-doc
  "power_level":TODO-doc
  "prev_state_id":TODO-doc
  "prev_state_origin":TODO-doc}

EDUs, by comparison to PDUs, do not have an ID, a context, or a list of
"previous" IDs. The only mandatory fields for these are the type, origin and
destination home server names, and the actual nested content.

::

 {"edu_type":"m.presence",
  "origin":"blue",
  "destination":"orange",
  "content":...}
  
  
Protocol URLs
-------------
.. WARNING::
  This section may be misleading or inaccurate.

All these URLs are namespaced within a prefix of::

  /_matrix/federation/v1/...

For active pushing of messages representing live activity "as it happens"::

  PUT .../send/:transaction_id/
    Body: JSON encoding of a single Transaction
    Response: TODO-doc

The transaction_id path argument will override any ID given in the JSON body.
The destination name will be set to that of the receiving server itself. Each
embedded PDU in the transaction body will be processed.


To fetch a particular PDU::

  GET .../pdu/:origin/:pdu_id/
    Response: JSON encoding of a single Transaction containing one PDU

Retrieves a given PDU from the server. The response will contain a single new
Transaction, inside which will be the requested PDU.
  

To fetch all the state of a given context::

  GET .../state/:context/
    Response: JSON encoding of a single Transaction containing multiple PDUs

Retrieves a snapshot of the entire current state of the given context. The
response will contain a single Transaction, inside which will be a list of PDUs
that encode the state.

To backfill events on a given context::

  GET .../backfill/:context/
    Query args: v, limit
    Response: JSON encoding of a single Transaction containing multiple PDUs

Retrieves a sliding-window history of previous PDUs that occurred on the given
context. Starting from the PDU ID(s) given in the "v" argument, the PDUs that
preceeded it are retrieved, up to a total number given by the "limit" argument.
These are then returned in a new Transaction containing all of the PDUs.


To stream events all the events::

  GET .../pull/
    Query args: origin, v
    Response: JSON encoding of a single Transaction consisting of multiple PDUs

Retrieves all of the transactions later than any version given by the "v"
arguments.


To make a query::

  GET .../query/:query_type
    Query args: as specified by the individual query types
    Response: JSON encoding of a response object

Performs a single query request on the receiving home server. The Query Type
part of the path specifies the kind of query being made, and its query
arguments have a meaning specific to that kind of query. The response is a
JSON-encoded object whose meaning also depends on the kind of query.

Backfilling
-----------
.. NOTE::
  This section is a work in progress.

.. TODO-doc
  - What it is, when is it used, how is it done

SRV Records
-----------
.. NOTE::
  This section is a work in progress.

.. TODO-doc
  - Why it is needed

State Conflict Resolution
-------------------------
.. NOTE::
  This section is a work in progress.

.. TODO-doc
  - How do conflicts arise (diagrams?)
  - How are they resolved (incl tie breaks)
  - How does this work with deleting current state

Presence
--------
The server API for presence is based entirely on exchange of the following
EDUs. There are no PDUs or Federation Queries involved.

Performing a presence update and poll subscription request::

  EDU type: m.presence

  Content keys:
    push: (optional): list of push operations.
      Each should be an object with the following keys:
        user_id: string containing a User ID
        presence: "offline"|"unavailable"|"online"|"free_for_chat"
        status_msg: (optional) string of freeform text
        last_active_ago: miliseconds since the last activity by the user

    poll: (optional): list of strings giving User IDs

    unpoll: (optional): list of strings giving User IDs

The presence of this combined message is two-fold: it informs the recipient
server of the current status of one or more users on the sending server (by the
``push`` key), and it maintains the list of users on the recipient server that
the sending server is interested in receiving updates for, by adding (by the
``poll`` key) or removing them (by the ``unpoll`` key). The ``poll`` and
``unpoll`` lists apply *changes* to the implied list of users; any existing IDs
that the server sent as ``poll`` operations in a previous message are not
removed until explicitly requested by a later ``unpoll``.

On receipt of a message containing a non-empty ``poll`` list, the receiving
server should immediately send the sending server a presence update EDU of its
own, containing in a ``push`` list the current state of every user that was in
the orginal EDU's ``poll`` list.

Sending a presence invite::

  EDU type: m.presence_invite

  Content keys:
    observed_user: string giving the User ID of the user whose presence is
      requested (i.e. the recipient of the invite)
    observer_user: string giving the User ID of the user who is requesting to
      observe the presence (i.e. the sender of the invite)

Accepting a presence invite::

  EDU type: m.presence_accept

  Content keys - as for m.presence_invite

Rejecting a presence invite::

  EDU type: m.presence_deny

  Content keys - as for m.presence_invite

.. TODO-doc
  - Explain the timing-based roundtrip reduction mechanism for presence
    messages
  - Explain the zero-byte presence inference logic
  See also: docs/client-server/model/presence

Profiles
--------
The server API for profiles is based entirely on the following Federation
Queries. There are no additional EDU or PDU types involved, other than the
implicit ``m.presence`` and ``m.room.member`` events (see section below).

Querying profile information::

  Query type: profile

  Arguments:
    user_id: the ID of the user whose profile to return
    field: (optional) string giving a field name

  Returns: JSON object containing the following keys:
    displayname: string of freeform text
    avatar_url: string containing an http-scheme URL

If the query contains the optional ``field`` key, it should give the name of a
result field. If such is present, then the result should contain only a field
of that name, with no others present. If not, the result should contain as much
of the user's profile as the home server has available and can make public.

Server-Server Authentication
----------------------------

.. TODO-doc
  - Why is this needed.
  - High level overview of process.
  - Transaction/PDU signing
  - How does this work with redactions? (eg hashing required keys only)



Threat Model
------------

Denial of Service
~~~~~~~~~~~~~~~~~

The attacker could attempt to prevent delivery of messages to or from the
victim in order to:

* Disrupt service or marketing campaign of a commercial competitor.
* Censor a discussion or censor a participant in a discussion.
* Perform general vandalism.

Threat: Resource Exhaustion
+++++++++++++++++++++++++++

An attacker could cause the victims server to exhaust a particular resource
(e.g. open TCP connections, CPU, memory, disk storage)

Threat: Unrecoverable Consistency Violations
++++++++++++++++++++++++++++++++++++++++++++

An attacker could send messages which created an unrecoverable "split-brain"
state in the cluster such that the victim's servers could no longer dervive a
consistent view of the chatroom state.

Threat: Bad History
+++++++++++++++++++

An attacker could convince the victim to accept invalid messages which the
victim would then include in their view of the chatroom history. Other servers
in the chatroom would reject the invalid messages and potentially reject the
victims messages as well since they depended on the invalid messages.

.. TODO-spec
  Track trustworthiness of HS or users based on if they try to pretend they
  haven't seen recent events, and fake a splitbrain... --M

Threat: Block Network Traffic
+++++++++++++++++++++++++++++

An attacker could try to firewall traffic between the victim's server and some
or all of the other servers in the chatroom.

Threat: High Volume of Messages
+++++++++++++++++++++++++++++++

An attacker could send large volumes of messages to a chatroom with the victim
making the chatroom unusable.

Threat: Banning users without necessary authorisation
+++++++++++++++++++++++++++++++++++++++++++++++++++++

An attacker could attempt to ban a user from a chatroom with the necessary
authorisation.

Spoofing
~~~~~~~~

An attacker could try to send a message claiming to be from the victim without
the victim having sent the message in order to:

* Impersonate the victim while performing illict activity.
* Obtain privileges of the victim.

Threat: Altering Message Contents
+++++++++++++++++++++++++++++++++

An attacker could try to alter the contents of an existing message from the
victim.

Threat: Fake Message "origin" Field
+++++++++++++++++++++++++++++++++++

An attacker could try to send a new message purporting to be from the victim
with a phony "origin" field.

Spamming
~~~~~~~~

The attacker could try to send a high volume of solicicted or unsolicted
messages to the victim in order to:

* Find victims for scams.
* Market unwanted products.

Threat: Unsoliticted Messages
+++++++++++++++++++++++++++++

An attacker could try to send messages to victims who do not wish to receive
them.

Threat: Abusive Messages
++++++++++++++++++++++++

An attacker could send abusive or threatening messages to the victim

Spying
~~~~~~

The attacker could try to access message contents or metadata for messages sent
by the victim or to the victim that were not intended to reach the attacker in
order to:

* Gain sensitive personal or commercial information.
* Impersonate the victim using credentials contained in the messages.
  (e.g. password reset messages)
* Discover who the victim was talking to and when.

Threat: Disclosure during Transmission
++++++++++++++++++++++++++++++++++++++

An attacker could try to expose the message contents or metadata during
transmission between the servers.

Threat: Disclosure to Servers Outside Chatroom
++++++++++++++++++++++++++++++++++++++++++++++

An attacker could try to convince servers within a chatroom to send messages to
a server it controls that was not authorised to be within the chatroom.

Threat: Disclosure to Servers Within Chatroom
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An attacker could take control of a server within a chatroom to expose message
contents or metadata for messages in that room.


Identity Servers
================
.. NOTE::
  This section is a work in progress.

.. TODO-doc Dave
  - 3PIDs and identity server, functions

Lawful Interception
-------------------

Key Escrow Servers
~~~~~~~~~~~~~~~~~~

Policy Servers
==============
.. NOTE::
  This section is a work in progress.

.. TODO-spec
  We should mention them in the Architecture section at least: how they fit
  into the picture.

Enforcing policies
------------------



.. Links through the external API docs are below
.. =============================================

.. |createRoom| replace:: ``/createRoom``
.. _createRoom: /docs/api/client-server/#!/-rooms/create_room

.. |initialSync| replace:: ``/initialSync``
.. _initialSync: /docs/api/client-server/#!/-events/initial_sync

.. |/rooms/<room_id>/initialSync| replace:: ``/rooms/<room_id>/initialSync``
.. _/rooms/<room_id>/initialSync: /docs/api/client-server/#!/-rooms/get_room_sync_data

.. |login| replace:: ``/login``
.. _login: /docs/api/client-server/#!/-login

.. |register| replace:: ``/register``
.. _register: /docs/api/client-server/#!/-registration

.. |/rooms/<room_id>/messages| replace:: ``/rooms/<room_id>/messages``
.. _/rooms/<room_id>/messages: /docs/api/client-server/#!/-rooms/get_messages

.. |/rooms/<room_id>/members| replace:: ``/rooms/<room_id>/members``
.. _/rooms/<room_id>/members: /docs/api/client-server/#!/-rooms/get_members

.. |/rooms/<room_id>/state| replace:: ``/rooms/<room_id>/state``
.. _/rooms/<room_id>/state: /docs/api/client-server/#!/-rooms/get_state_events

.. |/rooms/<room_id>/send/<event_type>| replace:: ``/rooms/<room_id>/send/<event_type>``
.. _/rooms/<room_id>/send/<event_type>: /docs/api/client-server/#!/-rooms/send_non_state_event

.. |/rooms/<room_id>/state/<event_type>/<state_key>| replace:: ``/rooms/<room_id>/state/<event_type>/<state_key>``
.. _/rooms/<room_id>/state/<event_type>/<state_key>: /docs/api/client-server/#!/-rooms/send_state_event

.. |/rooms/<room_id>/invite| replace:: ``/rooms/<room_id>/invite``
.. _/rooms/<room_id>/invite: /docs/api/client-server/#!/-rooms/invite

.. |/rooms/<room_id>/join| replace:: ``/rooms/<room_id>/join``
.. _/rooms/<room_id>/join: /docs/api/client-server/#!/-rooms/join_room

.. |/rooms/<room_id>/leave| replace:: ``/rooms/<room_id>/leave``
.. _/rooms/<room_id>/leave: /docs/api/client-server/#!/-rooms/leave

.. |/rooms/<room_id>/ban| replace:: ``/rooms/<room_id>/ban``
.. _/rooms/<room_id>/ban: /docs/api/client-server/#!/-rooms/ban

.. |/join/<room_alias_or_id>| replace:: ``/join/<room_alias_or_id>``
.. _/join/<room_alias_or_id>: /docs/api/client-server/#!/-rooms/join

.. _`Event Stream`: /docs/api/client-server/#!/-events/get_event_stream

