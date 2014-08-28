Matrix Specification
====================

TODO(Introduction) : Matthew
 - Similar to intro paragraph from README.
 - Explaining the overall mission, what this spec describes...
 - "What is Matrix?"

Architecture
============

- Basic structure: What are clients/home servers and what are their 
  responsibilities? What are events.

::

        { Matrix clients }                              { Matrix clients }
           ^          |                                    ^          |
           |  events  |                                    |  events  |
           |          V                                    |          V
       +------------------+                            +------------------+
       |                  |---------( HTTP )---------->|                  |
       |   Home Server    |                            |   Home Server    |
       |                  |<--------( HTTP )-----------|                  |
       +------------------+                            +------------------+
       
- How do identity servers fit in? 3PIDs? Users? Aliases
- Pattern of the APIs (HTTP/JSON, REST + txns)
- Standard error response format.
- C-S Event stream

Rooms
=====

A room is a conceptual place where users can send and receive messages. Rooms 
can be created, joined and left. Messages are sent to a room, and all 
participants in that room will receive the message. Rooms are uniquely 
identified via a room ID. There is exactly one room ID for each room.

- Aliases
- Invite/join dance
- State and non-state data (+extensibility)

TODO : Room permissions / config / power levels.

Messages
========

This specification outlines several standard message types, all of which are
prefixed with "m.".

- Namespacing?

State messages
--------------
- m.room.name
- m.room.topic
- m.room.member
- m.room.config
- m.room.invite_join

What are they, when are they used, what do they contain, how should they be used

Non-state messages
------------------
- m.room.message
- m.room.message.feedback (and compressed format)

What are they, when are they used, what do they contain, how should they be used

m.room.message types
--------------------
- m.text
- m.emote
- m.audio
- m.image
- m.video
- m.location


Presence
========

Each user has the concept of Presence information. This encodes a sense of the
"availability" of that user, suitable for display on other user's clients.

The basic piece of presence information is an enumeration of a small set of
state; such as "free to chat", "online", "busy", or "offline". The default state
unless the user changes it is "online". Lower states suggest some amount of
decreased availability from normal, which might have some client-side effect
like muting notification sounds and suggests to other users not to bother them
unless it is urgent. Equally, the "free to chat" state exists to let the user
announce their general willingness to receive messages moreso than default.

Home servers should also allow a user to set their state as "hidden" - a state
which behaves as offline, but allows the user to see the client state anyway and
generally interact with client features such as reading message history or
accessing contacts in the address book.

This basic state field applies to the user as a whole, regardless of how many
client devices they have connected. The home server should synchronise this
status choice among multiple devices to ensure the user gets a consistent
experience.

Idle Time
---------
As well as the basic state field, the presence information can also show a sense
of an "idle timer". This should be maintained individually by the user's
clients, and the homeserver can take the highest reported time as that to
report. Likely this should be presented in fairly coarse granularity; possibly
being limited to letting the home server automatically switch from a "free to
chat" or "online" mode into "idle".

When a user is offline, the Home Server can still report when the user was last
seen online, again perhaps in a somewhat coarse manner.

Device Type
-----------
Client devices that may limit the user experience somewhat (such as "mobile"
devices with limited ability to type on a real keyboard or read large amounts of
text) should report this to the home server, as this is also useful information
to report as "presence" if the user cannot be expected to provide a good typed
response to messages.

- m.presence and enums (when should they be used)

Presence List
-------------
Each user's home server stores a "presence list" for that user. This stores a
list of other user IDs the user has chosen to add to it (remembering any ACL
Pointer if appropriate).

To be added to a contact list, the user being added must grant permission. Once
granted, both user's HS(es) store this information, as it allows the user who
has added the contact some more abilities; see below. Since such subscriptions
are likely to be bidirectional, HSes may wish to automatically accept requests
when a reverse subscription already exists.

As a convenience, presence lists should support the ability to collect users
into groups, which could allow things like inviting the entire group to a new
("ad-hoc") chat room, or easy interaction with the profile information ACL
implementation of the HS.

Presence and Permissions
------------------------
For a viewing user to be allowed to see the presence information of a target
user, either

 * The target user has allowed the viewing user to add them to their presence
   list, or

 * The two users share at least one room in common

In the latter case, this allows for clients to display some minimal sense of
presence information in a user list for a room.

Home servers can also use the user's choice of presence state as a signal for
how to handle new private one-to-one chat message requests. For example, it
might decide:

 - "free to chat": accept anything
 - "online": accept from anyone in my address book list
 - "busy": accept from anyone in this "important people" group in my address
    book list

Typing notifications
====================

TODO : Leo

Voice over IP
=============

TODO : Dave

Profiles
========

Internally within Matrix users are referred to by their user ID, which is not a
human-friendly string. Profiles grant users the ability to see human-readable 
names for other users that are in some way meaningful to them. Additionally, 
profiles can publish additional information, such as the user's age or location.

It is also conceivable that since we are attempting to provide a
worldwide-applicable messaging system, that users may wish to present different
subsets of information in their profile to different other people, from a
privacy and permissions perspective.

A Profile consists of a display name, an avatar picture, and a set of other 
metadata fields that the user may wish to publish (email address, phone
numbers, website URLs, etc...). This specification puts no requirements on the 
display name other than it being a valid Unicode string.

- Metadata extensibility
- Bundled with which events? e.g. m.room.member

Registration and login
======================

Clients must register with a home server in order to use Matrix. After 
registering, the client will be given an access token which must be used in ALL
requests to that home server as a query parameter 'access_token'.

- TODO Kegan : Make registration like login (just omit the "user" key on the 
  initial request?)
- TODO Kegan : Allow alternative forms of login (>1 route)

If the client has already registered, they need to be able to login to their
account. The home server may provide many different ways of logging in, such
as user/password auth, login via a social network (OAuth2), login by confirming 
a token sent to their email address, etc. This specification does not define how
home servers should authorise their users who want to login to their existing 
accounts, but instead defines the standard interface which implementations 
should follow so that ANY client can login to ANY home server.

The login process breaks down into the following:
  1. Determine the requirements for logging in.
  2. Submit the login stage credentials.
  3. Get credentials or be told the next stage in the login process and repeat 
     step 2.
     
As each home server may have different ways of logging in, the client needs to know how
they should login. All distinct login stages MUST have a corresponding ``'type'``.
A ``'type'`` is a namespaced string which details the mechanism for logging in.

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
 - m.login.password
 - m.login.oauth2
 - m.login.email.code
 - m.login.email.url


Password-based
--------------
Type: 
  "m.login.password"
Description:
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
Type: 
  "m.login.oauth2"
Description:
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
Type: 
  "m.login.email.code"
Description:
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
Type: 
  "m.login.email.url"
Description:
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

This can be achieved by responding with the ``'next'`` login type on completion of a 
previous login stage::

  {
    "next": "<next login type>"
  }

If a home server implements N-factor authentication, it MUST respond with all 
``'stages'`` when initially queried for their login requirements::

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

TODO : Dave
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

 * Queries
   These are single request/response interactions between a given pair of
   servers, initiated by one side sending an HTTP request to obtain some
   information, and responded by the other. They are not persisted and contain
   no long-term significant history. They simply request a snapshot state at the
   instant the query is made.

 * EDUs - Ephemeral Data Units
   These are notifications of events that are pushed from one home server to
   another. They are not persisted and contain no long-term significant history,
   nor does the receiving home server have to reply to them.

 * PDUs - Persisted Data Units
   These are notifications of events that are broadcast from one home server to
   any others that are interested in the same "context" (namely, a Room ID).
   They are persisted to long-term storage and form the record of history for
   that context.

Where Queries are presented directly across the HTTP connection as GET requests
to specific URLs, EDUs and PDUs are further wrapped in an envelope called a
Transaction, which is transferred from the origin to the destination home server
using a PUT request.


Transactions and EDUs/PDUs
--------------------------
The transfer of EDUs and PDUs between home servers is performed by an exchange
of Transaction messages, which are encoded as JSON objects with a dict as the
top-level element, passed over an HTTP PUT request. A Transaction is meaningful
only to the pair of home servers that exchanged it; they are not globally-
meaningful.

Each transaction has an opaque ID and timestamp (UNIX epoch time in
milliseconds) generated by its origin server, an origin and destination server
name, a list of "previous IDs", and a list of PDUs - the actual message payload
that the Transaction carries.

 {"transaction_id":"916d630ea616342b42e98a3be0b74113",
  "ts":1404835423000,
  "origin":"red",
  "destination":"blue",
  "prev_ids":["e1da392e61898be4d2009b9fecce5325"],
  "pdus":[...],
  "edus":[...]}

The "previous IDs" field will contain a list of previous transaction IDs that
the origin server has sent to this destination. Its purpose is to act as a
sequence checking mechanism - the destination server can check whether it has
successfully received that Transaction, or ask for a retransmission if not.

The "pdus" field of a transaction is a list, containing zero or more PDUs.[*]
Each PDU is itself a dict containing a number of keys, the exact details of
which will vary depending on the type of PDU. Similarly, the "edus" field is
another list containing the EDUs. This key may be entirely absent if there are
no EDUs to transfer.

(* Normally the PDU list will be non-empty, but the server should cope with
receiving an "empty" transaction, as this is useful for informing peers of other
transaction IDs they should be aware of. This effectively acts as a push
mechanism to encourage peers to continue to replicate content.)

All PDUs have an ID, a context, a declaration of their type, a list of other PDU
IDs that have been seen recently on that context (regardless of which origin
sent them), and a nested content field containing the actual event content.

[[TODO(paul): Update this structure so that 'pdu_id' is a two-element
[origin,ref] pair like the prev_pdus are]]

 {"pdu_id":"a4ecee13e2accdadf56c1025af232176",
  "context":"#example.green",
  "origin":"green",
  "ts":1404838188000,
  "pdu_type":"m.text",
  "prev_pdus":[["blue","99d16afbc857975916f1d73e49e52b65"]],
  "content":...
  "is_state":false}

In contrast to the transaction layer, it is important to note that the prev_pdus
field of a PDU refers to PDUs that any origin server has sent, rather than
previous IDs that this origin has sent. This list may refer to other PDUs sent
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

 {"edu_type":"m.presence",
  "origin":"blue",
  "destination":"orange",
  "content":...}

Backfilling
-----------
- What it is, when is it used, how is it done

SRV Records
-----------
- Why it is needed

Security
========
- rate limiting
- crypto (s-s auth)
- E2E
- Lawful intercept + Key Escrow

TODO Mark

Policy Servers
==============
TODO

Content repository
==================
- thumbnail paths

Address book repository
=======================
- format


Glossary
========
- domain specific words/acronyms with definitions

User ID:
  An opaque ID which identifies an end-user, which consists of some opaque 
  localpart combined with the domain name of their home server. 
