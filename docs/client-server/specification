=========================
Synapse Client-Server API
=========================

The following specification outlines how a client can send and receive data from 
a home server.

[[TODO(kegan): 4/7/14 Grilling
- Mechanism for getting historical state changes (e.g. topic updates) - add 
  query param flag?
- Generic mechanism for linking first class events (e.g. feedback) with other s
  first class events (e.g. messages)?
- Generic mechanism for updating 'stuff about the room' (e.g. favourite coffee) 
  AND specifying clobbering rules (clobber/add to list/etc)?
- How to ensure a consistent view for clients paginating through room lists? 
  They aren't really ordered in any way, and if you're paginating
  through them, how can you show them a consistent result set? Temporary 'room 
  list versions' akin to event version? How does that work?
]]

[[TODO(kegan):
Outstanding problems / missing spec:
- Push
- Typing notifications
]]

Terminology
-----------
Stream Tokens: 
An opaque token used to make further streaming requests. When using any 
pagination streaming API, responses will contain a start and end stream token. 
When reconnecting to the stream, these tokens can be used to tell the server 
where the client got up to in the stream.

Event ID:
Every event that comes down the event stream or that is returned from the REST
API has an associated event ID (event_id). This ID will be the same between the 
REST API and the event stream, so any duplicate events can be clobbered 
correctly without knowing anything else about the event.

Message ID:
The ID of a message sent by a client in a room. Clients send IMs to each other 
in rooms. Each IM sent by a client must have a unique message ID which is unique
for that particular client.

User ID:
The @username:host style ID of the client. When registering for an account, the 
client specifies their username. The user_id is this username along with the 
home server's unique hostname. When federating between home servers, the user_id
is used to uniquely identify users across multiple home servers.

Room ID:
The room_id@host style ID for the room. When rooms are created, the client either
specifies or is allocated a room ID. This room ID must be used to send messages 
in that room. Like with clients, there may be multiple rooms with the same ID 
across multiple home servers. The room_id is used to uniquely identify a room 
when federating.

Global message ID:
The globally unique ID for a message. This ID is formed from the msg_id, the 
client's user_id and the room_id. This uniquely identifies any 
message. It is represented with '-' as the delimeter between IDs. The 
global_msg_id is of the form: room_id-user_id-msg_id


REST API and the Event Stream
-----------------------------
Clients send data to the server via a RESTful API. They can receive data via 
this API or from an event stream. An event stream is a special path which 
streams all events the client may be interested in. This makes it easy to 
immediately receive updates from the REST API. All data is represented as JSON.

Pagination streaming API
========================
Clients are often interested in very large datasets. The data itself could
be 1000s of messages in a given room, 1000s of rooms in a public room list, or
1000s of events (presence, typing, messages, etc) in the system. It is not
practical to send vast quantities of data to the client every time they
request a list of public rooms for example. There needs to be a way to show a
subset of this data, and apply various filters to it. This is what the pagination
streaming API is. This API defines standard request/response parameters which 
can be used when navigating this stream of data.

Pagination Request Query Parameters
-----------------------------------
Clients may wish to paginate results from the event stream, or other sources of 
information where the amount of information may be a problem,
e.g. in a room with 10,000s messages. The pagination query parameters provide a 
way to navigate a 'window' around a large set of data. These
parameters are only valid for GET requests.
       
        S e r v e r - s i d e   d a t a
 |-------------------------------------------------|
START      ^               ^                      END
           |_______________|
                   |
            Client-extraction

'START' and 'END' are magic token values which specify the start and end of the 
dataset respectively.

Query parameters:
  from : $streamtoken - The opaque token to start streaming from.
  to : $streamtoken - The opaque token to end streaming at. Typically,
       clients will not know the item of data to end at, so this will usually be 
       START or END.
  limit : integer - An integer representing the maximum number of items to 
          return.

For example, the event stream has events E1 -> E15. The client wants the last 5 
events and doesn't know any previous events:

S                                                    E
|-E1-E2-E3-E4-E5-E6-E7-E8-E9-E10-E11-E12-E13-E14-E15-|
|                               |                    |
|                          _____|                    |
|__________________       |       ___________________|
                   |      |      |
 GET /events?to=START&limit=5&from=END
 Returns:
   E15,E14,E13,E12,E11


Another example: a public room list has rooms R1 -> R17. The client is showing 5 
rooms at a time on screen, and is on page 2. They want to
now show page 3 (rooms R11 -> 15):

S                                                           E
|  0  1  2  3  4  5  6  7  8  9  10  11  12  13  14  15  16 | stream token
|-R1-R2-R3-R4-R5-R6-R7-R8-R9-R10-R11-R12-R13-R14-R15-R16-R17| room
                  |____________| |________________|
                        |                |
                    Currently            |
                    viewing              |
                                         |
                         GET /rooms/list?from=9&to=END&limit=5
                         Returns: R11,R12,R13,R14,R15
                         
Note that tokens are treated in an *exclusive*, not inclusive, manner. The end 
token from the intial request was '9' which corresponded to R10. When the 2nd
request was made, R10 did not appear again, even though from=9 was specified. If
you know the token, you already have the data.

Pagination Response
-------------------
Responses to pagination requests MUST follow the format:
{
  "chunk": [ ... , Responses , ... ],
  "start" : $streamtoken,
  "end" : $streamtoken
}
Where $streamtoken is an opaque token which can be used in another query to
get the next set of results. The "start" and "end" keys can only be omitted if
the complete dataset is provided in "chunk".

If the client wants earlier results, they should use from=$start_streamtoken,
to=START. Likewise, if the client wants later results, they should use
from=$end_streamtoken, to=END.

Unless specified, the default pagination parameters are from=START, to=END, 
without a limit set. This allows you to hit an API like
/events without any query parameters to get everything.

The Event Stream
----------------
The event stream returns events using the pagination streaming API. When the 
client disconnects for a while and wants to reconnect to the event stream, they 
should specify from=$end_streamtoken. This lets the server know where in the 
event stream the client is. These tokens are completely opaque, and the client 
cannot infer anything from them.

  GET /events?from=$LAST_STREAM_TOKEN
  REST Path: /events
  Returns (success): A JSON array of Event Data.
  Returns (failure): An Error Response

LAST_STREAM_TOKEN is the last stream token obtained from the event stream. If the 
client is connecting for the first time and does not know any stream tokens,
they can use "START" to request all events from the start. For more information 
on this, see "Pagination Request Query Parameters".

The event stream supports shortpoll and longpoll with the "timeout" query
parameter. This parameter specifies the number of milliseconds the server should
hold onto the connection waiting for incoming events. If no events occur in this
period, the connection will be closed and an empty chunk will be returned. To
use shortpoll, specify "timeout=0".

Event Data
----------
This is a JSON object which looks like:
{
  "event_id" : $EVENT_ID,
  "type" : $EVENT_TYPE,
  $URL_ARGS,
  "content" : {
    $EVENT_CONTENT
  }
}

EVENT_ID
  An ID identifying this event. This is so duplicate events can be suppressed on
  the client.

EVENT_TYPE
  The namespaced event type (m.*)

URL_ARGS
  Path specific data from the REST API.

EVENT_CONTENT
  The event content, matching the REST content PUT previously.

Events are differentiated via the event type "type" key. This is the type of 
event being received. This can be expanded upon by using different namespaces. 
Every event MUST have a 'type' key.

Most events will have a corresponding REST URL. This URL will generally have 
data in it to represent the resource being modified,
e.g. /rooms/$room_id. The event data will contain extra top-level keys to expose 
this information to clients listening on an event
stream. The event content maps directly to the contents submitted via the REST 
API.

For example:
  Event Type: m.example.room.members
  REST Path: /examples/room/$room_id/members/$user_id
  REST Content: { "membership" : "invited" }
  
is represented in the event stream as:

{
  "event_id" : "e_some_event_id",
  "type" : "m.example.room.members",
  "room_id" : $room_id,
  "user_id" : $user_id,
  "content" : {
    "membership" : "invited"
  }
}

As convention, the URL variable "$varname" will map directly onto the name 
of the JSON key "varname".

Error Responses
---------------
If the client sends an invalid request, the server MAY respond with an error 
response. This is of the form:
{
  "error" : "string",
  "errcode" : "string"
}
The 'error' string will be a human-readable error message, usually a sentence
explaining what went wrong. 

The 'errcode' string will be a unique string which can be used to handle an 
error message e.g. "M_FORBIDDEN". These error codes should have their namespace 
first in ALL CAPS, followed by a single _. For example, if there was a custom
namespace com.mydomain.here, and a "FORBIDDEN" code, the error code should look
like "COM.MYDOMAIN.HERE_FORBIDDEN". There may be additional keys depending on 
the error, but the keys 'error' and 'errcode' will always be present. 

Some standard error codes are below:

M_FORBIDDEN:
Forbidden access, e.g. bad access token, failed login.

M_BAD_JSON:
Request contained valid JSON, but it was malformed in some way, e.g. missing
required keys, invalid values for keys.

M_NOT_JSON:
Request did not contain valid JSON.

M_NOT_FOUND:
No resource was found for this request.

Some requests have unique error codes:

M_USER_IN_USE:
Encountered when trying to register a user ID which has been taken.

M_ROOM_IN_USE:
Encountered when trying to create a room which has been taken.

M_BAD_PAGINATION:
Encountered when specifying bad pagination values to a Pagination Streaming API.


========
REST API
========

All content must be application/json. Some keys are required, while others are 
optional. Unless otherwise specified,
all HTTP PUT/POST/DELETEs will return a 200 OK with an empty response body on 
success, and a 4xx/5xx with an optional Error Response on failure. When sending 
data, if there are no keys to send, an empty JSON object should be sent.

All POST/PUT/GET/DELETE requests MUST have an 'access_token' query parameter to 
allow the server to authenticate the client. All
POST requests MUST be submitted as application/json. 

All paths MUST be namespaced by the version of the API being used. This should
be:

/matrix/client/api/v1

All REST paths in this section MUST be prefixed with this. E.g.
  REST Path: /rooms/$room_id
  Absolute Path: /matrix/client/api/v1/rooms/$room_id

Registration
============
Clients must register with the server in order to use the service. After 
registering, the client will be given an
access token which must be used in ALL requests as a query parameter 
'access_token'.

Registering for an account
--------------------------
  POST /register
  With: A JSON object containing the key "user_id" which contains the desired 
        user_id, or an empty JSON object to have the server allocate a user_id 
        automatically.
  Returns (success): 200 OK with a JSON object:
                     {
                       "user_id" : "string [user_id]",
                       "access_token" : "string"
                     }
  Returns (failure): An Error Response. M_USER_IN_USE if the user ID is taken.
                     

Unregistering an account
------------------------
  POST /unregister
  With query parameters: access_token=$ACCESS_TOKEN
  Returns (success): 200 OK
  Returns (failure): An Error Response.
  
  
Logging in to an existing account
=================================
If the client has already registered, they need to be able to login to their
account. The home server may provide many different ways of logging in, such
as user/password auth, login via a social network (OAuth), login by confirming 
a token sent to their email address, etc. This section does NOT define how home 
servers should authorise their users who want to login to their existing 
accounts. This section defines the standard interface which implementations 
should follow so that ANY client can login to ANY home server.

The login process breaks down into the following:
  1: Get login process info.
  2: Submit the login stage credentials.
  3: Get access token or be told the next stage in the login process and repeat 
     step 2.
     
Getting login process info:
  GET /login
  Returns (success): 200 OK with LoginInfo.
  Returns (failure): An Error Response.
  
Submitting the login stage credentials:
  POST /login
  With: LoginSubmission
  Returns (success): 200 OK with LoginResult
  Returns (failure): An Error Response
  
Where LoginInfo is a JSON object which MUST have a "type" key which denotes the 
login type. If there are multiple login stages, this object MUST also contain a 
"stages" key, which has a JSON array of login types denoting all the steps in 
order to login, including the first stage which is in "type". This allows the 
client to make an informed decision as to whether or not they can natively
handle the entire login process, or whether they should fallback (see below).

Where LoginSubmission is a JSON object which MUST have a "type" key.

Where LoginResult is a JSON object which MUST have either a "next" key OR an
"access_token" key, depending if the login process is over or not. This object
MUST have a "session" key if multiple POSTs need to be sent to /login.

Fallback
--------
If the client does NOT know how to handle the given type, they should:
  GET /login/fallback
This MUST return an HTML page which can perform the entire login process.

Password-based
--------------
Type: "m.login.password"
LoginSubmission:
{
  "type": "m.login.password",
  "user": <user_id>,
  "password": <password>
}

Example:
Assume you are @bob:matrix.org and you wish to login on another mobile device.
First, you GET /login which returns:
{
  "type": "m.login.password"
}
Your client knows how to handle this, so your client prompts the user to enter
their username and password. This is then submitted:
{
  "type": "m.login.password",
  "user": "@bob:matrix.org",
  "password": "monkey"
}
The server checks this, finds it is valid, and returns:
{
  "access_token": "abcdef0123456789"
}

OAuth2-based
------------
Type: "m.login.oauth2"
This is a multi-stage login.

LoginSubmission:
{
  "type": "m.login.oauth2",
  "user": <user_id>
}
Returns:
{
  "uri": <Authorization Request uri OR service selection uri>
}

The home server acts as a 'confidential' Client for the purposes of OAuth2.

If the uri is a "sevice selection uri", it is a simple page which prompts the 
user to choose which service to authorize with. On selection of a service, they
link through to Authorization Request URIs. If there is only 1 service which the
home server accepts when logging in, this indirection can be skipped and the
"uri" key can be the Authorization Request URI. 

The client visits the Authorization Request URI, which then shows the OAuth2 
Allow/Deny prompt. Hitting 'Allow' returns the redirect URI with the auth code. 
Home servers can choose any path for the redirect URI. The client should visit 
the redirect URI, which will then finish the OAuth2 login process, granting the 
home server an access token for the chosen service. When the home server gets 
this access token, it knows that the cilent has authed with the 3rd party, and 
so can return a LoginResult.

The OAuth redirect URI (with auth code) MUST return a LoginResult.
    
Example:
Assume you are @bob:matrix.org and you wish to login on another mobile device.
First, you GET /login which returns:
{
  "type": "m.login.oauth2"
}
Your client knows how to handle this, so your client prompts the user to enter
their username. This is then submitted:
{
  "type": "m.login.oauth2",
  "user": "@bob:matrix.org"
}
The server only accepts auth from Google, so returns the Authorization Request
URI for Google:
{
  "uri": "https://accounts.google.com/o/oauth2/auth?response_type=code&
  client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&scope=photos"
}
The client then visits this URI and authorizes the home server. The client then
visits the REDIRECT_URI with the auth code= query parameter which returns:
{
  "access_token": "0123456789abcdef"
}

Email-based (code)
------------------
Type: "m.login.email.code"
This is a multi-stage login.

First LoginSubmission:
{
  "type": "m.login.email.code",
  "user": <user_id>
  "email": <email address>
}
Returns:
{
  "session": <session id>
}

The email contains a code which must be sent in the next LoginSubmission:
{
  "type": "m.login.email.code",
  "session": <session id>,
  "code": <code in email sent>
}
Returns:
{
  "access_token": <access token>
}

Example:
Assume you are @bob:matrix.org and you wish to login on another mobile device.
First, you GET /login which returns:
{
  "type": "m.login.email.code"
}
Your client knows how to handle this, so your client prompts the user to enter
their email address. This is then submitted:
{
  "type": "m.login.email.code",
  "user": "@bob:matrix.org",
  "email": "bob@mydomain.com"
}
The server confirms that bob@mydomain.com is linked to @bob:matrix.org, then 
sends an email to this address and returns:
{
  "session": "ewuigf7462"
}
The client's screen changes to a code submission page. The email arrives and it 
says something to the effect of "please enter 2348623 into the app". This is
the submitted along with the session:
{
  "type": "m.login.email.code",
  "session": "ewuigf7462",
  "code": "2348623"
}
The server accepts this and returns:
{
  "access_token": "abcdef0123456789"
}

Email-based (url)
-----------------
Type: "m.login.email.url"
This is a multi-stage login.

First LoginSubmission:
{
  "type": "m.login.email.url",
  "user": <user_id>
  "email": <email address>
}
Returns:
{
  "session": <session id>
}

The email contains a URL which must be clicked. After it has been clicked, the
client should perform a request:
{
  "type": "m.login.email.code",
  "session": <session id>
}
Returns:
{
  "access_token": <access token>
}

Example:
Assume you are @bob:matrix.org and you wish to login on another mobile device.
First, you GET /login which returns:
{
  "type": "m.login.email.url"
}
Your client knows how to handle this, so your client prompts the user to enter
their email address. This is then submitted:
{
  "type": "m.login.email.url",
  "user": "@bob:matrix.org",
  "email": "bob@mydomain.com"
}
The server confirms that bob@mydomain.com is linked to @bob:matrix.org, then 
sends an email to this address and returns:
{
  "session": "ewuigf7462"
}
The client then starts polling the server with the following:
{
  "type": "m.login.email.url",
  "session": "ewuigf7462"
}
(Alternatively, the server could send the device a push notification when the
email has been validated). The email arrives and it contains a URL to click on.
The user clicks on the which completes the login process with the server. The
next time the client polls, it returns:
{
  "access_token": "abcdef0123456789"
}

N-Factor auth
-------------
Multiple login stages can be combined with the "next" key in the LoginResult.

Example:
A server demands an email.code then password auth before logging in. First, the
client performs a GET /login which returns:
{
  "type": "m.login.email.code",
  "stages": ["m.login.email.code", "m.login.password"]
}
The client performs the email login (See "Email-based (code)"), but instead of
returning an access_token, it returns:
{
  "next": "m.login.password"
}
The client then presents a user/password screen and the login continues until
this is complete (See "Password-based"), which then returns the "access_token".

Rooms
=====
A room is a conceptual place where users can send and receive messages. Rooms 
can be created, joined and left. Messages are sent
to a room, and all participants in that room will receive the message. Rooms are 
uniquely identified via the room_id.

Creating a room (with a room ID)
--------------------------------
  Event Type: m.room.create [TODO(kegan): Do we generate events for this?]
  REST Path: /rooms/$room_id
  Valid methods: PUT
  Required keys: None.
  Optional keys:
    visibility : [public|private] - Set whether this room shows up in the public 
    room list.
  Returns:
    On Failure: MAY return a suggested alternative room ID if this room ID is 
    taken.
    {
      suggested_room_id : $new_room_id
      error : "Room already in use."
      errcode : "M_ROOM_IN_USE"
    }
    

Creating a room (without a room ID)
-----------------------------------
  Event Type: m.room.create [TODO(kegan): Do we generate events for this?]
  REST Path: /rooms
  Valid methods: POST
  Required keys: None.
  Optional keys:
    visibility : [public|private] - Set whether this room shows up in the public 
    room list.
  Returns:
    On Success: The allocated room ID. Additional information about the room
    such as the visibility MAY be included as extra keys in this response.
    {
      room_id : $room_id
    }

Setting the topic for a room
----------------------------
  Event Type: m.room.topic
  REST Path: /rooms/$room_id/topic
  Valid methods: GET/PUT
  Required keys: 
    topic : $topicname - Set the topic to $topicname in room $room_id.


See a list of public rooms
--------------------------
  REST Path: /public/rooms?pagination_query_parameters
  Valid methods: GET
  This API can use pagination query parameters.
  Returns:
    {
      "chunk" : JSON array of RoomInfo JSON objects - Required.
      "start" : "string (start token)" - See Pagination Response.
      "end" : "string (end token)" - See Pagination Response.
      "total" : integer - Optional. The total number of rooms.
    }

RoomInfo: Information about a single room.
  Servers MUST send the key: room_id
  Servers MAY send the keys: topic, num_members
  {
    "room_id" : "string",
    "topic" : "string",
    "num_members" : integer
  }

Room Members
============

Invite/Joining/Leaving a room
-----------------------------
  Event Type: m.room.member
  REST Path: /rooms/$room_id/members/$user_id/state
  Valid methods: PUT/GET/DELETE
  Required keys:
    membership : [join|invite] - The membership state of $user_id in room 
                                 $room_id.

Where:
  join - Indicate you ($user_id) are joining the room $room_id.
  invite - Indicate that $user_id has been invited to room $room_id.

User $user_id can leave room $room_id by DELETEing this path.

Checking the user list of a room
--------------------------------
  REST Path: /rooms/$room_id/members/list
  This API can use pagination query parameters.
  Valid methods: GET
  Returns:
    A pagination response with chunk data as m.room.member events.

Messages
========
Users send messages to other users in rooms. These messages may be text, images, 
video, etc. Clients may also want to acknowledge messages by sending feedback, 
in the form of delivery/read receipts.

Server-attached keys
--------------------
The server MAY attach additional keys to messages and feedback. If a client 
submits keys with the same name, they will be clobbered by
the server.

Required keys:
from : "string [user_id]"
  The user_id of the user who sent the message/feedback.

Optional keys:
hsob_ts : integer
  A timestamp (ms resolution) representing when the message/feedback got to the 
  sender's home server ("home server outbound timestamp").

hsib_ts : integer
  A timestamp (ms resolution) representing when the 
  message/feedback got to the receiver's home server ("home server inbound 
  timestamp"). This may be the same as hsob_ts if the sender/receiver are on the 
  same home server.

Sending messages
----------------
  Event Type: m.room.message
  REST Path: /rooms/$room_id/messages/$from/$msg_id
  Valid methods: GET/PUT
  URL parameters:
    $from : user_id - The sender's user_id. This value will be clobbered by the 
    server before sending.
  Required keys: 
    msgtype: [m.text|m.emote|m.image|m.audio|m.video|m.location|m.file] - 
             The type of message. Not to be confused with the Event 'type'.
  Optional keys:
    sender_ts : integer - A timestamp (ms resolution) representing the 
                wall-clock time when the message was sent from the client.
  Reserved keys:
    body : "string" - The human readable string for compatibility with clients 
           which cannot process a given msgtype. This key is optional, but
           if it is included, it MUST be human readable text 
           describing the message. See individual msgtypes for more 
           info on what this means in practice.

Each msgtype may have required fields of their own.

msgtype: m.text
----------------
Required keys:
  body : "string" - The body of the message.
Optional keys:
  None.

msgtype: m.emote
-----------------
Required keys:
  body : "string" - *tries to come up with a witty explanation*.
Optional keys:
  None.

msgtype: m.image
-----------------
Required keys:
  url : "string" - The URL to the image.
Optional keys:
  body : "string" - info : JSON object (ImageInfo) - The image info for image 
         referred to in 'url'.
  thumbnail_url : "string" - The URL to the thumbnail.
  thumbnail_info : JSON object (ImageInfo) - The image info for the image 
                   referred to in 'thumbnail_url'.

ImageInfo: Information about an image.
{
  "size" : integer (size of image in bytes),
  "w" : integer (width of image in pixels),
  "h" : integer (height of image in pixels),
  "mimetype" : "string (e.g. image/jpeg)"
}

Interpretation of 'body' key: The alt text of the image, or some kind of content 
description for accessibility e.g. "image attachment".

msgtype: m.audio
-----------------
Required keys:
  url : "string" - The URL to the audio.
Optional keys:
  info : JSON object (AudioInfo) - The audio info for the audio referred to in 
         'url'.

AudioInfo: Information about a piece of audio. 
{
  "mimetype" : "string (e.g. audio/aac)",
  "size" : integer (size of audio in bytes),
  "duration" : integer (duration of audio in milliseconds)
}

Interpretation of 'body' key: A description of the audio e.g. "Bee Gees - 
Stayin' Alive", or some kind of content description for accessibility e.g. 
"audio attachment".

msgtype: m.video
-----------------
Required keys:
  url : "string" - The URL to the video.
Optional keys:
  info : JSON object (VideoInfo) - The video info for the video referred to in 
         'url'.

VideoInfo: Information about a video.
{
  "mimetype" : "string (e.g. video/mp4)",
  "size" : integer (size of video in bytes),
  "duration" : integer (duration of video in milliseconds),
  "w" : integer (width of video in pixels),
  "h" : integer (height of video in pixels),
  "thumbnail_url" : "string (URL to image)",
  "thumbanil_info" : JSON object (ImageInfo)
}

Interpretation of 'body' key: A description of the video e.g. "Gangnam style", 
or some kind of content description for accessibility e.g. "video attachment".

msgtype: m.location
--------------------
Required keys:
  geo_uri : "string" - The geo URI representing the location.
Optional keys:
  thumbnail_url : "string" - The URL to a thumnail of the location being 
                  represented.
  thumbnail_info : JSON object (ImageInfo) - The image info for the image 
                   referred to in 'thumbnail_url'.

Interpretation of 'body' key: A description of the location e.g. "Big Ben, 
London, UK", or some kind of content description for accessibility e.g. 
"location attachment".


Sending feedback
----------------
When you receive a message, you may want to send delivery receipt to let the 
sender know that the message arrived. You may also want to send a read receipt 
when the user has read the message. These receipts are collectively known as 
'feedback'.

  Event Type: m.room.message.feedback
  REST Path: /rooms/$room_id/messages/$msgfrom/$msg_id/feedback/$from/$feedback
  Valid methods: GET/PUT
  URL parameters:
    $msgfrom - The sender of the message's user_id.
    $from : user_id - The sender of the feedback's user_id. This value will be 
    clobbered by the server before sending.
    $feedback : [d|r] - Specify if this is a [d]elivery or [r]ead receipt.
  Required keys:
    None.
  Optional keys:
    sender_ts : integer - A timestamp (ms resolution) representing the 
    wall-clock time when the receipt was sent from the client.

Receiving messages (bulk/pagination)
------------------------------------
  Event Type: m.room.message
  REST Path: /rooms/$room_id/messages/list
  Valid methods: GET
  Query Parameters:
    feedback : [true|false] - Specify if feedback should be bundled with each 
    message.
  This API can use pagination query parameters.
  Returns:
    A JSON array of Event Data in "chunk" (see Pagination Response). If the 
    "feedback" parameter was set, the Event Data will also contain a "feedback" 
    key which contains a JSON array of feedback, with each element as Event Data 
    with compressed feedback for this message.

Event Data with compressed feedback is a special type of feedback with 
contextual keys removed. It is designed to limit the amount of redundant data 
being sent for feedback. This removes the type, event_id, room ID, 
message sender ID and message ID keys.

     ORIGINAL (via event streaming)
{
  "event_id":"e1247632487",
  "type":"m.room.message.feedback",
  "from":"string [user_id]",
  "feedback":"string [d|r]",
  "room_id":"$room_id",
  "msg_id":"$msg_id",
  "msgfrom":"$msgfromid",
  "content":{
    "sender_ts":139880943
  }
}

     COMPRESSED (via /messages/list)
{
  "from":"string [user_id]",
  "feedback":"string [d|r]",
  "content":{
    "sender_ts":139880943
  }
}

When you join a room $room_id, you may want the last 10 messages with feedback. 
This is represented as:
  GET 
  /rooms/$room_id/messages/list?from=END&to=START&limit=10&feedback=true

You may want to get 10 messages even earlier than that without feedback. If the 
start stream token from the previous request was stok_019173, this request would 
be:
  GET 
  /rooms/$room_id/messages/list?from=stok_019173&to=START&limit=10&
                               feedback=false
  
NOTE: Care must be taken when using this API in conjunction with event 
      streaming. It is possible that this will return a message which will
      then come down the event stream, resulting in a duplicate message. Clients 
      should clobber based on the global message ID, or event ID.


Get current state for all rooms (aka IM Initial Sync API)
-------------------------------
  REST Path: /im/sync
  Valid methods: GET
  This API can use pagination query parameters. Pagination is applied on a per
  *room* basis. E.g. limit=1 means "get 1 message for each room" and not "get 1
  room's messages". If there is no limit, all messages for all rooms will be
  returned.
  If you want 1 room's messages, see "Receiving messages (bulk/pagination)".
  Additional query parameters: 
    feedback: [true] - Bundles feedback with messages.
  Returns:
    An array of RoomStateInfo.

RoomStateInfo: A snapshot of information about a single room.
  {
    "room_id" : "string",
    "membership" : "string [join|invite]",
    "messages" : {
      "start": "string",
      "end": "string",
      "chunk":
      m.room.message pagination stream events (with feedback if specified),
      this is the same as "Receiving messages (bulk/pagination)".
    }
  }
The "membership" key is the calling user's membership state in the given 
"room_id". The "messages" key may be omitted if the "membership" value is 
"invite". Additional keys may be added to the top-level object, such as:
  "topic" : "string" - The topic for the room in question.
  "room_image_url" : "string" - The URL of the room image if specified.
  "num_members" : integer - The number of members in the room.


Profiles
========

Getting/Setting your own displayname
------------------------------------
  REST Path: /profile/$user_id/displayname
  Valid methods: GET/PUT
  Required keys:
    displayname : The displayname text

Getting/Setting your own avatar image URL
-----------------------------------------
The homeserver does not currently store the avatar image itself, but offers
storage for the user to specify a web URL that points at the required image,
leaving it up to clients to fetch it themselves.
  REST Path: /profile/$user_id/avatar_url
  Valid methods: GET/PUT
  Required keys:
    avatar_url : The URL path to the required image

Getting other user's profile information
----------------------------------------
Either of the above REST methods may be used to fetch other user's profile
information by the client, either on other local users on the same homeserver or
for users from other servers entirely.


Presence
========

In the following messages, the presence state is an integer enumeration of the
following states:
  0 : OFFLINE
  1 : BUSY
  2 : ONLINE
  3 : FREE_TO_CHAT

Aside from OFFLINE, the protocol doesn't assign any special meaning to these
states; they are provided as an approximate signal for users to give to other
users and for clients to present them in some way that may be useful. Clients
could have different behaviours for different states of the user's presence, for
example to decide how much prominence or sound to use for incoming event
notifications.

Getting/Setting your own presence state
---------------------------------------
  REST Path: /presence/$user_id/status
  Valid methods: GET/PUT
  Required keys:
    state : [0|1|2|3] - The user's new presence state
  Optional keys:
    status_msg : text string provided by the user to explain their status

Fetching your presence list
---------------------------
  REST Path: /presence_list/$user_id
  Valid methods: GET/(post)
  Returns:
    An array of presence list entries. Each entry is an object with the
    following keys:
      {
        "user_id" : string giving the observed user's ID
        "state" : int giving their status
        "status_msg" : optional text string
        "displayname" : optional text string from the user's profile
        "avatar_url" : optional text string from the user's profile
      }

Maintaining your presence list
------------------------------
  REST Path: /presence_list/$user_id
  Valid methods: POST/(get)
  With: A JSON object optionally containing either of the following keys:
    "invite" : a list of strings giving user IDs to invite for presence
      subscription
    "drop" : a list of strings giving user IDs to remove from your presence
      list

Receiving presence update events
--------------------------------
  Event Type: m.presence
  Keys of the event's content are the same as those returned by the presence
    list.

Examples
========

The following example is the story of "bob", who signs up at "sy.org" and joins 
the public room "room_beta@sy.org". They get the 2 most recent
messages (with feedback) in that room and then send a message in that room. 

For context, here is the complete chat log for room_beta@sy.org:

Room: "Hello world" (room_beta@sy.org)
Members: (2) alice@randomhost.org, friend_of_alice@randomhost.org
Messages:
  alice@randomhost.org : hi friend!                     
  [friend_of_alice@randomhost.org DELIVERED]
  alice@randomhost.org : you're my only friend          
  [friend_of_alice@randomhost.org DELIVERED]
  alice@randomhost.org : afk                            
  [friend_of_alice@randomhost.org DELIVERED]
  [ bob@sy.org joins ]
  bob@sy.org : Hi everyone
  [ alice@randomhost.org changes the topic to "FRIENDS ONLY" ]
  alice@randomhost.org : Hello!!!!
  alice@randomhost.org : Let's go to another room
  alice@randomhost.org : You're not my friend
  [ alice@randomhost.org invites bob@sy.org to the room 
  commoners@randomhost.org]


REGISTER FOR AN ACCOUNT
POST: /register
Content: {}
Returns: { "user_id" : "bob@sy.org" , "access_token" : "abcdef0123456789" }

GET PUBLIC ROOM LIST
GET: /rooms/list?access_token=abcdef0123456789
Returns: 
{ 
  "total":3,
  "chunk":
  [
    { "room_id":"room_alpha@sy.org", "topic":"I am a fish" },
    { "room_id":"room_beta@sy.org", "topic":"Hello world" },
    { "room_id":"room_xyz@sy.org", "topic":"Goodbye cruel world" }
  ]
}

JOIN ROOM room_beta@sy.org
PUT 
/rooms/room_beta%40sy.org/members/bob%40sy.org/state?
                                    access_token=abcdef0123456789
Content: { "membership" : "join" }
Returns: 200 OK

GET LATEST 2 MESSAGES WITH FEEDBACK
GET 
/rooms/room_beta%40sy.org/messages/list?from=END&to=START&limit=2&
                                    feedback=true&access_token=abcdef0123456789
Returns:
{
  "chunk":
    [
      { 
        "event_id":"01948374", 
        "type":"m.room.message",
        "room_id":"room_beta@sy.org",
        "msg_id":"avefifu",
        "from":"alice@randomhost.org",
        "hs_ts":139985736,
        "content":{
          "msgtype":"m.text",
          "body":"afk"
        }
        "feedback": [
          {
            "from":"friend_of_alice@randomhost.org",
            "feedback":"d",
            "hs_ts":139985850,
            "content":{
              "sender_ts":139985843
            }
          }
        ]
      },
      { 
        "event_id":"028dfe8373", 
        "type":"m.room.message",
        "room_id":"room_beta@sy.org",
        "msg_id":"afhgfff",
        "from":"alice@randomhost.org",
        "hs_ts":139970006,
        "content":{
          "msgtype":"m.text",
          "body":"you're my only friend"
        }
        "feedback": [
          {
            "from":"friend_of_alice@randomhost.org",
            "feedback":"d",
            "hs_ts":139970144,
            "content":{
              "sender_ts":139970122
            }
          }
        ]
      },
    ],
  "start": "stok_04823947",
  "end": "etok_1426425"
}

SEND MESSAGE IN ROOM
PUT 
/rooms/room_beta%40sy.org/messages/bob%40sy.org/m0001?
                            access_token=abcdef0123456789
Content: { "msgtype" : "text" , "body" : "Hi everyone" }
Returns: 200 OK


Checking the event stream for this user:
GET: /events?from=START&access_token=abcdef0123456789
Returns:
{
  "chunk": 
    [
      { 
        "event_id":"e10f3d2b", 
        "type":"m.room.member",
        "room_id":"room_beta@sy.org",
        "user_id":"bob@sy.org",
        "content":{
          "membership":"join"
        }
      },
      { 
        "event_id":"1b352d32", 
        "type":"m.room.message",
        "room_id":"room_beta@sy.org",
        "msg_id":"m0001",
        "from":"bob@sy.org",
        "hs_ts":140193857,
        "content":{
          "msgtype":"m.text",
          "body":"Hi everyone"
        }
      }
    ],
  "start": "stok_9348635",
  "end": "etok_1984723"
}

Client disconnects for a while and the topic is updated in this room, 3 new 
messages arrive whilst offline, and bob is invited to another room.

GET /events?from=etok_1984723&access_token=abcdef0123456789
Returns:
{
  "chunk": 
    [
      { 
        "event_id":"feee0294", 
        "type":"m.room.topic",
        "room_id":"room_beta@sy.org",
        "from":"alice@randomhost.org",
        "content":{
          "topic":"FRIENDS ONLY",
        }
      },
      { 
        "event_id":"a028bd9e", 
        "type":"m.room.message",
        "room_id":"room_beta@sy.org",
        "msg_id":"z839409",
        "from":"alice@randomhost.org",
        "hs_ts":140195000,
        "content":{
          "msgtype":"m.text",
          "body":"Hello!!!"
        }
      },
      { 
        "event_id":"49372d9e", 
        "type":"m.room.message",
        "room_id":"room_beta@sy.org",
        "msg_id":"z839410",
        "from":"alice@randomhost.org",
        "hs_ts":140196000,
        "content":{
          "msgtype":"m.text",
          "body":"Let's go to another room"
        }
      },
      { 
        "event_id":"10abdd01", 
        "type":"m.room.message",
        "room_id":"room_beta@sy.org",
        "msg_id":"z839411",
        "from":"alice@randomhost.org",
        "hs_ts":140197000,
        "content":{
          "msgtype":"m.text",
          "body":"You're not my friend"
        }
      },
      { 
        "event_id":"0018453d", 
        "type":"m.room.member",
        "room_id":"commoners@randomhost.org",
        "from":"alice@randomhost.org",
        "user_id":"bob@sy.org",
        "content":{
          "membership":"invite"
        }
      },
    ],
  "start": "stok_0184288",
  "end": "etok_1348723"
}
