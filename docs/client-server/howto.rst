How to use the client-server API
================================

If you haven't already, get a home server up and running on localhost:8080.


Accounts
========
Before you can send and receive messages, you must register for an account. If
you already have an account, you must login into it.

Registration
------------
The aim of registration is to get a user ID and access token which you will need
when accessing other APIs.

    curl -XPOST -d '{"user_id":"example", "password":"wordpass"}' "http://localhost:8080/matrix/client/api/v1/register"

    {
        "access_token": "QGV4YW1wbGU6bG9jYWxob3N0.AqdSzFmFYrLrTmteXc", 
        "home_server": "localhost", 
        "user_id": "@example:localhost"
    }

NB: If a user ID is not specified, one will be randomly generated for you. If
you do not specify a password, you will be unable to login to the account if you
forget the access token.

Login
-----
The aim of login is to get an access token for your existing user ID.

    curl -XGET "http://localhost:8080/matrix/client/api/v1/login"

    {
        "type": "m.login.password"
    }

    curl -XPOST -d '{"type":"m.login.password", "user":"example", "password":"wordpass"}' "http://localhost:8080/matrix/client/api/v1/login"

    {
        "access_token": "QGV4YW1wbGU6bG9jYWxob3N0.vRDLTgxefmKWQEtgGd", 
        "home_server": "localhost", 
        "user_id": "@example:localhost"
    }
    
NB: Different home servers may implement different methods for logging in to an
existing account. In order to check that you know how to login to this home 
server, you must perform a GET first and make sure you recognise the type. If 
you do not know how to login, you can GET /login/fallback which will return a 
basic webpage which you can use to login.


Making rooms and sending messages
=================================

Creating a room
---------------
If you want to send a message to someone, you have to be in a room with them. To
create a room:

    curl -XPOST -d '{"room_alias_name":"tutorial"}' "http://localhost:8080/matrix/client/api/v1/rooms?access_token=QGV4YW1wbGU6bG9jYWxob3N0.vRDLTgxefmKWQEtgGd"

    {
        "room_alias": "#tutorial:localhost", 
        "room_id": "!CvcvRuDYDzTOzfKKgh:localhost"
    }
    
The "room alias" is a human-readable string which can be shared with other users
so they can join a room, rather than the room ID which is a randomly generated
string. You can have multiple room aliases per room.

TODO(kegan): How to add/remove aliases from an existing room.
    

Sending messages
----------------
You can now send messages to this room:

    curl -XPUT -d '{"msgtype":"m.text", "body":"hello"}' "http://localhost:8080/matrix/client/api/v1/rooms/%21CvcvRuDYDzTOzfKKgh:localhost/messages/%40example%3Alocalhost/msgid1?access_token=QGV4YW1wbGU6bG9jYWxob3N0.vRDLTgxefmKWQEtgGd"
    
NB: There are no limitations to the types of messages which can be exchanged.
The only requirement is that 'msgtype' is specified.


Inviting and joining rooms
==========================

Inviting a user to a room
-------------------------
You can directly invite a user to a room like so:

    curl -XPUT -d '{"membership":"invite"}' "http://localhost:8080/matrix/client/api/v1/rooms/%21CvcvRuDYDzTOzfKKgh:localhost/members/%40myfriend%3Alocalhost/state?access_token=QGV4YW1wbGU6bG9jYWxob3N0.vRDLTgxefmKWQEtgGd"
    
This informs @myfriend:localhost of the room ID !CvcvRuDYDzTOzfKKgh:localhost
and allows them to join the room.

Joining a room via an invite
----------------------------
If you receive an invite, you can join the room by changing the membership to
join:

    curl -XPUT -d '{"membership":"join"}' "http://localhost:8080/matrix/client/api/v1/rooms/%21CvcvRuDYDzTOzfKKgh:localhost/members/%40myfriend%3Alocalhost/state?access_token=QG15ZnJpZW5kOmxvY2FsaG9zdA...XKuGdVsovHmwMyDDvK"
    
NB: Only the person invited (@myfriend:localhost) can change the membership
state to 'join'.

Joining a room via an alias
---------------------------
Alternatively, if you know the room alias for this room and the room config 
allows it, you can directly join a room via the alias:

    curl -XPUT -d '{}' "http://localhost:8080/matrix/client/api/v1/join/%23tutorial%3Alocalhost?access_token=QG15ZnJpZW5kOmxvY2FsaG9zdA...XKuGdVsovHmwMyDDvK"
    
    {
        "room_id": "!CvcvRuDYDzTOzfKKgh:localhost"
    }
    
You will need to use the room ID when sending messages, not the room alias.

Getting events
==============
An event is some interesting piece of data that a client may be interested in. 
It can be a message in a room, a room invite, etc. There are many different ways
of getting events, depending on what state the client is in.

Getting all state
-----------------
If the client doesn't know any information on the rooms the user is 
invited/joined on, you can get all your state for all your rooms like so:

    curl -XGET "http://localhost:8080/matrix/client/api/v1/im/sync?access_token=QG15ZnJpZW5kOmxvY2FsaG9zdA...XKuGdVsovHmwMyDDvK"
    
    [
        {
            "membership": "join", 
            "messages": {
                "chunk": [
                    {
                        "content": {
                            "body": "@example:localhost joined the room.", 
                            "hsob_ts": 1408444664249, 
                            "membership": "join", 
                            "membership_source": "@example:localhost", 
                            "membership_target": "@example:localhost", 
                            "msgtype": "m.text"
                        }, 
                        "event_id": "lZjmmlrEvo", 
                        "msg_id": "m1408444664249", 
                        "room_id": "!CvcvRuDYDzTOzfKKgh:localhost", 
                        "type": "m.room.message", 
                        "user_id": "_homeserver_"
                    }, 
                    {
                        "content": {
                            "body": "hello", 
                            "hsob_ts": 1408445405672, 
                            "msgtype": "m.text"
                        }, 
                        "event_id": "BiBJqamISg", 
                        "msg_id": "msgid1", 
                        "room_id": "!CvcvRuDYDzTOzfKKgh:localhost", 
                        "type": "m.room.message", 
                        "user_id": "@example:localhost"
                    }, 
                    [...]
                    {
                        "content": {
                            "body": "@myfriend:localhost joined the room.", 
                            "hsob_ts": 1408446501661, 
                            "membership": "join", 
                            "membership_source": "@myfriend:localhost", 
                            "membership_target": "@myfriend:localhost", 
                            "msgtype": "m.text"
                        }, 
                        "event_id": "IMmXbOzFAa", 
                        "msg_id": "m1408446501661", 
                        "room_id": "!CvcvRuDYDzTOzfKKgh:localhost", 
                        "type": "m.room.message", 
                        "user_id": "_homeserver_"
                    }
                ], 
                "end": "20", 
                "start": "0"
            }, 
            "room_id": "!CvcvRuDYDzTOzfKKgh:localhost"
        }
    ]
    
This returns all the room IDs of rooms you are invited/joined on, as well as all
of the messages and feedback for these rooms. This can be a LOT of data. You may
just want the most recent message for each room. This can be done by applying
pagination stream parameters to this request:

    curl -XGET "http://localhost:8080/matrix/client/api/v1/im/sync?access_token=QG15ZnJpZW5kOmxvY2FsaG9zdA...XKuGdVsovHmwMyDDvK&from=END&to=START&limit=1"
    
    [
        {
            "membership": "join", 
            "messages": {
                "chunk": [
                    {
                        "content": {
                            "body": "@myfriend:localhost joined the room.", 
                            "hsob_ts": 1408446501661, 
                            "membership": "join", 
                            "membership_source": "@myfriend:localhost", 
                            "membership_target": "@myfriend:localhost", 
                            "msgtype": "m.text"
                        }, 
                        "event_id": "IMmXbOzFAa", 
                        "msg_id": "m1408446501661", 
                        "room_id": "!CvcvRuDYDzTOzfKKgh:localhost", 
                        "type": "m.room.message", 
                        "user_id": "_homeserver_"
                    }
                ], 
                "end": "20", 
                "start": "21"
            }, 
            "room_id": "!CvcvRuDYDzTOzfKKgh:localhost"
        }
    ]

Getting live state
------------------
Once you know which rooms the client has previously interacted with, you need to
listen for incoming events. This can be done like so:

    curl -XGET "http://localhost:8080/matrix/client/api/v1/events?access_token=QG15ZnJpZW5kOmxvY2FsaG9zdA...XKuGdVsovHmwMyDDvK&from=END"
    
    {
        "chunk": [], 
        "end": "215", 
        "start": "215"
    }
    
This will block waiting for an incoming event, timing out after several seconds.
A client should repeatedly make requests with the "from" query parameter with
the value of "end" (in this case "215").

NB: The timeout can be changed by adding a "timeout" query parameter, which is
in milliseconds. A timeout of 0 will not block.

