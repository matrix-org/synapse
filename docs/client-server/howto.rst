.. TODO kegan
  Room config (specifically: message history,
  public rooms). /register seems super simplistic compared to /login, maybe it
  would be better if /register used the same technique as /login? /register should
  be "user" not "user_id".


How to use the client-server API
================================

This guide focuses on how the client-server APIs *provided by the reference 
home server* can be used. Since this is specific to a home server 
implementation, there may be variations in relation to registering/logging in
which are not covered in extensive detail in this guide.

If you haven't already, get a home server up and running on 
``http://localhost:8008``.


Accounts
========
Before you can send and receive messages, you must **register** for an account. 
If you already have an account, you must **login** into it.

`Try out the fiddle`__

.. __: http://jsfiddle.net/gh/get/jquery/1.8.3/matrix-org/synapse/tree/master/jsfiddles/register_login

Registration
------------
The aim of registration is to get a user ID and access token which you will need
when accessing other APIs::

    curl -XPOST -d '{"user":"example", "password":"wordpass", "type":"m.login.password"}' "http://localhost:8008/_matrix/client/api/v1/register"

    {
        "access_token": "QGV4YW1wbGU6bG9jYWxob3N0.AqdSzFmFYrLrTmteXc", 
        "home_server": "localhost", 
        "user_id": "@example:localhost"
    }

NB: If a ``user`` is not specified, one will be randomly generated for you. 
If you do not specify a ``password``, you will be unable to login to the account
if you forget the ``access_token``.

Implementation note: The matrix specification does not enforce how users 
register with a server. It just specifies the URL path and absolute minimum 
keys. The reference home server uses a username/password to authenticate user,
but other home servers may use different methods. This is why you need to
specify the ``type`` of method.

Login
-----
The aim when logging in is to get an access token for your existing user ID::

    curl -XGET "http://localhost:8008/_matrix/client/api/v1/login"

    {
        "flows": [
            {
                "type": "m.login.password"
            }
        ]
    }

    curl -XPOST -d '{"type":"m.login.password", "user":"example", "password":"wordpass"}' "http://localhost:8008/_matrix/client/api/v1/login"

    {
        "access_token": "QGV4YW1wbGU6bG9jYWxob3N0.vRDLTgxefmKWQEtgGd", 
        "home_server": "localhost", 
        "user_id": "@example:localhost"
    }
    
Implementation note: Different home servers may implement different methods for 
logging in to an existing account. In order to check that you know how to login 
to this home server, you must perform a ``GET`` first and make sure you 
recognise the login type. If you do not know how to login, you can 
``GET /login/fallback`` which will return a basic webpage which you can use to 
login. The reference home server implementation support username/password login,
but other home servers may support different login methods (e.g. OAuth2).


Communicating
=============

In order to communicate with another user, you must **create a room** with that 
user and **send a message** to that room. 

`Try out the fiddle`__

.. __: http://jsfiddle.net/gh/get/jquery/1.8.3/matrix-org/synapse/tree/master/jsfiddles/create_room_send_msg

Creating a room
---------------
If you want to send a message to someone, you have to be in a room with them. To
create a room::

    curl -XPOST -d '{"room_alias_name":"tutorial"}' "http://localhost:8008/_matrix/client/api/v1/createRoom?access_token=YOUR_ACCESS_TOKEN"

    {
        "room_alias": "#tutorial:localhost", 
        "room_id": "!CvcvRuDYDzTOzfKKgh:localhost"
    }
    
The "room alias" is a human-readable string which can be shared with other users
so they can join a room, rather than the room ID which is a randomly generated
string. You can have multiple room aliases per room.

.. TODO(kegan)
  How to add/remove aliases from an existing room.
    

Sending messages
----------------
You can now send messages to this room::

    curl -XPOST -d '{"msgtype":"m.text", "body":"hello"}' "http://localhost:8008/_matrix/client/api/v1/rooms/%21CvcvRuDYDzTOzfKKgh%3Alocalhost/send/m.room.message?access_token=YOUR_ACCESS_TOKEN"
    
    {
        "event_id": "YUwRidLecu"
    }
    
The event ID returned is a unique ID which identifies this message.
    
NB: There are no limitations to the types of messages which can be exchanged.
The only requirement is that ``"msgtype"`` is specified. The Matrix 
specification outlines the following standard types: ``m.text``, ``m.image``,
``m.audio``, ``m.video``, ``m.location``, ``m.emote``. See the specification for
more information on these types.

Users and rooms
===============

Each room can be configured to allow or disallow certain rules. In particular,
these rules may specify if you require an **invitation** from someone already in
the room in order to **join the room**. In addition, you may also be able to 
join a room **via a room alias** if one was set up.

`Try out the fiddle`__

.. __: http://jsfiddle.net/gh/get/jquery/1.8.3/matrix-org/synapse/tree/master/jsfiddles/room_memberships

Inviting a user to a room
-------------------------
You can directly invite a user to a room like so::

    curl -XPOST -d '{"user_id":"@myfriend:localhost"}' "http://localhost:8008/_matrix/client/api/v1/rooms/%21CvcvRuDYDzTOzfKKgh%3Alocalhost/invite?access_token=YOUR_ACCESS_TOKEN"
    
This informs ``@myfriend:localhost`` of the room ID 
``!CvcvRuDYDzTOzfKKgh:localhost`` and allows them to join the room.

Joining a room via an invite
----------------------------
If you receive an invite, you can join the room::

    curl -XPOST -d '{}' "http://localhost:8008/_matrix/client/api/v1/rooms/%21CvcvRuDYDzTOzfKKgh%3Alocalhost/join?access_token=YOUR_ACCESS_TOKEN"
    
NB: Only the person invited (``@myfriend:localhost``) can change the membership
state to ``"join"``. Repeatedly joining a room does nothing.

Joining a room via an alias
---------------------------
Alternatively, if you know the room alias for this room and the room config 
allows it, you can directly join a room via the alias::

    curl -XPOST -d '{}' "http://localhost:8008/_matrix/client/api/v1/join/%23tutorial%3Alocalhost?access_token=YOUR_ACCESS_TOKEN"
    
    {
        "room_id": "!CvcvRuDYDzTOzfKKgh:localhost"
    }
    
You will need to use the room ID when sending messages, not the room alias.

NB: If the room is configured to be an invite-only room, you will still require
an invite in order to join the room even though you know the room alias. As a
result, it is more common to see a room alias in relation to a public room, 
which do not require invitations.

Getting events
==============
An event is some interesting piece of data that a client may be interested in. 
It can be a message in a room, a room invite, etc. There are many different ways
of getting events, depending on what the client already knows.

`Try out the fiddle`__

.. __: http://jsfiddle.net/gh/get/jquery/1.8.3/matrix-org/synapse/tree/master/jsfiddles/event_stream

Getting all state
-----------------
If the client doesn't know any information on the rooms the user is 
invited/joined on, they can get all the user's state for all rooms::

    curl -XGET "http://localhost:8008/_matrix/client/api/v1/initialSync?access_token=YOUR_ACCESS_TOKEN"
    
    {
        "end": "s39_18_0", 
        "presence": [
            {
                "content": {
                    "last_active_ago": 1061436, 
                    "user_id": "@example:localhost"
                }, 
                "type": "m.presence"
            }
        ], 
        "rooms": [
            {
                "membership": "join", 
                "messages": {
                    "chunk": [
                        {
                            "content": {
                                "@example:localhost": 10, 
                                "default": 0
                            }, 
                            "event_id": "wAumPSTsWF", 
                            "required_power_level": 10, 
                            "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                            "state_key": "", 
                            "ts": 1409665585188, 
                            "type": "m.room.power_levels", 
                            "user_id": "@example:localhost"
                        }, 
                        {
                            "content": {
                                "join_rule": "public"
                            }, 
                            "event_id": "jrLVqKHKiI", 
                            "required_power_level": 10, 
                            "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                            "state_key": "", 
                            "ts": 1409665585188, 
                            "type": "m.room.join_rules", 
                            "user_id": "@example:localhost"
                        }, 
                        {
                            "content": {
                                "level": 10
                            }, 
                            "event_id": "WpmTgsNWUZ", 
                            "required_power_level": 10, 
                            "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                            "state_key": "", 
                            "ts": 1409665585188, 
                            "type": "m.room.add_state_level", 
                            "user_id": "@example:localhost"
                        }, 
                        {
                            "content": {
                                "level": 0
                            }, 
                            "event_id": "qUMBJyKsTQ", 
                            "required_power_level": 10, 
                            "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                            "state_key": "", 
                            "ts": 1409665585188, 
                            "type": "m.room.send_event_level", 
                            "user_id": "@example:localhost"
                        }, 
                        {
                            "content": {
                                "ban_level": 5, 
                                "kick_level": 5
                            }, 
                            "event_id": "YAaDmKvoUW", 
                            "required_power_level": 10, 
                            "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                            "state_key": "", 
                            "ts": 1409665585188, 
                            "type": "m.room.ops_levels", 
                            "user_id": "@example:localhost"
                        }, 
                        {
                            "content": {
                                "avatar_url": null, 
                                "displayname": null, 
                                "membership": "join"
                            }, 
                            "event_id": "RJbPMtCutf", 
                            "membership": "join", 
                            "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                            "state_key": "@example:localhost", 
                            "ts": 1409665586730, 
                            "type": "m.room.member", 
                            "user_id": "@example:localhost"
                        }, 
                        {
                            "content": {
                                "body": "hello", 
                                "hsob_ts": 1409665660439, 
                                "msgtype": "m.text"
                            }, 
                            "event_id": "YUwRidLecu", 
                            "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                            "ts": 1409665660439, 
                            "type": "m.room.message", 
                            "user_id": "@example:localhost"
                        }, 
                        {
                            "content": {
                                "membership": "invite"
                            }, 
                            "event_id": "YjNuBKnPsb", 
                            "membership": "invite", 
                            "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                            "state_key": "@myfriend:localhost", 
                            "ts": 1409666426819, 
                            "type": "m.room.member", 
                            "user_id": "@example:localhost"
                        }, 
                        {
                            "content": {
                                "avatar_url": null, 
                                "displayname": null, 
                                "membership": "join", 
                                "prev": "join"
                            }, 
                            "event_id": "KWwdDjNZnm", 
                            "membership": "join", 
                            "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                            "state_key": "@example:localhost", 
                            "ts": 1409666551582, 
                            "type": "m.room.member", 
                            "user_id": "@example:localhost"
                        }, 
                        {
                            "content": {
                                "avatar_url": null, 
                                "displayname": null, 
                                "membership": "join"
                            }, 
                            "event_id": "JFLVteSvQc", 
                            "membership": "join", 
                            "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                            "state_key": "@example:localhost", 
                            "ts": 1409666587265, 
                            "type": "m.room.member", 
                            "user_id": "@example:localhost"
                        }
                    ], 
                    "end": "s39_18_0", 
                    "start": "t1-11_18_0"
                }, 
                "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                "state": [
                    {
                        "content": {
                            "creator": "@example:localhost"
                        }, 
                        "event_id": "dMUoqVTZca", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.create", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "@example:localhost": 10, 
                            "default": 0
                        }, 
                        "event_id": "wAumPSTsWF", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.power_levels", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "join_rule": "public"
                        }, 
                        "event_id": "jrLVqKHKiI", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.join_rules", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "level": 10
                        }, 
                        "event_id": "WpmTgsNWUZ", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.add_state_level", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "level": 0
                        }, 
                        "event_id": "qUMBJyKsTQ", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.send_event_level", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "ban_level": 5, 
                            "kick_level": 5
                        }, 
                        "event_id": "YAaDmKvoUW", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.ops_levels", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "membership": "invite"
                        }, 
                        "event_id": "YjNuBKnPsb", 
                        "membership": "invite", 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "@myfriend:localhost", 
                        "ts": 1409666426819, 
                        "type": "m.room.member", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "avatar_url": null, 
                            "displayname": null, 
                            "membership": "join"
                        }, 
                        "event_id": "JFLVteSvQc", 
                        "membership": "join", 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "@example:localhost", 
                        "ts": 1409666587265, 
                        "type": "m.room.member", 
                        "user_id": "@example:localhost"
                    }
                ]
            }
        ]
    }
    
This returns all the room information the user is invited/joined on, as well as
all of the presences relevant for these rooms. This can be a LOT of data. You
may just want the most recent event for each room. This can be achieved by 
applying query parameters to ``limit`` this request::

    curl -XGET "http://localhost:8008/_matrix/client/api/v1/initialSync?limit=1&access_token=YOUR_ACCESS_TOKEN"
    
    {
        "end": "s39_18_0", 
        "presence": [
            {
                "content": {
                    "last_active_ago": 1279484, 
                    "user_id": "@example:localhost"
                }, 
                "type": "m.presence"
            }
        ], 
        "rooms": [
            {
                "membership": "join", 
                "messages": {
                    "chunk": [
                        {
                            "content": {
                                "avatar_url": null, 
                                "displayname": null, 
                                "membership": "join"
                            }, 
                            "event_id": "JFLVteSvQc", 
                            "membership": "join", 
                            "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                            "state_key": "@example:localhost", 
                            "ts": 1409666587265, 
                            "type": "m.room.member", 
                            "user_id": "@example:localhost"
                        }
                    ], 
                    "end": "s39_18_0", 
                    "start": "t10-30_18_0"
                }, 
                "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                "state": [
                    {
                        "content": {
                            "creator": "@example:localhost"
                        }, 
                        "event_id": "dMUoqVTZca", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.create", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "@example:localhost": 10, 
                            "default": 0
                        }, 
                        "event_id": "wAumPSTsWF", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.power_levels", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "join_rule": "public"
                        }, 
                        "event_id": "jrLVqKHKiI", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.join_rules", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "level": 10
                        }, 
                        "event_id": "WpmTgsNWUZ", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.add_state_level", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "level": 0
                        }, 
                        "event_id": "qUMBJyKsTQ", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.send_event_level", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "ban_level": 5, 
                            "kick_level": 5
                        }, 
                        "event_id": "YAaDmKvoUW", 
                        "required_power_level": 10, 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "", 
                        "ts": 1409665585188, 
                        "type": "m.room.ops_levels", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "membership": "invite"
                        }, 
                        "event_id": "YjNuBKnPsb", 
                        "membership": "invite", 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "@myfriend:localhost", 
                        "ts": 1409666426819, 
                        "type": "m.room.member", 
                        "user_id": "@example:localhost"
                    }, 
                    {
                        "content": {
                            "avatar_url": null, 
                            "displayname": null, 
                            "membership": "join"
                        }, 
                        "event_id": "JFLVteSvQc", 
                        "membership": "join", 
                        "room_id": "!MkDbyRqnvTYnoxjLYx:localhost", 
                        "state_key": "@example:localhost", 
                        "ts": 1409666587265, 
                        "type": "m.room.member", 
                        "user_id": "@example:localhost"
                    }
                ]
            }
        ]
    }

Getting live state
------------------
Once you know which rooms the client has previously interacted with, you need to
listen for incoming events. This can be done like so::

    curl -XGET "http://localhost:8008/_matrix/client/api/v1/events?access_token=YOUR_ACCESS_TOKEN"
    
    {
        "chunk": [], 
        "end": "s39_18_0", 
        "start": "s39_18_0"
    }
    
This will block waiting for an incoming event, timing out after several seconds.
Even if there are no new events (as in the example above), there will be some
pagination stream response keys. The client should make subsequent requests 
using the value of the ``"end"`` key (in this case ``s39_18_0``) as the ``from`` 
query parameter e.g. ``http://localhost:8008/_matrix/client/api/v1/events?access
_token=YOUR_ACCESS_TOKEN&from=s39_18_0``. This value should be stored so when the 
client reopens your app after a period of inactivity, you can resume from where 
you got up to in the event stream. If it has been a long period of inactivity, 
there may be LOTS of events waiting for the user. In this case, you may wish to 
get all state instead and then resume getting live state from a newer end token.

NB: The timeout can be changed by adding a ``timeout`` query parameter, which is
in milliseconds. A timeout of 0 will not block.


Example application
-------------------
The following example demonstrates registration and login, live event streaming,
creating and joining rooms, sending messages, getting member lists and getting 
historical messages for a room. This covers most functionality of a messaging
application.

`Try out the fiddle`__

.. __: http://jsfiddle.net/gh/get/jquery/1.8.3/matrix-org/synapse/tree/master/jsfiddles/example_app
