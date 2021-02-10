.. contents::

Query User Account
==================

This API returns information about a specific user account.

The api is::

    GET /_synapse/admin/v2/users/<user_id>

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

It returns a JSON body like the following:

.. code:: json

    {
        "displayname": "User",
        "threepids": [
            {
                "medium": "email",
                "address": "<user_mail_1>"
            },
            {
                "medium": "email",
                "address": "<user_mail_2>"
            }
        ],
        "avatar_url": "<avatar_url>",
        "admin": false,
        "deactivated": false,
        "password_hash": "$2b$12$p9B4GkqYdRTPGD",
        "creation_ts": 1560432506,
        "appservice_id": null,
        "consent_server_notice_sent": null,
        "consent_version": null
    }

URL parameters:

- ``user_id``: fully-qualified user id: for example, ``@user:server.com``.

Create or modify Account
========================

This API allows an administrator to create or modify a user account with a
specific ``user_id``.

This api is::

    PUT /_synapse/admin/v2/users/<user_id>

with a body of:

.. code:: json

    {
        "password": "user_password",
        "displayname": "User",
        "threepids": [
            {
                "medium": "email",
                "address": "<user_mail_1>"
            },
            {
                "medium": "email",
                "address": "<user_mail_2>"
            }
        ],
        "avatar_url": "<avatar_url>",
        "admin": false,
        "deactivated": false
    }

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

URL parameters:

- ``user_id``: fully-qualified user id: for example, ``@user:server.com``.

Body parameters:

- ``password``, optional. If provided, the user's password is updated and all
  devices are logged out.

- ``displayname``, optional, defaults to the value of ``user_id``.

- ``threepids``, optional, allows setting the third-party IDs (email, msisdn)
  belonging to a user.

- ``avatar_url``, optional, must be a
  `MXC URI <https://matrix.org/docs/spec/client_server/r0.6.0#matrix-content-mxc-uris>`_.

- ``admin``, optional, defaults to ``false``.

- ``deactivated``, optional. If unspecified, deactivation state will be left
  unchanged on existing accounts and set to ``false`` for new accounts.
  A user cannot be erased by deactivating with this API. For details on deactivating users see
  `Deactivate Account <#deactivate-account>`_.

If the user already exists then optional parameters default to the current value.

In order to re-activate an account ``deactivated`` must be set to ``false``. If
users do not login via single-sign-on, a new ``password`` must be provided.

List Accounts
=============

This API returns all local user accounts.

The api is::

    GET /_synapse/admin/v2/users?from=0&limit=10&guests=false

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

The parameter ``from`` is optional but used for pagination, denoting the
offset in the returned results. This should be treated as an opaque value and
not explicitly set to anything other than the return value of ``next_token``
from a previous call.

The parameter ``limit`` is optional but is used for pagination, denoting the
maximum number of items to return in this call. Defaults to ``100``.

The parameter ``user_id`` is optional and filters to only return users with user IDs
that contain this value. This parameter is ignored when using the ``name`` parameter.

The parameter ``name`` is optional and filters to only return users with user ID localparts
**or** displaynames that contain this value.

The parameter ``guests`` is optional and if ``false`` will **exclude** guest users.
Defaults to ``true`` to include guest users.

The parameter ``deactivated`` is optional and if ``true`` will **include** deactivated users.
Defaults to ``false`` to exclude deactivated users.

A JSON body is returned with the following shape:

.. code:: json

    {
        "users": [
            {
                "name": "<user_id1>",
                "is_guest": 0,
                "admin": 0,
                "user_type": null,
                "deactivated": 0,
                "displayname": "<User One>",
                "avatar_url": null
            }, {
                "name": "<user_id2>",
                "is_guest": 0,
                "admin": 1,
                "user_type": null,
                "deactivated": 0,
                "displayname": "<User Two>",
                "avatar_url": "<avatar_url>"
            }
        ],
        "next_token": "100",
        "total": 200
    }

To paginate, check for ``next_token`` and if present, call the endpoint again
with ``from`` set to the value of ``next_token``. This will return a new page.

If the endpoint does not return a ``next_token`` then there are no more users
to paginate through.

Query current sessions for a user
=================================

This API returns information about the active sessions for a specific user.

The api is::

    GET /_synapse/admin/v1/whois/<user_id>

and::

    GET /_matrix/client/r0/admin/whois/<userId>

See also: `Client Server API Whois
<https://matrix.org/docs/spec/client_server/r0.6.1#get-matrix-client-r0-admin-whois-userid>`_

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

It returns a JSON body like the following:

.. code:: json

    {
        "user_id": "<user_id>",
        "devices": {
            "": {
                "sessions": [
                    {
                        "connections": [
                            {
                                "ip": "1.2.3.4",
                                "last_seen": 1417222374433,
                                "user_agent": "Mozilla/5.0 ..."
                            },
                            {
                                "ip": "1.2.3.10",
                                "last_seen": 1417222374500,
                                "user_agent": "Dalvik/2.1.0 ..."
                            }
                        ]
                    }
                ]
            }
        }
    }

``last_seen`` is measured in milliseconds since the Unix epoch.

Deactivate Account
==================

This API deactivates an account. It removes active access tokens, resets the
password, and deletes third-party IDs (to prevent the user requesting a
password reset).

It can also mark the user as GDPR-erased. This means messages sent by the
user will still be visible by anyone that was in the room when these messages
were sent, but hidden from users joining the room afterwards.

The api is::

    POST /_synapse/admin/v1/deactivate/<user_id>

with a body of:

.. code:: json

    {
        "erase": true
    }

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

The erase parameter is optional and defaults to ``false``.
An empty body may be passed for backwards compatibility.

The following actions are performed when deactivating an user:

- Try to unpind 3PIDs from the identity server
- Remove all 3PIDs from the homeserver
- Delete all devices and E2EE keys
- Delete all access tokens
- Delete the password hash
- Removal from all rooms the user is a member of
- Remove the user from the user directory
- Reject all pending invites
- Remove all account validity information related to the user

The following additional actions are performed during deactivation if``erase``
is set to ``true``:

- Remove the user's display name
- Remove the user's avatar URL
- Mark the user as erased


Reset password
==============

Changes the password of another user. This will automatically log the user out of all their devices.

The api is::

    POST /_synapse/admin/v1/reset_password/<user_id>

with a body of:

.. code:: json

   {
       "new_password": "<secret>",
       "logout_devices": true
   }

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

The parameter ``new_password`` is required.
The parameter ``logout_devices`` is optional and defaults to ``true``.

Get whether a user is a server administrator or not
===================================================


The api is::

    GET /_synapse/admin/v1/users/<user_id>/admin

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

A response body like the following is returned:

.. code:: json

    {
        "admin": true
    }


Change whether a user is a server administrator or not
======================================================

Note that you cannot demote yourself.

The api is::

    PUT /_synapse/admin/v1/users/<user_id>/admin

with a body of:

.. code:: json

    {
        "admin": true
    }

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.


List room memberships of an user
================================
Gets a list of all ``room_id`` that a specific ``user_id`` is member.

The API is::

  GET /_synapse/admin/v1/users/<user_id>/joined_rooms

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

A response body like the following is returned:

.. code:: json

    {
        "joined_rooms": [
            "!DuGcnbhHGaSZQoNQR:matrix.org",
            "!ZtSaPCawyWtxfWiIy:matrix.org"
        ],
        "total": 2
    }

The server returns the list of rooms of which the user and the server
are member. If the user is local, all the rooms of which the user is
member are returned.

**Parameters**

The following parameters should be set in the URL:

- ``user_id`` - fully qualified: for example, ``@user:server.com``.

**Response**

The following fields are returned in the JSON response body:

- ``joined_rooms`` - An array of ``room_id``.
- ``total`` - Number of rooms.


List media of an user
================================
Gets a list of all local media that a specific ``user_id`` has created.
The response is ordered by creation date descending and media ID descending.
The newest media is on top.

The API is::

  GET /_synapse/admin/v1/users/<user_id>/media

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

A response body like the following is returned:

.. code:: json

    {
      "media": [
        {
          "created_ts": 100400,
          "last_access_ts": null,
          "media_id": "qXhyRzulkwLsNHTbpHreuEgo",
          "media_length": 67,
          "media_type": "image/png",
          "quarantined_by": null,
          "safe_from_quarantine": false,
          "upload_name": "test1.png"
        },
        {
          "created_ts": 200400,
          "last_access_ts": null,
          "media_id": "FHfiSnzoINDatrXHQIXBtahw",
          "media_length": 67,
          "media_type": "image/png",
          "quarantined_by": null,
          "safe_from_quarantine": false,
          "upload_name": "test2.png"
        }
      ],
      "next_token": 3,
      "total": 2
    }

To paginate, check for ``next_token`` and if present, call the endpoint again
with ``from`` set to the value of ``next_token``. This will return a new page.

If the endpoint does not return a ``next_token`` then there are no more
reports to paginate through.

**Parameters**

The following parameters should be set in the URL:

- ``user_id`` - string - fully qualified: for example, ``@user:server.com``.
- ``limit``: string representing a positive integer - Is optional but is used for pagination,
  denoting the maximum number of items to return in this call. Defaults to ``100``.
- ``from``: string representing a positive integer - Is optional but used for pagination,
  denoting the offset in the returned results. This should be treated as an opaque value and
  not explicitly set to anything other than the return value of ``next_token`` from a previous call.
  Defaults to ``0``.

**Response**

The following fields are returned in the JSON response body:

- ``media`` - An array of objects, each containing information about a media.
  Media objects contain the following fields:

  - ``created_ts`` - integer - Timestamp when the content was uploaded in ms.
  - ``last_access_ts`` - integer - Timestamp when the content was last accessed in ms.
  - ``media_id`` - string - The id used to refer to the media.
  - ``media_length`` - integer - Length of the media in bytes.
  - ``media_type`` - string - The MIME-type of the media.
  - ``quarantined_by`` - string - The user ID that initiated the quarantine request
    for this media.

  - ``safe_from_quarantine`` - bool - Status if this media is safe from quarantining.
  - ``upload_name`` - string - The name the media was uploaded with.

- ``next_token``: integer - Indication for pagination. See above.
- ``total`` - integer - Total number of media.

Login as a user
===============

Get an access token that can be used to authenticate as that user. Useful for
when admins wish to do actions on behalf of a user.

The API is::

    POST /_synapse/admin/v1/users/<user_id>/login
    {}

An optional ``valid_until_ms`` field can be specified in the request body as an
integer timestamp that specifies when the token should expire. By default tokens
do not expire.

A response body like the following is returned:

.. code:: json

    {
        "access_token": "<opaque_access_token_string>"
    }


This API does *not* generate a new device for the user, and so will not appear
their ``/devices`` list, and in general the target user should not be able to
tell they have been logged in as.

To expire the token call the standard ``/logout`` API with the token.

Note: The token will expire if the *admin* user calls ``/logout/all`` from any
of their devices, but the token will *not* expire if the target user does the
same.


User devices
============

List all devices
----------------
Gets information about all devices for a specific ``user_id``.

The API is::

  GET /_synapse/admin/v2/users/<user_id>/devices

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

A response body like the following is returned:

.. code:: json

    {
      "devices": [
        {
          "device_id": "QBUAZIFURK",
          "display_name": "android",
          "last_seen_ip": "1.2.3.4",
          "last_seen_ts": 1474491775024,
          "user_id": "<user_id>"
        },
        {
          "device_id": "AUIECTSRND",
          "display_name": "ios",
          "last_seen_ip": "1.2.3.5",
          "last_seen_ts": 1474491775025,
          "user_id": "<user_id>"
        }
      ],
      "total": 2
    }

**Parameters**

The following parameters should be set in the URL:

- ``user_id`` - fully qualified: for example, ``@user:server.com``.

**Response**

The following fields are returned in the JSON response body:

- ``devices`` - An array of objects, each containing information about a device.
  Device objects contain the following fields:

  - ``device_id`` - Identifier of device.
  - ``display_name`` - Display name set by the user for this device.
    Absent if no name has been set.
  - ``last_seen_ip`` - The IP address where this device was last seen.
    (May be a few minutes out of date, for efficiency reasons).
  - ``last_seen_ts`` - The timestamp (in milliseconds since the unix epoch) when this
    devices was last seen. (May be a few minutes out of date, for efficiency reasons).
  - ``user_id`` - Owner of  device.

- ``total`` - Total number of user's devices.

Delete multiple devices
------------------
Deletes the given devices for a specific ``user_id``, and invalidates
any access token associated with them.

The API is::

    POST /_synapse/admin/v2/users/<user_id>/delete_devices

    {
      "devices": [
        "QBUAZIFURK",
        "AUIECTSRND"
      ],
    }

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

An empty JSON dict is returned.

**Parameters**

The following parameters should be set in the URL:

- ``user_id`` - fully qualified: for example, ``@user:server.com``.

The following fields are required in the JSON request body:

- ``devices`` - The list of device IDs to delete.

Show a device
---------------
Gets information on a single device, by ``device_id`` for a specific ``user_id``.

The API is::

    GET /_synapse/admin/v2/users/<user_id>/devices/<device_id>

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

A response body like the following is returned:

.. code:: json

    {
      "device_id": "<device_id>",
      "display_name": "android",
      "last_seen_ip": "1.2.3.4",
      "last_seen_ts": 1474491775024,
      "user_id": "<user_id>"
    }

**Parameters**

The following parameters should be set in the URL:

- ``user_id`` - fully qualified: for example, ``@user:server.com``.
- ``device_id`` - The device to retrieve.

**Response**

The following fields are returned in the JSON response body:

- ``device_id`` - Identifier of device.
- ``display_name`` - Display name set by the user for this device.
  Absent if no name has been set.
- ``last_seen_ip`` - The IP address where this device was last seen.
  (May be a few minutes out of date, for efficiency reasons).
- ``last_seen_ts`` - The timestamp (in milliseconds since the unix epoch) when this
  devices was last seen. (May be a few minutes out of date, for efficiency reasons).
- ``user_id`` - Owner of  device.

Update a device
---------------
Updates the metadata on the given ``device_id`` for a specific ``user_id``.

The API is::

    PUT /_synapse/admin/v2/users/<user_id>/devices/<device_id>

    {
      "display_name": "My other phone"
    }

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

An empty JSON dict is returned.

**Parameters**

The following parameters should be set in the URL:

- ``user_id`` - fully qualified: for example, ``@user:server.com``.
- ``device_id`` - The device to update.

The following fields are required in the JSON request body:

- ``display_name`` - The new display name for this device. If not given,
  the display name is unchanged.

Delete a device
---------------
Deletes the given ``device_id`` for a specific ``user_id``,
and invalidates any access token associated with it.

The API is::

    DELETE /_synapse/admin/v2/users/<user_id>/devices/<device_id>

    {}

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

An empty JSON dict is returned.

**Parameters**

The following parameters should be set in the URL:

- ``user_id`` - fully qualified: for example, ``@user:server.com``.
- ``device_id`` - The device to delete.

List all pushers
================
Gets information about all pushers for a specific ``user_id``.

The API is::

  GET /_synapse/admin/v1/users/<user_id>/pushers

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

A response body like the following is returned:

.. code:: json

    {
      "pushers": [
        {
          "app_display_name":"HTTP Push Notifications",
          "app_id":"m.http",
          "data": {
            "url":"example.com"
          },
          "device_display_name":"pushy push",
          "kind":"http",
          "lang":"None",
          "profile_tag":"",
          "pushkey":"a@example.com"
        }
      ],
      "total": 1
    }

**Parameters**

The following parameters should be set in the URL:

- ``user_id`` - fully qualified: for example, ``@user:server.com``.

**Response**

The following fields are returned in the JSON response body:

- ``pushers`` - An array containing the current pushers for the user

  - ``app_display_name`` - string - A string that will allow the user to identify
    what application owns this pusher.

  - ``app_id`` - string - This is a reverse-DNS style identifier for the application.
    Max length, 64 chars.

  - ``data`` - A dictionary of information for the pusher implementation itself.

    - ``url`` - string - Required if ``kind`` is ``http``. The URL to use to send
      notifications to.

    - ``format`` - string - The format to use when sending notifications to the
      Push Gateway.

  - ``device_display_name`` - string -  A string that will allow the user to identify
    what device owns this pusher.

  - ``profile_tag`` - string - This string determines which set of device specific rules
    this pusher executes.

  - ``kind`` - string -  The kind of pusher. "http" is a pusher that sends HTTP pokes.
  - ``lang`` - string - The preferred language for receiving notifications
    (e.g. 'en' or 'en-US')

  - ``profile_tag`` - string - This string determines which set of device specific rules
    this pusher executes.

  - ``pushkey`` - string - This is a unique identifier for this pusher.
    Max length, 512 bytes.

- ``total`` - integer - Number of pushers.

See also `Client-Server API Spec <https://matrix.org/docs/spec/client_server/latest#get-matrix-client-r0-pushers>`_

Shadow-banning users
====================

Shadow-banning is a useful tool for moderating malicious or egregiously abusive users.
A shadow-banned users receives successful responses to their client-server API requests,
but the events are not propagated into rooms. This can be an effective tool as it
(hopefully) takes longer for the user to realise they are being moderated before
pivoting to another account.

Shadow-banning a user should be used as a tool of last resort and may lead to confusing
or broken behaviour for the client. A shadow-banned user will not receive any
notification and it is generally more appropriate to ban or kick abusive users.
A shadow-banned user will be unable to contact anyone on the server.

The API is::

  POST /_synapse/admin/v1/users/<user_id>/shadow_ban

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

An empty JSON dict is returned.

**Parameters**

The following parameters should be set in the URL:

- ``user_id`` - The fully qualified MXID: for example, ``@user:server.com``. The user must
  be local.
