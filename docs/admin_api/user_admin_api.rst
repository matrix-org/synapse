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
        "deactivated": false
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
                "password_hash": "<password_hash1>",
                "is_guest": 0,
                "admin": 0,
                "user_type": null,
                "deactivated": 0,
                "displayname": "<User One>",
                "avatar_url": null
            }, {
                "name": "<user_id2>",
                "password_hash": "<password_hash2>",
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


Reset password
==============

Changes the password of another user. This will automatically log the user out of all their devices.

The api is::

    POST /_synapse/admin/v1/reset_password/<user_id>

with a body of:

.. code:: json

   {
       "new_password": "<secret>",
       "logout_devices": true,
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

**Parameters**

The following parameters should be set in the URL:

- ``user_id`` - fully qualified: for example, ``@user:server.com``.

**Response**

The following fields are returned in the JSON response body:

- ``joined_rooms`` - An array of ``room_id``.
- ``total`` - Number of rooms.


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
      ]
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
