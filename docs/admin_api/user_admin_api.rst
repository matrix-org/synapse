Create or modify Account
========================

This API allows an administrator to create or modify a user account with a
specific ``user_id``. Be aware that ``user_id`` is fully qualified: for example,
``@user:server.com``.

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

including an ``access_token`` of a server admin.

Parameters:

- ``password``, optional, if provided, the user's password is updated and all
  devices are logged out
  
- ``displayname``, optional, defaults to the value of ``user_id``

- ``threepids``, optional, allows setting the third-party IDs (email, msisdn)
  belonging to a user

- ``avatar_url``, optional, must be a [MXC
URI](https://matrix.org/docs/spec/client_server/r0.6.0#matrix-content-mxc-uris)

- ``admin``, optional, defaults to ``false``

- ``deactivated``, optional, defaults to ``false``

If the user already exists then optional parameters default to the current value.

List Accounts
=============

This API returns all local user accounts.

The api is::

    GET /_synapse/admin/v2/users?from=0&limit=10&guests=false

including an ``access_token`` of a server admin.

The parameter ``from`` is optional but used for pagination, denoting the
offset in the returned results. This should be treated as an opaque value and
not explicitly set to anything other than the return value of ``next_token``
from a previous call.

The parameter ``limit`` is optional but is used for pagination, denoting the
maximum number of items to return in this call. Defaults to ``100``.

The parameter ``user_id`` is optional and filters to only users with user IDs
that contain this value.

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

Query Account
=============

This API returns information about a specific user account.

The api is::

    GET /_synapse/admin/v1/whois/<user_id> (deprecated)
    GET /_synapse/admin/v2/users/<user_id>

including an ``access_token`` of a server admin.

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
password reset). It can also mark the user as GDPR-erased (stopping their data
from distributed further, and deleting it entirely if there are no other
references to it).

The api is::

    POST /_synapse/admin/v1/deactivate/<user_id>

with a body of:

.. code:: json

    {
        "erase": true
    }

including an ``access_token`` of a server admin.

The erase parameter is optional and defaults to 'false'.
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

including an ``access_token`` of a server admin.

The parameter ``new_password`` is required.
The parameter ``logout_devices`` is optional and defaults to ``true``.

Get whether a user is a server administrator or not
===================================================


The api is::

    GET /_synapse/admin/v1/users/<user_id>/admin

including an ``access_token`` of a server admin.

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

including an ``access_token`` of a server admin.
