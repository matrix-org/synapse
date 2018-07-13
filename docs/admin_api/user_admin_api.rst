Query Account
=============

This API returns information about a specific user account.

The api is::

    GET /_matrix/client/r0/admin/whois/<user_id>

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

    POST /_matrix/client/r0/admin/deactivate/<user_id>

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

Changes the password of another user.

The api is::

    POST /_matrix/client/r0/admin/reset_password/<user_id>

with a body of:

.. code:: json

   {
       "new_password": "<secret>"
   }

including an ``access_token`` of a server admin.
