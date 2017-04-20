Query Account
=============

This API returns information about a specific user account.

The api is::

    GET /_matrix/client/r0/admin/whois/<user_id>

including an ``access_token`` of a server admin.

It returns a JSON body liek the following:

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
                                "last_seen": 1417222374433, # ms since 1970
                                "user_agent": "Mozilla/5.0 ..."
                            },
                            # ...
                        ]
                    }
                ]
            }
        }
    }


Deactivate Account
==================

This API deactivates an account. It removes active access tokens, resets the
password, and deletes third-party IDs (to prevent the user requesting a
password reset).

The api is::

    POST /_matrix/client/r0/admin/deactivate/<user_id>

including an ``access_token`` of a server admin, and an empty request body.


Reset password
==============

Changes the password of another user.

The api is::

    POST /_matrix/client/r0/admin/reset_password/<user_id>

with a body of::

   {
       "new_password": "<secret>"
   }

including an ``access_token`` of a server admin.
