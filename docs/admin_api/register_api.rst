Shared-Secret Registration
==========================

This API allows for the creation of users in an administrative and
non-interactive way. This is generally used for bootstrapping a Synapse
instance with administrator accounts.

To authenticate yourself to the server, you will need both the shared secret
(``registration_shared_secret`` in the homeserver configuration), and a
one-time nonce. If the registration shared secret is not configured, this API
is not enabled.

To fetch the nonce, you need to request one from the API::

  > GET /_synapse/admin/v1/register

  < {"nonce": "thisisanonce"}

Once you have the nonce, you can make a ``POST`` to the same URL with a JSON
body containing the nonce, username, password, whether they are an admin
(optional, False by default), and a HMAC digest of the content. Also you can
set the displayname (optional, ``username`` by default).

As an example::

  > POST /_synapse/admin/v1/register
  > {
     "nonce": "thisisanonce",
     "username": "pepper_roni",
     "displayname": "Pepper Roni",
     "password": "pizza",
     "admin": true,
     "mac": "mac_digest_here"
    }

  < {
     "access_token": "token_here",
     "user_id": "@pepper_roni:localhost",
     "home_server": "test",
     "device_id": "device_id_here"
    }

The MAC is the hex digest output of the HMAC-SHA1 algorithm, with the key being
the shared secret and the content being the nonce, user, password, either the
string "admin" or "notadmin", and optionally the user_type
each separated by NULs. For an example of generation in Python::

  import hmac, hashlib

  def generate_mac(nonce, user, password, admin=False, user_type=None):

      mac = hmac.new(
        key=shared_secret,
        digestmod=hashlib.sha1,
      )

      mac.update(nonce.encode('utf8'))
      mac.update(b"\x00")
      mac.update(user.encode('utf8'))
      mac.update(b"\x00")
      mac.update(password.encode('utf8'))
      mac.update(b"\x00")
      mac.update(b"admin" if admin else b"notadmin")
      if user_type:
          mac.update(b"\x00")
          mac.update(user_type.encode('utf8'))

      return mac.hexdigest()
