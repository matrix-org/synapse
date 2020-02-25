Admin APIs
==========

This directory includes documentation for the various synapse specific admin
APIs available.

Only users that are server admins can use these APIs. A user can be marked as a
server admin by updating the database directly, e.g.:

``UPDATE users SET admin = 1 WHERE name = '@foo:bar.com'``

Restarting may be required for the changes to register.

Using an admin access_token
###########################

Many of the API calls listed in the documentation here will require to include an admin `access_token`.
Finding your user's `access_token` is client-dependent, but will usually be shown in the client's settings.

Once you have your `access_token`, to include it in a request, the best option is to add the token to a request header:

``curl --header "Authorization: Bearer <access_token>" <the_rest_of_your_API_request>``

Fore more details, please refer to the complete `matrix spec documentation <https://matrix.org/docs/spec/client_server/r0.5.0#using-access-tokens>`_.
