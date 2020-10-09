Admin APIs
==========

This directory includes documentation for the various synapse specific admin
APIs available.

Authenticating as a server admin
--------------------------------

Many of the API calls in the admin api will require an `access_token` for a
server admin. (Note that a server admin is distinct from a room admin.)

A user can be marked as a server admin by updating the database directly, e.g.:

.. code-block:: sql

    UPDATE users SET admin = 1 WHERE name = '@foo:bar.com';

A new server admin user can also be created using the
``register_new_matrix_user`` script.

Finding your user's `access_token` is client-dependent, but will usually be shown in the client's settings.

Once you have your `access_token`, to include it in a request, the best option is to add the token to a request header:

``curl --header "Authorization: Bearer <access_token>" <the_rest_of_your_API_request>``

Fore more details, please refer to the complete `matrix spec documentation <https://matrix.org/docs/spec/client_server/r0.5.0#using-access-tokens>`_.
