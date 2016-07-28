Admin APIs
==========

This directory includes documentation for the various synapse specific admin
APIs available.

Only users that are server admins can use these APIs. A user can be marked as a
server admin by updating the database directly, e.g.:

``UPDATE users SET admin = 1 WHERE name = '@foo:bar.com'``

Restarting may be required for the changes to register.
