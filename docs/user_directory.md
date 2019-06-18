User Directory API Implementation
=================================

The user directory is currently maintained based on the 'visible' users
on this particular server - i.e. ones which your account shares a room with, or
who are present in a publicly viewable room present on the server.

The directory info is stored in various tables, which can (typically after
DB corruption) get stale or out of sync.  If this happens, for now the
solution to fix it is to execute the SQL here
https://github.com/matrix-org/synapse/blob/master/synapse/storage/schema/delta/53/user_dir_populate.sql
and then restart synapse. This should then start a background task to
flush the current tables and regenerate the directory.
