Upgrading to v0.0.1
===================

This release completely changes the database schema and so requires upgrading
it before starting the new version of the homeserver.

The script "database-prepare-for-0.0.1.sh" should be used to upgrade the
database. This will save all user information, such as logins and profiles, 
but will otherwise purge the database. This includes messages, which
rooms the home server was a member of and room alias mappings.

Before running the command the homeserver should be first completely 
shutdown. To run it, simply specify the location of the database, e.g.:

  ./database-prepare-for-0.0.1.sh "homeserver.db"

Once this has successfully completed it will be safe to restart the 
homeserver. You may notice that the homeserver takes a few seconds longer to 
restart than usual as it reinitializes the database.

On startup of the new version, users can either rejoin remote rooms using room
aliases or by being reinvited. Alternatively, if any other homeserver sends a
message to a room that the homeserver was previously in the local HS will 
automatically rejoin the room.
