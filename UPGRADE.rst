Upgrading to v0.2.0
===================

The home server now requires setting up of SSL config before it can run. To
automatically generate default config use::

    $ python synapse/app/homeserver.py \
        --server-name machine.my.domain.name \
        --bind-port 8448 \
        --config-path homeserver.config \
        --generate-config

This config can be edited if desired, for example to specify a different SSL 
certificate to use. Once done you can run the home server using::

    $ python synapse/app/homeserver.py --config-path homeserver.config

See the README.rst for more information.

Also note that some config options have been renamed, including:

- "host" to "server-name"
- "database" to "database-path"
- "port" to "bind-port" and "unsecure-port"


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
